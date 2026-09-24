"""Evidence collection and approval-gated, identity-rechecked deletion.

Deletion refreshes process references and inode identity immediately before
each unlink/rmdir. This narrows the check/use window but cannot make a Linux
filesystem check plus unlink atomic: another process may start using an inode
after the last /proc observation and before the syscall. Callers must coordinate
with writers when they need stronger exclusion guarantees.

Process visibility is also namespace-scoped. In commonly marked OCI/Docker
containers, a candidate below a separate mountpoint is treated as unknown:
the container may not see host processes using bind-mounted data. This is a
practical signal check, not proof that every container or hidden PID namespace
is detected; inspect host bind-mounted data from the host for stronger coverage.
"""

from __future__ import annotations

import os
import shutil
import stat
import time
from pathlib import Path
from typing import Any

DEFAULT_INSPECT_CAPS = {"max_processes": 20_000, "max_fds_per_process": 4_096,
                        "max_proc_bytes": 64 * 1024, "max_maps_bytes": 1024 * 1024,
                        "max_tree_entries": 50_000,
                        "max_proc_milliseconds": 2_000,
                        "max_delete_milliseconds": 10_000}
PROC_ROOT = Path("/proc")
MOUNTINFO_PATH = Path("/proc/self/mountinfo")
CONTAINER_MARKER_PATHS = (Path("/.dockerenv"), Path("/run/.containerenv"))
MAX_MOUNTINFO_BYTES = 1024 * 1024
OPTIONAL_CONSUMER_CHECKS = ("docker_mounts", "pm2_processes", "systemd_units",
                            "cron_jobs", "git_state", "literal_code_refs")
SUPPORTED_CONSUMER_CHECKS = ("processes", "mounts", *OPTIONAL_CONSUMER_CHECKS)
REQUIRED_CONSUMER_CHECKS = SUPPORTED_CONSUMER_CHECKS


def _identity(st: os.stat_result) -> dict[str, int]:
    return {"dev": int(st.st_dev), "ino": int(st.st_ino), "mode": int(st.st_mode),
            "uid": int(st.st_uid), "gid": int(st.st_gid), "size": int(st.st_size),
            "mtime_ns": int(st.st_mtime_ns), "ctime_ns": int(st.st_ctime_ns),
            "nlink": int(st.st_nlink)}


def _same_identity(left: dict[str, Any], right: dict[str, Any]) -> bool:
    keys = ("dev", "ino", "mode", "uid", "gid", "size", "mtime_ns", "ctime_ns", "nlink")
    return all(left.get(key) == right.get(key) for key in keys)


def _same_object(left: dict[str, Any], right: dict[str, Any]) -> bool:
    """Compare inode identity without mutable directory size/timestamps."""
    return all(left.get(key) == right.get(key) for key in ("dev", "ino", "mode", "uid", "gid"))


def _caps(value: dict[str, Any] | None) -> dict[str, int]:
    result = dict(DEFAULT_INSPECT_CAPS)
    if value:
        for key in result:
            raw = value.get(key, result[key])
            if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
                raise ValueError(f"caps.{key} must be a non-negative integer")
            if raw > DEFAULT_INSPECT_CAPS[key]:
                raise ValueError(f"caps.{key} exceeds the hard safety limit")
            result[key] = raw
    return result


def _proc_processes(proc_root: Path, cap: int, deadline: float) -> tuple[list[Path], list[str]]:
    unknown: list[str] = []
    try:
        with os.scandir(proc_root) as entries:
            processes = []
            for entry in entries:
                if time.monotonic() >= deadline:
                    unknown.append("process_time_budget_exhausted")
                    break
                if entry.name.isdigit():
                    if len(processes) >= cap:
                        unknown.append("process_budget_exhausted")
                        break
                    processes.append(Path(entry.path))
            return processes, unknown
    except OSError as exc:
        return [], [f"proc_unavailable:{type(exc).__name__}"]


def _path_mentioned(raw: bytes, candidate: str, max_bytes: int) -> bool | None:
    if len(raw) > max_bytes:
        return None
    text = os.fsdecode(raw)
    # cmdline strings are NUL-separated; compare exact candidate or descendant.
    for arg in text.split("\x00"):
        if arg == candidate or arg.startswith(candidate.rstrip(os.sep) + os.sep):
            return True
        if "=" in arg:
            value = arg.split("=", 1)[1]
            if value == candidate or value.startswith(candidate.rstrip(os.sep) + os.sep):
                return True
    return False


def _mapped_inodes(proc: Path, member_identities: set[tuple[int, int]],
                   max_bytes: int) -> tuple[list[int], list[str]]:
    """Find mapped files by device/inode; paths in maps are not authoritative."""
    unknown: list[str] = []
    try:
        with (proc / "maps").open("rb") as stream:
            raw = stream.read(max_bytes + 1)
    except FileNotFoundError:
        return [], []  # process exited while it was inspected
    except PermissionError:
        return [], ["maps_inaccessible"]
    except OSError as exc:
        return [], [f"maps_unreadable:{type(exc).__name__}"]
    if len(raw) > max_bytes:
        return [], ["maps_budget_exhausted"]

    matches: list[int] = []
    for line in raw.splitlines():
        fields = line.split(None, 5)
        if len(fields) < 5:
            unknown.append("maps_malformed")
            continue
        try:
            major, minor = fields[3].split(b":", 1)
            key = (os.makedev(int(major, 16), int(minor, 16)), int(fields[4], 10))
        except (ValueError, OverflowError):
            unknown.append("maps_malformed")
            continue
        if key in member_identities:
            matches.append(key[1])
    return matches, unknown


def _mount_records(raw: str) -> list[tuple[str, str]]:
    """Parse mountpoint and filesystem type pairs from Linux mountinfo."""
    records: list[tuple[str, str]] = []
    for line in raw.splitlines():
        fields = line.split()
        try:
            separator = fields.index("-")
            if len(fields) < 6 or separator < 6 or len(fields) <= separator + 1:
                raise ValueError("short mountinfo record")
            mountpoint = fields[4]
            for encoded, decoded in (("\\040", " "), ("\\011", "\t"),
                                     ("\\012", "\n"), ("\\134", "\\")):
                mountpoint = mountpoint.replace(encoded, decoded)
            records.append((os.path.normpath(mountpoint), fields[separator + 1]))
        except (ValueError, IndexError):
            raise ValueError("malformed mountinfo") from None
    if not records:
        raise ValueError("empty mountinfo")
    return records


def _container_mount_scope_unknown(candidate: Path, *,
                                  mountinfo_path: Path | None = None,
                                  marker_paths: tuple[Path, ...] | None = None
                                  ) -> str | None:
    """Flag mounted candidates when common container signals hide host PIDs.

    The check intentionally leaves a container's root filesystem and ordinary
    host mounts alone. Generic PID namespace detection is not reliable from an
    unprivileged process, so this only covers common OCI/Docker indicators.
    """
    mountinfo_path = MOUNTINFO_PATH if mountinfo_path is None else mountinfo_path
    marker_paths = CONTAINER_MARKER_PATHS if marker_paths is None else marker_paths
    marked_container = any(marker.exists() for marker in marker_paths)
    try:
        with mountinfo_path.open("rb") as stream:
            raw = stream.read(MAX_MOUNTINFO_BYTES + 1)
        if len(raw) > MAX_MOUNTINFO_BYTES:
            raise ValueError("mountinfo exceeds byte limit")
        records = _mount_records(raw.decode("utf-8", "strict"))
    except (OSError, UnicodeError, ValueError):
        return "container_mount_process_visibility_unknown" if marked_container else None

    root_filesystems = {fs for mountpoint, fs in records if mountpoint == "/"}
    container_signal = marked_container or bool(
        root_filesystems & {"overlay", "fuse-overlayfs"}
    )
    if not container_signal:
        return None

    target = os.path.normpath(os.path.abspath(os.fspath(candidate)))
    covering_mounts = []
    for mountpoint, _ in records:
        try:
            if os.path.commonpath((target, mountpoint)) == mountpoint:
                covering_mounts.append(mountpoint)
        except ValueError:
            continue
    if not covering_mounts:
        return "container_mount_process_visibility_unknown"
    longest = max(covering_mounts, key=len)
    if longest != "/":
        return "container_mount_process_visibility_unknown"
    return None


def _proc_evidence(candidate: Path, caps: dict[str, int],
                   member_identities: set[tuple[int, int]] | None = None) -> dict[str, Any]:
    proc_root = PROC_ROOT
    deadline = time.monotonic() + caps["max_proc_milliseconds"] / 1000
    processes, unknown = _proc_processes(proc_root, caps["max_processes"], deadline)
    mount_scope_unknown = _container_mount_scope_unknown(candidate)
    if mount_scope_unknown:
        unknown.append(mount_scope_unknown)
    if not processes and unknown:
        return {"status": "unknown", "process_visibility": "unknown",
                "references": [], "unknown": unknown}
    references: list[dict[str, Any]] = []
    candidate_text = str(candidate)
    try:
        target_stat = candidate.lstat()
        target_identity = _identity(target_stat)
    except OSError as exc:
        return {"status": "unknown", "process_visibility": "partial",
                "references": [], "unknown": [f"candidate_stat:{type(exc).__name__}"]}

    scanned = 0
    for process in processes:
        if time.monotonic() >= deadline:
            unknown.append("process_time_budget_exhausted")
            break
        pid = process.name
        try:
            cmdline = (process / "cmdline").read_bytes()
            cwd_text = os.readlink(process / "cwd")
        except FileNotFoundError:
            continue  # process exited during inspection
        except PermissionError:
            unknown.append(f"process_inaccessible:{pid}")
            continue
        except OSError as exc:
            unknown.append(f"process_unreadable:{pid}:{type(exc).__name__}")
            continue
        mentioned = _path_mentioned(cmdline, candidate_text, caps["max_proc_bytes"])
        if mentioned is None:
            unknown.append(f"cmdline_budget_exhausted:{pid}")
        elif mentioned:
            references.append({"pid": int(pid), "kind": "cmdline_path"})
        mapped, maps_unknown = _mapped_inodes(process, member_identities or
                                               {(target_identity["dev"], target_identity["ino"])},
                                               caps["max_maps_bytes"])
        unknown.extend(f"{reason}:{pid}" for reason in maps_unknown)
        if mapped:
            references.append({"pid": int(pid), "kind": "mmap", "mapping_count": len(mapped)})
        try:
            cwd = Path(os.path.normpath(cwd_text))
            if cwd == candidate or candidate in cwd.parents:
                references.append({"pid": int(pid), "kind": "cwd"})
        except (OSError, ValueError):
            unknown.append(f"cwd_unreadable:{pid}")

        fd_dir = process / "fd"
        try:
            with os.scandir(fd_dir) as entries:
                fds = []
                for entry in entries:
                    if len(fds) >= caps["max_fds_per_process"]:
                        unknown.append(f"fd_budget_exhausted:{pid}")
                        break
                    fds.append(entry.path)
        except FileNotFoundError:
            continue
        except PermissionError:
            unknown.append(f"fd_inaccessible:{pid}")
            continue
        except OSError as exc:
            unknown.append(f"fd_unreadable:{pid}:{type(exc).__name__}")
            continue
        for fd in fds:
            if time.monotonic() >= deadline:
                unknown.append("process_time_budget_exhausted")
                break
            scanned += 1
            try:
                fd_stat = os.stat(fd)
            except FileNotFoundError:
                continue
            except PermissionError:
                unknown.append(f"fd_stat_inaccessible:{pid}")
                continue
            except OSError:
                continue
            key = (fd_stat.st_dev, fd_stat.st_ino)
            if key == (target_identity["dev"], target_identity["ino"]) or key in (member_identities or set()):
                references.append({"pid": int(pid), "kind": "open_fd"})
                break
    return {"status": "clear" if not references and not unknown else "active" if references else "unknown",
            "process_visibility": "complete" if not unknown else "partial",
            "processes_seen": len(processes), "fds_seen": scanned,
            "references": references, "unknown": sorted(set(unknown))}


def _mountpoints() -> tuple[set[str], str | None]:
    try:
        mounts: set[str] = set()
        with Path("/proc/self/mountinfo").open("r", encoding="utf-8") as stream:
            for line in stream:
                fields = line.split()
                if len(fields) < 5:
                    return mounts, "malformed_mountinfo"
                value = fields[4]
                for encoded, decoded in (("\\040", " "), ("\\011", "\t"),
                                         ("\\012", "\n"), ("\\134", "\\")):
                    value = value.replace(encoded, decoded)
                mounts.add(os.path.normpath(value))
        return mounts, None
    except OSError as exc:
        return set(), f"mountinfo_unavailable:{type(exc).__name__}"


def _tree_evidence(candidate: Path, expected_dev: int, max_entries: int) -> dict[str, Any]:
    mounts, mount_error = _mountpoints()
    unknown: list[str] = [mount_error] if mount_error else []
    stack = [candidate]
    count = 0
    newest_mtime_ns = 0
    allocated_bytes = 0
    owner_uids: set[int] = set()
    hardlinks: list[str] = []
    symlinks: list[str] = []
    member_identities: set[tuple[int, int]] = set()
    allocated_inodes: set[tuple[int, int]] = set()
    while stack:
        path = stack.pop()
        try:
            st = path.lstat()
        except OSError as exc:
            unknown.append(f"stat:{type(exc).__name__}")
            continue
        count += 1
        if count > max_entries:
            unknown.append("tree_entry_budget_exhausted")
            break
        if st.st_dev != expected_dev:
            unknown.append("filesystem_boundary")
            continue
        if str(path) in mounts and path != candidate:
            unknown.append("nested_mount_boundary")
            continue
        owner_uids.add(st.st_uid)
        member_identities.add((st.st_dev, st.st_ino))
        newest_mtime_ns = max(newest_mtime_ns, st.st_mtime_ns)
        inode_key = (st.st_dev, st.st_ino)
        if inode_key not in allocated_inodes:
            allocated_bytes += max(0, int(getattr(st, "st_blocks", 0)) * 512)
            allocated_inodes.add(inode_key)
        if stat.S_ISLNK(st.st_mode):
            symlinks.append(str(path))
        elif stat.S_ISREG(st.st_mode):
            if st.st_nlink > 1:
                hardlinks.append(str(path))
        elif stat.S_ISDIR(st.st_mode):
            try:
                with os.scandir(path) as children:
                    stack.extend(Path(item.path) for item in children)
            except OSError as exc:
                unknown.append(f"enumerate:{type(exc).__name__}")
        else:
            unknown.append("unsupported_file_type")
    return {"status": "clear" if not unknown and not hardlinks else "unknown",
            "entries": count, "allocated_bytes": allocated_bytes,
            "newest_mtime_ns": newest_mtime_ns, "owner_uids": sorted(owner_uids),
            "symlink_count": len(symlinks), "hardlink_count": len(hardlinks),
            "member_identities": [list(item) for item in sorted(member_identities)],
            "unknown": sorted(set(unknown)),
            "unsafe": [*( ["hardlinks_present"] if hardlinks else [] ),
                       *( ["symlinks_present"] if symlinks else [] )]}


def inspect(candidate: dict[str, Any] | str | os.PathLike[str],
            caps: dict[str, Any] | None = None, *,
            consumer_evidence: dict[str, Any] | None = None,
            _include_member_identities: bool = False) -> dict[str, Any]:
    """Return conservative evidence for one path; inability to check is unknown."""
    limits = _caps(caps)
    path_value = candidate.get("path") if isinstance(candidate, dict) else os.fspath(candidate)
    if not isinstance(path_value, str) or not path_value or "\x00" in path_value:
        return {"status": "unknown", "unknown": ["invalid_candidate_path"]}
    path = Path(os.path.abspath(path_value))
    if path_value != str(path):
        return {"status": "unknown", "path": path_value,
                "unknown": ["candidate_path_not_canonical"]}
    if path == Path(path.anchor):
        return {"status": "unsafe", "path": str(path), "unsafe": ["filesystem_root"], "unknown": []}
    try:
        st = path.lstat()
    except OSError as exc:
        return {"status": "unknown", "path": str(path), "unknown": [f"lstat:{type(exc).__name__}"]}
    if stat.S_ISLNK(st.st_mode):
        return {"status": "unsafe", "path": str(path), "identity": _identity(st),
                "unsafe": ["symlink_candidate"], "unknown": []}
    mounts, mount_error = _mountpoints()
    unsafe: list[str] = []
    unknown: list[str] = []
    core_unknown: list[str] = []
    if mount_error:
        unknown.append(mount_error)
        core_unknown.append(mount_error)
    if str(path) in mounts:
        unsafe.append("mount_point")
    if stat.S_ISREG(st.st_mode) and st.st_nlink > 1:
        unsafe.append("hardlink_candidate")
    tree = _tree_evidence(path, st.st_dev, limits["max_tree_entries"])
    unsafe.extend(tree["unsafe"])
    unknown.extend(tree["unknown"])
    core_unknown.extend(tree["unknown"])
    member_ids = {tuple(item) for item in tree.pop("member_identities", [])}
    processes = _proc_evidence(path, limits, member_ids)
    unknown.extend(processes["unknown"])
    core_unknown.extend(processes["unknown"])
    if processes["references"]:
        unsafe.append("active_process_reference")
    if len(tree["owner_uids"]) > 1:
        unsafe.append("owner_mismatch_in_tree")
    supplied_consumers = consumer_evidence if isinstance(consumer_evidence, dict) else {}
    consumer_checks: dict[str, str] = {
        "processes": "clear" if processes["status"] == "clear" else processes["status"],
        "mounts": "clear" if not mount_error and "nested_mount_boundary" not in tree["unknown"]
        and str(path) not in mounts else "unknown",
    }
    for check in OPTIONAL_CONSUMER_CHECKS:
        supplied = supplied_consumers.get(check)
        state = supplied if isinstance(supplied, str) else (
            supplied.get("status") if isinstance(supplied, dict) else
            "clear" if supplied is True else None)
        if state == "clear":
            consumer_checks[check] = "clear"
        elif state in {"in_use", "active", "unsafe", "matched"}:
            consumer_checks[check] = "in_use"
            unsafe.append(f"consumer_in_use:{check}")
            if isinstance(supplied, dict) and supplied.get("matches"):
                consumer_checks[f"{check}_matches"] = supplied["matches"]
            if isinstance(supplied, dict):
                consumer_checks[f"{check}_evidence"] = supplied
        else:
            consumer_checks[check] = "unknown"
            unknown.append(f"consumer_not_checked:{check}")
            if isinstance(supplied, dict):
                consumer_checks[f"{check}_evidence"] = supplied
    if unsafe:
        status = "unsafe"
    elif unknown:
        status = "unknown"
    else:
        status = "clear"
    expected = candidate.get("identity") if isinstance(candidate, dict) else None
    identity = _identity(st)
    identity_matches = _same_identity(expected, identity) if isinstance(expected, dict) else None
    result = {"status": status, "path": str(path), "identity": identity,
            "identity_matches_scan": identity_matches,
            "tree": tree, "processes": processes, "consumer_checks": consumer_checks,
            "unsafe": sorted(set(unsafe)), "unknown": sorted(set(unknown)),
            "core_unknown": sorted(set(core_unknown))}
    if _include_member_identities:
        result["_member_identities"] = [list(item) for item in sorted(member_ids)]
    return result


def _approved(candidate: dict[str, Any], config: dict[str, Any]) -> tuple[bool, str, str | None]:
    path = candidate.get("path")
    identity = candidate.get("identity")
    if not isinstance(path, str) or not isinstance(identity, dict):
        return False, "candidate_missing_path_or_identity", None
    for approval in config.get("approved_paths", []):
        if isinstance(approval, dict) and approval.get("path") == path:
            if _same_identity(approval.get("identity", {}), identity):
                return True, "exact_path_approval", None
            return False, "approved_path_identity_mismatch", None

    if not isinstance(config.get("enabled_categories"), list):
        return False, "categories_not_enabled", None
    matched_rules: list[dict[str, Any]] = []
    for rule in config.get("category_rules", []):
        if not isinstance(rule, dict):
            continue
        category_id = rule.get("id")
        if category_id not in config["enabled_categories"]:
            continue
        parent = rule.get("parent_dir")
        basename = Path(path).name
        if not isinstance(parent, str) or os.path.dirname(path) != os.path.abspath(parent):
            continue
        exact = rule.get("basename")
        prefix = rule.get("basename_prefix")
        if exact is not None:
            matches = isinstance(exact, str) and basename == exact
        elif isinstance(prefix, str) and prefix and not any(ch in prefix for ch in "/*?[]"):
            matches = basename.startswith(prefix)
        else:
            continue
        if matches:
            matched_rules.append(rule)
    if len(matched_rules) > 1:
        return False, "ambiguous_category_rules", None
    for rule in matched_rules:
        category_id = rule.get("id")
        parent = rule.get("parent_dir")
        exact = rule.get("basename")
        prefix = rule.get("basename_prefix")
        if not isinstance(category_id, str) or not category_id.strip():
            return False, "category_id_required", None
        if exact is not None and prefix is not None:
            return False, "category_rule_must_use_exact_or_prefix", category_id
        if (not isinstance(parent, str) or not os.path.isabs(parent)
                or os.path.normpath(parent) == os.path.sep):
            return False, "category_parent_must_be_absolute_nonroot", category_id
        if isinstance(prefix, str) and exact is None and (
                len(prefix) < 4 or not any(ch.isalnum() for ch in prefix) or prefix.startswith(".")):
            return False, "category_prefix_too_broad", category_id
        if isinstance(exact, str) and (not exact or exact in {".", ".."} or
                                        "/" in exact or "\\" in exact):
            return False, "category_basename_invalid", category_id
        owner_uid = rule.get("owner_uid")
        if isinstance(owner_uid, bool) or not isinstance(owner_uid, int) or owner_uid < 0:
            return False, "category_owner_uid_invalid", category_id
        if identity.get("uid") != rule.get("owner_uid"):
            return False, "category_owner_mismatch", category_id
        if (isinstance(rule.get("min_age_seconds"), bool) or
                not isinstance(rule.get("min_age_seconds"), (int, float)) or
                rule["min_age_seconds"] <= 0):
            return False, "category_invalid_min_age", category_id
        if (isinstance(rule.get("max_bytes"), bool) or
                not isinstance(rule.get("max_bytes"), int) or rule["max_bytes"] <= 0):
            return False, "category_invalid_max_bytes", category_id
        if (isinstance(rule.get("max_count"), bool) or
                not isinstance(rule.get("max_count"), int) or rule["max_count"] <= 0):
            return False, "category_invalid_max_count", category_id
        return True, "category_rule", category_id
    return False, "no_matching_approval", None


def _recheck(candidate: dict[str, Any], caps: dict[str, Any],
             consumer_evidence: dict[str, Any] | None,
             required_checks: tuple[str, ...]) -> dict[str, Any]:
    evidence = inspect(candidate, caps, consumer_evidence=consumer_evidence,
                       _include_member_identities=True)
    required_missing = [check for check in required_checks
                        if evidence.get("consumer_checks", {}).get(check) != "clear"]
    if evidence.get("unsafe") or evidence.get("core_unknown") or required_missing:
        evidence["required_consumer_checks_missing"] = required_missing
        return evidence
    if evidence.get("identity_matches_scan") is not True:
        evidence["status"] = "unsafe"
        evidence.setdefault("unsafe", []).append("identity_changed_since_scan")
    return evidence


def _required_checks(candidate: dict[str, Any], config: dict[str, Any],
                     category_id: str | None) -> tuple[str, ...] | None:
    """Resolve user-reviewed consumer requirements; core checks stay mandatory."""
    rules = config.get("approved_paths", []) if category_id is None else config.get("category_rules", [])
    for item in rules:
        if not isinstance(item, dict):
            continue
        if category_id is None:
            matches = item.get("path") == candidate.get("path")
        else:
            matches = item.get("id") == category_id
        if not matches:
            continue
        raw = item.get("required_consumer_checks", list(REQUIRED_CONSUMER_CHECKS))
        if not isinstance(raw, list) or any(check not in SUPPORTED_CONSUMER_CHECKS for check in raw):
            return None
        return tuple(sorted(set((*raw, "processes", "mounts"))))
    return None


def _unlink_tree(path: Path, expected: dict[str, Any], root_dev: int,
                 limits: dict[str, int],
                 member_identities: set[tuple[int, int]]) -> tuple[int, str | None]:
    """Remove a tree without following symlinks; refuse if a node changes.

    dir_fd operations pin each parent directory, preventing replacement of an
    ancestor path from redirecting unlink operations outside the approved tree.
    """
    if os.name != "posix" or not hasattr(os, "supports_dir_fd"):
        return 0, "dir_fd_operations_unavailable"
    mounts, mount_error = _mountpoints()
    if mount_error:
        return 0, "mount_visibility_unknown"
    if os.path.normpath(str(path)) in mounts:
        return 0, "candidate_is_mount_point"
    # Open every parent component without following symlinks. A plain open of
    # path.parent would allow a replaced ancestor symlink to redirect deletion.
    parent_fd = os.open(path.anchor, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    fd_registry = {parent_fd}
    try:
        for component in path.parent.parts[1:]:
            next_fd = os.open(component, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                               getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
            os.close(parent_fd)
            fd_registry.discard(parent_fd)
            parent_fd = next_fd
            fd_registry.add(parent_fd)
    except OSError as exc:
        for fd in fd_registry:
            try:
                os.close(fd)
            except OSError:
                pass
        return 0, f"parent_path_changed:{type(exc).__name__}"
    deleted_bytes = 0
    deadline = time.monotonic() + limits["max_delete_milliseconds"] / 1000

    def check_live_references() -> str | None:
        if time.monotonic() >= deadline:
            return "delete_time_budget_exhausted"
        current = _proc_evidence(path, limits, member_identities)
        if current["references"]:
            return "active_process_reference_before_unlink"
        if current["unknown"]:
            return "process_visibility_unknown_before_unlink"
        if time.monotonic() >= deadline:
            return "delete_time_budget_exhausted"
        return None

    try:
        root_now = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if not _same_identity(expected, _identity(root_now)):
            return 0, "identity_changed_before_delete"
        if not stat.S_ISDIR(root_now.st_mode):
            error = check_live_references()
            if error:
                return 0, error
            root_now = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
            if (not _same_identity(expected, _identity(root_now)) or
                    not (stat.S_ISREG(root_now.st_mode) or stat.S_ISLNK(root_now.st_mode)) or
                    (stat.S_ISREG(root_now.st_mode) and root_now.st_nlink > 1)):
                return 0, "entry_changed_during_delete"
            os.unlink(path.name, dir_fd=parent_fd)
            return max(0, int(getattr(root_now, "st_blocks", 0)) * 512), None

        # Directory walker processes one pinned directory fd at a time.
        initial_fd = os.dup(parent_fd)
        fd_registry.add(initial_fd)
        stack: list[tuple[int, str, int, dict[str, Any], bool, Path]] = [
            (initial_fd, path.name, root_dev, expected, False, path)]
        visited = 0
        while stack:
            dirfd, name, dev, identity, post, absolute_path = stack.pop()
            try:
                if time.monotonic() >= deadline:
                    return deleted_bytes, "delete_time_budget_exhausted"
                if os.path.normpath(str(absolute_path)) in mounts:
                    return deleted_bytes, "mount_boundary_appeared_during_delete"
                if post:
                    now = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
                    if not _same_object(identity, _identity(now)):
                        return deleted_bytes, "directory_changed_during_delete"
                    error = check_live_references()
                    if error:
                        return deleted_bytes, error
                    now = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
                    if not _same_object(identity, _identity(now)):
                        return deleted_bytes, "directory_changed_during_delete"
                    os.rmdir(name, dir_fd=dirfd)
                    deleted_bytes += max(0, int(getattr(now, "st_blocks", 0)) * 512)
                    continue
                now = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
                if not _same_identity(identity, _identity(now)):
                    return deleted_bytes, "entry_changed_during_delete"
                childfd = os.open(name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                                  getattr(os, "O_NOFOLLOW", 0), dir_fd=dirfd)
                fd_registry.add(childfd)
                child_st = os.fstat(childfd)
                if child_st.st_dev != dev or not _same_identity(identity, _identity(child_st)):
                    os.close(childfd)
                    fd_registry.discard(childfd)
                    return deleted_bytes, "directory_identity_changed"
                with os.scandir(childfd) as entries:
                    children = [(entry.name, os.stat(entry.name, dir_fd=childfd,
                                                     follow_symlinks=False)) for entry in entries]
                visited += len(children)
                if visited > limits["max_tree_entries"]:
                    os.close(childfd)
                    fd_registry.discard(childfd)
                    return deleted_bytes, "tree_entry_budget_exhausted"
                if any((child_st.st_dev, child_st.st_ino) not in member_identities
                       for _, child_st in children):
                    os.close(childfd)
                    fd_registry.discard(childfd)
                    return deleted_bytes, "tree_entry_not_in_rechecked_inventory"
                post_fd = os.dup(dirfd)
                fd_registry.add(post_fd)
                stack.append((post_fd, name, dev, identity, True, absolute_path))
                for child_name, child_st in children:
                    child_path = absolute_path / child_name
                    if os.path.normpath(str(child_path)) in mounts:
                        os.close(childfd)
                        fd_registry.discard(childfd)
                        return deleted_bytes, "mount_boundary_appeared_during_delete"
                    if stat.S_ISDIR(child_st.st_mode):
                        child_parent_fd = os.dup(childfd)
                        fd_registry.add(child_parent_fd)
                        stack.append((child_parent_fd, child_name, dev, _identity(child_st), False,
                                      child_path))
                # Files and symlinks are revalidated immediately before unlink.
                for child_name, child_st in children:
                    if stat.S_ISDIR(child_st.st_mode):
                        continue
                    current = os.stat(child_name, dir_fd=childfd, follow_symlinks=False)
                    if not _same_identity(_identity(child_st), _identity(current)):
                        os.close(childfd)
                        fd_registry.discard(childfd)
                        return deleted_bytes, "entry_changed_during_delete"
                    if (current.st_dev != dev or not (stat.S_ISREG(current.st_mode) or
                                                       stat.S_ISLNK(current.st_mode)) or
                            (stat.S_ISREG(current.st_mode) and current.st_nlink > 1)):
                        os.close(childfd)
                        fd_registry.discard(childfd)
                        return deleted_bytes, "unsafe_tree_entry"
                    error = check_live_references()
                    if error:
                        os.close(childfd)
                        fd_registry.discard(childfd)
                        return deleted_bytes, error
                    current = os.stat(child_name, dir_fd=childfd, follow_symlinks=False)
                    if (not _same_identity(_identity(child_st), _identity(current)) or
                            current.st_dev != dev or
                            not (stat.S_ISREG(current.st_mode) or stat.S_ISLNK(current.st_mode)) or
                            (stat.S_ISREG(current.st_mode) and current.st_nlink > 1)):
                        os.close(childfd)
                        fd_registry.discard(childfd)
                        return deleted_bytes, "entry_changed_during_delete"
                    os.unlink(child_name, dir_fd=childfd)
                    deleted_bytes += max(0, int(getattr(current, "st_blocks", 0)) * 512)
                os.close(childfd)
                fd_registry.discard(childfd)
            finally:
                os.close(dirfd)
                fd_registry.discard(dirfd)
        return deleted_bytes, None
    except OSError as exc:
        return deleted_bytes, f"delete_error:{type(exc).__name__}"
    finally:
        for fd in tuple(fd_registry):
            try:
                os.close(fd)
            except OSError:
                pass


def execute_delete(candidate: dict[str, Any], consent_config: dict[str, Any], *,
                   apply: bool = False, caps: dict[str, Any] | None = None,
                   run_state: dict[str, Any] | None = None,
                   consumer_evidence: dict[str, Any] | None = None) -> dict[str, Any]:
    """Delete one exactly approved candidate; dry-run is the default.

    `run_state` is a mutable per-invocation accumulator owned by the CLI and is
    required for category count/byte limits across a multi-candidate plan.
    """
    if not isinstance(candidate, dict) or not isinstance(consent_config, dict):
        return {"status": "rejected", "reason": "invalid_json_object"}
    path_value = candidate.get("path")
    if not isinstance(path_value, str) or not path_value:
        return {"status": "rejected", "reason": "candidate_missing_path"}
    path = Path(os.path.abspath(path_value))
    if path_value != str(path):
        return {"status": "rejected", "reason": "candidate_path_not_canonical"}
    if path == Path(path.anchor) or path == path.parent:
        return {"status": "rejected", "reason": "filesystem_root_forbidden"}
    approved, approval_kind, category_id = _approved(candidate, consent_config)
    if not approved:
        return {"status": "rejected", "reason": approval_kind}
    rule = next((item for item in consent_config.get("category_rules", [])
                 if isinstance(item, dict) and item.get("id") == category_id), None)
    if category_id is not None and rule is None:
        return {"status": "rejected", "reason": "category_rule_missing"}
    required_checks = _required_checks(candidate, consent_config, category_id)
    if required_checks is None:
        return {"status": "rejected", "reason": "required_consumer_checks_invalid"}
    if not apply:
        return {"status": "dry_run", "path": str(path), "approval": approval_kind,
                "category_id": category_id, "deleted": False}

    limits = _caps(caps)
    evidence = _recheck(candidate, limits, consumer_evidence, required_checks)
    member_identities = {tuple(item) for item in evidence.pop("_member_identities", [])}
    if evidence.get("unsafe") or evidence.get("core_unknown") or evidence.get("required_consumer_checks_missing"):
        return {"status": "rejected", "reason": "safety_recheck_failed",
                "evidence": evidence}
    identity = evidence["identity"]
    evidence_bytes = evidence["tree"]["allocated_bytes"]
    if category_id is not None:
        age = max(0.0, (time.time_ns() - evidence["tree"]["newest_mtime_ns"]) / 1e9)
        if age < float(rule["min_age_seconds"]):
            return {"status": "rejected", "reason": "candidate_too_recent", "age_seconds": age}
        if evidence_bytes > rule["max_bytes"]:
            return {"status": "rejected", "reason": "category_byte_limit_exceeded",
                    "allocated_bytes": evidence_bytes, "max_bytes": rule["max_bytes"]}
        if run_state is None:
            return {"status": "rejected", "reason": "category_run_state_required"}
        counts = run_state.setdefault("category_counts", {})
        byte_counts = run_state.setdefault("category_bytes", {})
        if counts.get(category_id, 0) >= rule["max_count"]:
            return {"status": "rejected", "reason": "category_count_limit_exceeded",
                    "max_count": rule["max_count"]}
        if byte_counts.get(category_id, 0) + evidence_bytes > rule["max_bytes"]:
            return {"status": "rejected", "reason": "category_run_byte_limit_exceeded",
                    "max_bytes": rule["max_bytes"]}
    else:
        # Exact approvals are still checked for fresh scan identity and safety.
        if evidence.get("identity_matches_scan") is not True:
            return {"status": "rejected", "reason": "identity_mismatch"}

    parent = path.parent
    try:
        parent_stat = parent.stat()
    except OSError as exc:
        return {"status": "rejected", "reason": f"parent_unavailable:{type(exc).__name__}"}
    if identity["dev"] != parent_stat.st_dev:
        return {"status": "rejected", "reason": "filesystem_boundary"}
    deleted_bytes, error = _unlink_tree(path, identity, parent_stat.st_dev,
                                        limits, member_identities)
    if error:
        if category_id is not None and deleted_bytes:
            counts = run_state.setdefault("category_counts", {})
            byte_counts = run_state.setdefault("category_bytes", {})
            counts[category_id] = counts.get(category_id, 0) + 1
            byte_counts[category_id] = byte_counts.get(category_id, 0) + deleted_bytes
        return {"status": "partial" if deleted_bytes else "rejected",
                "reason": error, "partial_deleted_bytes": deleted_bytes,
                "category_id": category_id, "deleted": False}
    if category_id is not None:
        run_state["category_counts"][category_id] = run_state["category_counts"].get(category_id, 0) + 1
        run_state["category_bytes"][category_id] = run_state["category_bytes"].get(category_id, 0) + deleted_bytes
    return {"status": "deleted", "path": str(path), "category_id": category_id,
            "allocated_bytes": deleted_bytes, "deleted": True}
