"""Bounded, read-only filesystem inventory for the cleanup agent.

All paths in the returned object are local paths. Callers must keep this data
local when names may contain secrets; do not forward raw paths to a model.
The scanner never follows symlinks and reports incomplete visibility explicitly.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any

from .safety import inspect

SCHEMA_VERSION = 1
DEFAULT_CAPS = {
    "max_entries": 100_000,
    "max_depth": 64,
    "max_candidates": 50,
    "min_file_bytes": 64 * 1024 * 1024,
    "min_directory_bytes": 256 * 1024 * 1024,
    "inspect_candidates": 0,
    "max_processes": 20_000,
    "max_fds_per_process": 4_096,
    "max_proc_bytes": 64 * 1024,
    "max_proc_milliseconds": 2_000,
}


def _caps(value: dict[str, Any] | None) -> dict[str, int]:
    result = dict(DEFAULT_CAPS)
    if value:
        for key, raw in value.items():
            if key not in result:
                continue
            if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
                raise ValueError(f"caps.{key} must be a non-negative integer")
            result[key] = raw
    if result["max_entries"] < 1 or result["max_depth"] < 1:
        raise ValueError("max_entries and max_depth must be positive")
    return result


def _allocated(st: os.stat_result) -> int:
    return max(0, int(getattr(st, "st_blocks", 0)) * 512)


def _identity(st: os.stat_result) -> dict[str, int]:
    return {
        "dev": int(st.st_dev),
        "ino": int(st.st_ino),
        "mode": int(st.st_mode),
        "uid": int(st.st_uid),
        "gid": int(st.st_gid),
        "size": int(st.st_size),
        "mtime_ns": int(st.st_mtime_ns),
        "ctime_ns": int(st.st_ctime_ns),
        "nlink": int(st.st_nlink),
    }


def _root_path(root: str | os.PathLike[str]) -> Path:
    raw = os.fspath(root)
    if "\x00" in raw:
        raise ValueError("root contains NUL")
    path = Path(os.path.abspath(raw))
    # Refuse symlinks in every supplied path component. Resolving first would
    # silently change the requested scan boundary.
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        try:
            st = current.lstat()
        except OSError:
            continue
        if stat.S_ISLNK(st.st_mode):
            raise ValueError("root path contains a symlink component")
    return path


def _mountpoints() -> tuple[set[str], str | None]:
    mountinfo = Path("/proc/self/mountinfo")
    try:
        result: set[str] = set()
        with mountinfo.open("r", encoding="utf-8", errors="strict") as stream:
            for line in stream:
                fields = line.split()
                if len(fields) < 5:
                    return result, "malformed_mountinfo"
                mount = fields[4]
                for encoded, decoded in (("\\040", " "), ("\\011", "\t"),
                                         ("\\012", "\n"), ("\\134", "\\")):
                    mount = mount.replace(encoded, decoded)
                result.add(os.path.normpath(mount))
        return result, None
    except OSError as exc:
        return set(), f"mountinfo_unavailable:{type(exc).__name__}"


def _base(root: Path) -> dict[str, Any]:
    try:
        root_stat = root.lstat()
    except OSError as exc:
        return {"schema_version": SCHEMA_VERSION, "root": str(root),
                "status": "error", "error": f"root_unavailable:{type(exc).__name__}",
                "candidates": [], "skipped": []}
    if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
        return {"schema_version": SCHEMA_VERSION, "root": str(root),
                "status": "error", "error": "root_must_be_real_directory",
                "candidates": [], "skipped": []}
    return {"schema_version": SCHEMA_VERSION, "root": str(root),
            "root_identity": _identity(root_stat), "status": "complete",
            "capabilities": {}, "totals": {"entries": 0, "files": 0,
            "directories": 0, "allocated_bytes": 0},
            "candidates": [], "sparse_files": [], "skipped": []}


def scan(root: str | os.PathLike[str], caps: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return a bounded inventory. Errors and visibility gaps become unknowns."""
    limits = _caps(caps)
    base = _base(_root_path(root))
    if base["status"] == "error":
        return base

    mounts, mount_error = _mountpoints()
    base["capabilities"]["mount_table"] = "available" if mount_error is None else "unknown"
    if mount_error:
        base["capabilities"]["mount_table_reason"] = mount_error
        base["status"] = "partial"

    root_path = Path(base["root"])
    root_dev = base["root_identity"]["dev"]
    # Records accumulate sizes bottom-up. Symlinks and mount boundaries count
    # as entries but their targets/contents are never read.
    dirs: dict[str, dict[str, Any]] = {
        str(root_path): {"allocated": 0, "newest_mtime_ns": 0, "entries": 0}
    }
    records: list[dict[str, Any]] = []
    sparse_records: list[dict[str, Any]] = []
    records_by_inode: dict[tuple[int, int], dict[str, Any]] = {}
    seen_file_inodes: set[tuple[int, int]] = set()
    stack: list[tuple[Path, int, bool]] = [(root_path, 0, False)]
    counted = 0

    while stack:
        path, depth, visited = stack.pop()
        if visited:
            if path == root_path:
                continue
            record = dirs.get(str(path))
            if record is None:
                continue
            parent = str(path.parent)
            if parent in dirs:
                dirs[parent]["allocated"] += record["allocated"]
                dirs[parent]["newest_mtime_ns"] = max(
                    dirs[parent]["newest_mtime_ns"], record["newest_mtime_ns"])
                dirs[parent]["entries"] += record["entries"] + 1
            if record["allocated"] >= limits["min_directory_bytes"]:
                try:
                    st = path.lstat()
                except OSError:
                    continue
                records.append({"path": str(path), "identity": _identity(st),
                                "allocated_bytes": record["allocated"],
                                "newest_mtime_ns": record["newest_mtime_ns"],
                                "entry_count": record["entries"] + 1,
                                "kind": "directory", "category": "inventory_directory"})
            continue

        try:
            st = path.lstat()
        except OSError as exc:
            base["skipped"].append({"path": str(path), "reason": f"stat:{type(exc).__name__}",
                                    "unknown": True})
            base["status"] = "partial"
            continue
        counted += 1
        if counted > limits["max_entries"]:
            base["skipped"].append({"path": str(path), "reason": "entry_budget_exhausted",
                                    "unknown": True})
            base["status"] = "partial"
            break

        allocated = _allocated(st)
        base["totals"]["entries"] += 1
        base["totals"]["allocated_bytes"] += allocated
        if stat.S_ISDIR(st.st_mode):
            base["totals"]["directories"] += 1
            dirs.setdefault(str(path), {"allocated": allocated,
                                        "newest_mtime_ns": st.st_mtime_ns,
                                        "entries": 0})
            if path != root_path:
                stack.append((path, depth, True))
            if path != root_path and os.path.normpath(str(path)) in mounts:
                base["skipped"].append({"path": str(path), "reason": "mount_boundary",
                                        "unknown": True})
                base["status"] = "partial"
                continue
            if mount_error and path != root_path:
                base["skipped"].append({"path": str(path), "reason": "mount_visibility_unknown",
                                        "unknown": True})
                base["status"] = "partial"
                continue
            if st.st_dev != root_dev:
                base["skipped"].append({"path": str(path), "reason": "filesystem_boundary",
                                        "unknown": True})
                base["status"] = "partial"
                continue
            if depth >= limits["max_depth"]:
                base["skipped"].append({"path": str(path), "reason": "depth_budget_exhausted",
                                        "unknown": True})
                base["status"] = "partial"
                continue
            try:
                with os.scandir(path) as entries:
                    children: list[Path] = []
                    for entry in entries:
                        if counted + len(stack) + len(children) >= limits["max_entries"]:
                            base["skipped"].append({"path": str(path),
                                                    "reason": "entry_queue_budget_exhausted",
                                                    "omitted_children_at_least": 1,
                                                    "unknown": True})
                            base["status"] = "partial"
                            break
                        children.append(Path(entry.path))
            except OSError as exc:
                base["skipped"].append({"path": str(path), "reason": f"enumerate:{type(exc).__name__}",
                                        "unknown": True})
                base["status"] = "partial"
                continue
            stack.extend((child, depth + 1, False) for child in reversed(children))
        elif stat.S_ISREG(st.st_mode):
            base["totals"]["files"] += 1
            inode_key = (st.st_dev, st.st_ino)
            first_link = inode_key not in seen_file_inodes
            seen_file_inodes.add(inode_key)
            if not first_link:
                base["totals"]["allocated_bytes"] -= allocated
            parent = str(path.parent)
            if parent in dirs:
                # Hard links are one physical allocation, even when reachable
                # through several names. They remain ineligible for deletion.
                if first_link:
                    dirs[parent]["allocated"] += allocated
                dirs[parent]["newest_mtime_ns"] = max(dirs[parent]["newest_mtime_ns"], st.st_mtime_ns)
                dirs[parent]["entries"] += 1
            if allocated >= limits["min_file_bytes"]:
                prior = records_by_inode.get(inode_key)
                if prior is not None:
                    prior.setdefault("hardlink_paths", []).append(str(path))
                elif first_link:
                    item = {"path": str(path), "identity": _identity(st),
                            "allocated_bytes": allocated, "newest_mtime_ns": st.st_mtime_ns,
                            "entry_count": 1, "kind": "file", "category": "inventory_large_file",
                            "logical_size_bytes": int(st.st_size),
                            "extension": path.suffix.lower() or None}
                    records.append(item)
                    records_by_inode[inode_key] = item
            elif st.st_size >= limits["min_file_bytes"] and first_link:
                sparse_records.append({"path": str(path), "identity": _identity(st),
                                       "allocated_bytes": allocated,
                                       "logical_size_bytes": int(st.st_size),
                                       "kind": "sparse_file_fact",
                                       "extension": path.suffix.lower() or None})
        elif stat.S_ISLNK(st.st_mode):
            base["skipped"].append({"path": str(path), "reason": "symlink_not_followed",
                                    "unknown": True})
            base["status"] = "partial"
        else:
            base["skipped"].append({"path": str(path), "reason": "unsupported_file_type",
                                    "unknown": True})
            base["status"] = "partial"

    records.sort(key=lambda item: (-item["allocated_bytes"], item["path"]))
    sparse_records.sort(key=lambda item: (-item["logical_size_bytes"], item["path"]))
    total_records = len(records)
    records = records[:limits["max_candidates"]]
    for index, item in enumerate(records):
        if index >= limits["inspect_candidates"]:
            item["evidence"] = {"status": "not_checked", "unknown": ["inspection_budget_exhausted"]}
            item["unknown"] = True
        else:
            item["evidence"] = inspect(item, {
                "max_processes": limits["max_processes"],
                "max_fds_per_process": limits["max_fds_per_process"],
                "max_proc_bytes": limits["max_proc_bytes"],
                "max_proc_milliseconds": limits["max_proc_milliseconds"],
            })
            item["unknown"] = bool(item["evidence"].get("unknown"))
    if total_records > len(records):
        base["status"] = "partial"
        base["skipped"].append({"reason": "candidate_budget_exhausted",
                                "omitted_candidates": total_records - len(records),
                                "unknown": True})
    base["totals"]["candidate_count"] = total_records
    base["candidates"] = records
    base["sparse_files"] = sparse_records[:limits["max_candidates"]]
    if len(sparse_records) > limits["max_candidates"]:
        base["status"] = "partial"
        base["skipped"].append({"reason": "sparse_fact_budget_exhausted",
                                "omitted_sparse_files": len(sparse_records) - limits["max_candidates"],
                                "unknown": True})
    return base
