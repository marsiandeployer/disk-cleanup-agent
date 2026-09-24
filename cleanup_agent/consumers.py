"""Bounded, read-only hints about consumers outside the process table.

An empty result means only that the named source was checked. Callers must keep
the scope and any unknown checks visible; these hints never authorize deletion.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
from typing import Any


MAX_OUTPUT = 2_000_000


def _run(argv: list[str], timeout: float = 3) -> tuple[str, str]:
    if not shutil.which(argv[0]):
        return "unknown", "command_missing"
    try:
        result = subprocess.run(
            argv, capture_output=True, timeout=timeout, check=False,
            env={**os.environ, "NO_COLOR": "1"},
        )
    except subprocess.TimeoutExpired:
        return "unknown", "timeout"
    except OSError as exc:
        return "unknown", type(exc).__name__
    if len(result.stdout) > MAX_OUTPUT or len(result.stderr) > MAX_OUTPUT:
        return "unknown", "output_limit"
    if result.returncode != 0:
        return "unknown", f"exit_{result.returncode}"
    return "ok", result.stdout.decode("utf-8", "replace")


def _overlaps(target: Path, reference: str) -> bool:
    if not reference.startswith("/"):
        return False
    try:
        ref = Path(reference).resolve(strict=False)
        return target == ref or target in ref.parents or ref in target.parents
    except (OSError, RuntimeError, ValueError):
        return False


def _result(status: str, source: str, matches: list[str] | None = None,
            reason: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"status": status, "source": source,
                               "matches": matches or []}
    if reason:
        result["reason"] = reason
    return result


def docker_mounts(path: str | Path, *, max_containers: int = 100) -> dict[str, Any]:
    target = Path(path).resolve(strict=False)
    state, output = _run(["docker", "ps", "-aq", "--no-trunc"])
    if state != "ok":
        return _result("unknown", "docker ps -aq", reason=output)
    ids = output.splitlines()
    if len(ids) > max_containers:
        return _result("unknown", "docker ps -aq", reason="container_limit")
    if not ids:
        return _result("clear", "docker ps -aq")
    state, output = _run(["docker", "inspect", *ids], timeout=6)
    if state != "ok":
        return _result("unknown", "docker inspect", reason=output)
    try:
        containers = json.loads(output)
        if not isinstance(containers, list):
            raise ValueError("expected list")
    except (json.JSONDecodeError, ValueError):
        return _result("unknown", "docker inspect", reason="invalid_json")
    matches: list[str] = []
    for container in containers:
        if not isinstance(container, dict):
            return _result("unknown", "docker inspect", reason="invalid_container")
        for mount in container.get("Mounts", []):
            source = mount.get("Source") if isinstance(mount, dict) else None
            if isinstance(source, str) and _overlaps(target, source):
                matches.append(str(container.get("Name") or container.get("Id") or "container")[:120])
    return _result("in_use" if matches else "clear", "docker inspect Mounts", matches)


def pm2_processes(path: str | Path) -> dict[str, Any]:
    target = Path(path).resolve(strict=False)
    # PM2 commands can spawn a daemon when none exists. A missing RPC socket is
    # therefore an unknown result, not a reason to run `pm2 jlist`.
    pm2_dir = Path(os.environ.get("PM2_HOME", str(Path.home() / ".pm2")))
    rpc_socket = pm2_dir / "rpc.sock"
    try:
        if not stat.S_ISSOCK(rpc_socket.stat().st_mode):
            return _result("unknown", "pm2 rpc.sock", reason="daemon_socket_unavailable")
    except OSError:
        return _result("unknown", "pm2 rpc.sock", reason="daemon_socket_unavailable")
    if not _pm2_daemon_verified(pm2_dir):
        return _result("unknown", "pm2 daemon pid", reason="daemon_identity_unverified")
    state, output = _run(["pm2", "jlist"], timeout=5)
    if state != "ok":
        return _result("unknown", "pm2 jlist", reason=output)
    try:
        processes = json.loads(output)
        if not isinstance(processes, list):
            raise ValueError("expected list")
    except (json.JSONDecodeError, ValueError):
        return _result("unknown", "pm2 jlist", reason="invalid_json")
    matches: list[str] = []
    for process in processes:
        if not isinstance(process, dict):
            return _result("unknown", "pm2 jlist", reason="invalid_process")
        env = process.get("pm2_env") or {}
        if not isinstance(env, dict):
            continue
        refs = [env.get("pm_cwd"), env.get("pm_exec_path")]
        if any(isinstance(ref, str) and _overlaps(target, ref) for ref in refs):
            matches.append(str(process.get("name") or "pm2-process")[:120])
    return _result("in_use" if matches else "clear", "pm2 jlist cwd/executable", matches)


def _pm2_daemon_verified(pm2_dir: Path) -> bool:
    try:
        pid = int((pm2_dir / "pm2.pid").read_text(encoding="ascii").strip())
        if pid <= 1 or not (Path("/proc") / str(pid) / "cmdline").is_file():
            raise ValueError("stale pid")
        command = (Path("/proc") / str(pid) / "cmdline").read_bytes()[:4096]
        if b"PM2" not in command and b"pm2" not in command:
            raise ValueError("pid is not PM2")
    except (OSError, ValueError):
        return False
    return True


def _literal_files(path: str | Path, roots: list[str | Path], source: str) -> dict[str, Any]:
    target = Path(path).resolve(strict=False)
    existing = [str(Path(root)) for root in roots if Path(root).exists()]
    if not existing:
        return _result("unknown", source, reason="roots_unavailable")
    if not shutil.which("rg"):
        return _result("unknown", source, reason="rg_missing")
    needles = [str(target)]
    if target.name and len(target.name) >= 8:
        needles.append(target.name)
    matches: set[str] = set()
    for needle in needles:
        try:
            result = subprocess.run(
                ["rg", "-F", "-l", "--hidden", "--glob", "!.git/**",
                 "--max-filesize", "1M", "--", needle, *existing],
                capture_output=True, timeout=5, check=False,
            )
        except subprocess.TimeoutExpired:
            return _result("unknown", source, reason="timeout")
        except OSError as exc:
            return _result("unknown", source, reason=type(exc).__name__)
        if len(result.stdout) > MAX_OUTPUT or len(result.stderr) > MAX_OUTPUT:
            return _result("unknown", source, reason="output_limit")
        if result.returncode not in (0, 1):
            return _result("unknown", source, reason=f"exit_{result.returncode}")
        matches.update(line[:300] for line in result.stdout.decode("utf-8", "replace").splitlines())
    # A clear result is scoped to the supplied roots and literal strings only.
    return _result("in_use" if matches else "clear", source, sorted(matches)[:100])


def systemd_units(path: str | Path) -> dict[str, Any]:
    return _literal_files(path, ["/etc/systemd/system", "/usr/lib/systemd/system"],
                          "systemd unit files (literal references)")


def cron_jobs(path: str | Path) -> dict[str, Any]:
    return _literal_files(path, ["/etc/crontab", "/etc/cron.d", "/var/spool/cron"],
                          "system cron files (literal references)")


def git_state(path: str | Path) -> dict[str, Any]:
    target = Path(path).resolve(strict=False)
    if target.is_dir() and ((target / ".git").exists() or
                            ((target / "HEAD").is_file() and (target / "objects").is_dir())):
        return _result("in_use", "Git repository marker", [str(target)])
    if not any((parent / ".git").exists() for parent in (target.parent, *target.parent.parents)):
        return _result("clear", "Git repository marker", reason="outside_repository")
    state, output = _run(["git", "-C", str(target.parent), "rev-parse", "--show-toplevel"])
    if state != "ok":
        return _result("unknown", "git rev-parse", reason=output)
    repo = Path(output.strip())
    try:
        rel = str(target.relative_to(repo))
    except ValueError:
        return _result("unknown", "git rev-parse", reason="inconsistent_root")
    state, output = _run(["git", "-C", str(repo), "ls-files", "--error-unmatch", "--", rel])
    if state == "ok":
        return _result("in_use", "git ls-files", [str(repo)])
    if output == "exit_1":
        return _result("unknown", "git ls-files", reason="untracked_in_repository")
    return _result("unknown", "git ls-files", reason=output)


def literal_code_refs(path: str | Path, roots: list[str | Path] | None = None) -> dict[str, Any]:
    if not roots:
        return _result("unknown", "configured code roots", reason="no_search_roots")
    return _literal_files(path, roots, "configured code roots (literal references)")


def collect(path: str | Path, *, code_roots: list[str | Path] | None = None,
            checks: set[str] | None = None) -> dict[str, Any]:
    """Run selected optional checks; omitted checks remain unverified to callers."""
    available = {
        "docker_mounts": lambda: docker_mounts(path),
        "pm2_processes": lambda: pm2_processes(path),
        "systemd_units": lambda: systemd_units(path),
        "cron_jobs": lambda: cron_jobs(path),
        "git_state": lambda: git_state(path),
        "literal_code_refs": lambda: literal_code_refs(path, code_roots),
    }
    selected = checks if checks is not None else set(available)
    if not selected <= set(available):
        raise ValueError("unknown consumer check requested")
    return {name: available[name]() for name in available if name in selected}
