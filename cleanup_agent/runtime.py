"""Isolated OpenCode + local llama.cpp runtime.

This module starts short-lived child processes only.  It does not install or
register services, expose model tools, or make deletion decisions.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from pathlib import Path
from typing import Mapping


class RuntimeErrorBase(RuntimeError):
    """Base error for unavailable or failed local inference."""


class RuntimeUnavailable(RuntimeErrorBase):
    """The required local executable/model cannot be started."""


class RuntimeFailure(RuntimeErrorBase):
    """The OpenCode/model run failed or returned no usable text."""


class RuntimeTimeout(RuntimeFailure):
    """A bounded startup or inference operation timed out."""


class RuntimeInterrupted(RuntimeFailure):
    """The parent requested shutdown; owned child processes were cleaned up."""


class OpenCodeRuntime:
    """Run one OpenCode request against a temporary local llama-server.

    All OpenCode tools and permissions are denied in a private configuration.
    The model receives only the caller's prompt and cannot run commands or
    mutate files.  The server is bound to IPv4 loopback and every child is
    stopped as a process group on success, error, timeout, or interruption.
    """

    def __init__(
        self,
        *,
        opencode_bin: str | os.PathLike[str] | None = None,
        llama_server_bin: str | os.PathLike[str] | None = None,
        model_path: str | os.PathLike[str] | None = None,
        runtime_dir: str | os.PathLike[str] | None = None,
        context_size: int = 4096,
        threads: int | None = None,
        startup_timeout: float = 45.0,
        request_timeout: float = 120.0,
        max_prompt_chars: int = 10_000,
    ) -> None:
        if context_size < 4096:
            raise ValueError("context_size must be at least 4096; 2048 caused OpenCode compaction loops in smoke tests")
        if startup_timeout <= 0 or request_timeout <= 0:
            raise ValueError("timeouts must be positive")
        if threads is not None and threads <= 0:
            raise ValueError("threads must be positive")
        if max_prompt_chars < 1:
            raise ValueError("max_prompt_chars must be positive")
        transport = os.environ.get("CLEANUP_AGENT_TRANSPORT", "loopback")
        if transport != "loopback":
            if transport == "stdio":
                raise RuntimeUnavailable("stdio transport is not yet supported by the bundled runtime")
            raise RuntimeUnavailable(f"unsupported local model transport: {transport}")
        self.opencode_bin = self._resolve_executable(opencode_bin, "OPENCODE_BIN", "opencode")
        self.llama_server_bin = self._resolve_executable(llama_server_bin, "LLAMA_SERVER_BIN", "llama-server")
        model = model_path or os.environ.get("CLEANUP_AGENT_MODEL_PATH")
        if not model:
            raise RuntimeUnavailable("set CLEANUP_AGENT_MODEL_PATH to the bundled local GGUF model")
        self.model_path = Path(model).expanduser().resolve()
        if not self.model_path.is_file():
            raise RuntimeUnavailable(f"local model file not found: {self.model_path}")
        base = runtime_dir or os.environ.get("DISKCLEANUP_RUNTIME_DIR")
        if base is None:
            base = os.environ.get("XDG_RUNTIME_DIR") or os.environ.get("TMPDIR") or tempfile.gettempdir()
        self.runtime_base = Path(base).expanduser().resolve()
        if not self.runtime_base.is_dir() or not os.access(self.runtime_base, os.W_OK | os.X_OK):
            raise RuntimeUnavailable(f"runtime directory is not writable: {self.runtime_base}")
        self.context_size = context_size
        self.threads = max(1, min(4, threads or (os.cpu_count() or 1)))
        self.startup_timeout = startup_timeout
        self.request_timeout = request_timeout
        self.max_prompt_chars = max_prompt_chars

    @staticmethod
    def _resolve_executable(value: str | os.PathLike[str] | None, env_name: str, default: str) -> str:
        candidate = value or os.environ.get(env_name) or default
        path = shutil.which(os.fspath(candidate))
        if path is None:
            raise RuntimeUnavailable(f"executable not found: {candidate} (set {env_name})")
        return path

    def generate(
        self, prompt: str, *, response_schema: Mapping[str, object] | None = None
    ) -> str:
        """Return the final assistant text or raise an explicit runtime error."""
        if not isinstance(prompt, str) or not prompt.strip():
            raise ValueError("prompt must be a non-empty string")
        if len(prompt) > self.max_prompt_chars:
            raise RuntimeFailure(
                f"prompt is {len(prompt)} characters; limit is {self.max_prompt_chars}. "
                "No partial scan was sent to the model."
            )

        work_root = Path(tempfile.mkdtemp(prefix="disk-cleanup-opencode-", dir=self.runtime_base))
        os.chmod(work_root, 0o700)
        guard = _SignalGuard()
        guard.install()
        registry_file = os.environ.get("DISKCLEANUP_CHILD_REGISTRY") or str(
            self.runtime_base / f"children-{os.getpid()}.json"
        )
        registry: _ChildRegistry | None = None
        try:
            registry = _ChildRegistry(Path(registry_file))
            work_dir = work_root / "work"
            work_dir.mkdir(mode=0o700)
            config_home = work_root / "config"
            cache_home = work_root / "cache"
            state_home = work_root / "state"
            data_home = work_root / "data"
            home = work_root / "home"
            for directory in (config_home, cache_home, state_home, data_home, home):
                directory.mkdir(mode=0o700)

            port = self._free_loopback_port()
            server_url = f"http://127.0.0.1:{port}/v1"
            server_log = _BoundedPipe()
            runtime_env = self._minimal_child_environment(work_root)
            server = subprocess.Popen(
                self._llama_command(port),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=runtime_env,
                start_new_session=True,
                close_fds=True,
            )
            server._cleanup_agent_port = port  # type: ignore[attr-defined]
            try:
                registry.register(server, self.llama_server_bin)
            except Exception:
                self._stop_process_group(server)
                raise
            server_log.start(server.stdout)
            try:
                self._wait_for_server(server, server_log)
                config = self._opencode_config(
                    server_url, self.context_size, self.request_timeout,
                    response_schema=response_schema,
                )
                env = self._opencode_environment(
                    config=config,
                    config_home=config_home,
                    cache_home=cache_home,
                    state_home=state_home,
                    data_home=data_home,
                    home=home,
                )
                command = [
                    self.opencode_bin,
                    "run",
                    "--pure",
                    "--format", "json",
                    "--model", "local/cleanup-model",
                    "--agent", "cleanup_planner",
                    "--dir", str(work_dir),
                    prompt,
                ]
                client = subprocess.Popen(
                    command,
                    cwd=work_dir,
                    env=env,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    start_new_session=True,
                    close_fds=True,
                )
                try:
                    registry.register(client, self.opencode_bin)
                except Exception:
                    self._stop_process_group(client)
                    raise
                stdout_capture = _CappedPipe(max_bytes=2_000_000)
                stderr_capture = _CappedPipe(max_bytes=256_000)
                stdout_capture.start(client.stdout)
                stderr_capture.start(client.stderr)
                deadline = time.monotonic() + self.request_timeout
                try:
                    while client.poll() is None:
                        if stdout_capture.overflowed or stderr_capture.overflowed:
                            self._stop_and_forget(client, registry)
                            raise RuntimeFailure("OpenCode output exceeded its bounded capture; no plan was accepted")
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            self._stop_and_forget(client, registry)
                            raise RuntimeTimeout(
                                f"OpenCode exceeded {self.request_timeout:g}s; no plan was accepted"
                            )
                        try:
                            client.wait(timeout=min(0.1, remaining))
                        except subprocess.TimeoutExpired:
                            continue
                finally:
                    self._stop_and_forget(client, registry)
                    stdout_capture.join()
                    stderr_capture.join()
                if stdout_capture.overflowed or stderr_capture.overflowed:
                    raise RuntimeFailure("OpenCode output exceeded its bounded capture; no plan was accepted")
                stdout = stdout_capture.text()
                stderr = stderr_capture.text()
                diagnostic_path = self._write_diagnostic_dump(
                    stdout,
                    stderr,
                    work_root=work_root,
                    enabled=os.environ.get("CLEANUP_AGENT_DIAGNOSTIC_DUMP") == "1",
                )
                if client.returncode != 0:
                    stderr_tail = _tail(stderr, 4000)
                    raise RuntimeFailure(
                        f"OpenCode exited with status {client.returncode}; stderr tail: {stderr_tail or '(empty)'}"
                    )
                event_error = self._first_error_event(stdout)
                if event_error is not None:
                    name, message = event_error
                    detail = _redact_diagnostic(
                        f"{name}: {message}",
                        [str(work_root), str(self.runtime_base), self.opencode_bin,
                         self.llama_server_bin, str(self.model_path)],
                        max_chars=500,
                    )
                    suffix = f"; bounded diagnostic saved to {diagnostic_path}" if diagnostic_path else ""
                    raise RuntimeFailure(f"OpenCode stream error: {detail}{suffix}")
                text = self._extract_text(stdout)
                if not text.strip():
                    summary = self._event_summary(stdout)
                    suffix = f"; bounded diagnostic saved to {diagnostic_path}" if diagnostic_path else ""
                    raise RuntimeFailure(
                        "OpenCode returned no assistant text "
                        f"(stdout_bytes={len(stdout.encode('utf-8', errors='replace'))}, "
                        f"events={summary}){suffix}"
                    )
                return text.strip()
            finally:
                self._stop_and_forget(server, registry)
                if server_log.tail():
                    # Retain server diagnostics only in the exception path;
                    # keeping them out of normal output avoids noisy reports.
                    pass
        finally:
            guard.protect_cleanup()
            if registry is not None:
                registry.cleanup_remaining()
            cleanup_pending = bool(registry and registry.entries)
            if registry is None or not registry.entries:
                if registry is not None:
                    registry.remove_file()
                shutil.rmtree(work_root, ignore_errors=True)
            guard.restore()
            if cleanup_pending:
                raise RuntimeFailure("an owned child group could not be verified as stopped; child registry retained")

    @staticmethod
    def _free_loopback_port() -> int:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.bind(("127.0.0.1", 0))
                return int(probe.getsockname()[1])
        except OSError as exc:
            raise RuntimeUnavailable(
                "local inference needs loopback TCP sockets; this sandbox denies socket creation/bind"
            ) from exc

    def _llama_command(self, port: int) -> list[str]:
        return [
            self.llama_server_bin,
            "--model", str(self.model_path),
            "--host", "127.0.0.1",
            "--port", str(port),
            "--ctx-size", str(self.context_size),
            "--threads", str(self.threads),
            "--parallel", "1",
            "--no-webui",
            # Qwen3.5 supports a non-thinking mode. llama.cpp b11160 exposes
            # the stable `--reasoning off` option; avoid spending the small
            # output budget on hidden reasoning tokens.
            "--reasoning", "off",
        ]

    def _wait_for_server(self, process: subprocess.Popen[str], logs: "_BoundedPipe") -> None:
        deadline = time.monotonic() + self.startup_timeout
        # llama's health endpoint is served at /health (outside the /v1 API).
        # Use a numeric loopback URL, never a hostname that triggers DNS.
        port = self._port_from_server(process, logs)
        health_url = f"http://127.0.0.1:{port}/health"
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeUnavailable(
                    f"llama-server exited with status {process.returncode}: {_tail(logs.tail(), 4000)}"
                )
            try:
                with opener.open(health_url, timeout=1.0) as response:
                    if response.status == 200:
                        return
            except (urllib.error.URLError, TimeoutError, OSError):
                time.sleep(0.2)
        raise RuntimeTimeout(
            f"llama-server did not become healthy within {self.startup_timeout:g}s: "
            f"{_tail(logs.tail(), 4000)}"
        )

    @staticmethod
    def _port_from_server(process: subprocess.Popen[str], logs: "_BoundedPipe") -> int:
        # The requested port is logged by llama-server.  Store it as an
        # attribute on the Popen object at creation in future API changes;
        # here the log includes an explicit fallback-resolvable endpoint.
        value = getattr(process, "_cleanup_agent_port", None)
        if value is None:
            raise RuntimeFailure("internal error: missing local model port")
        return int(value)

    @staticmethod
    def _opencode_config(
        base_url: str, context_size: int, request_timeout: float = 110.0,
        *, response_schema: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        # OpenCode v1.14.21 embeds @ai-sdk/openai-compatible.  Do not configure
        # an npm provider package, plugin, MCP server, or inherited user tools.
        timeout_ms = int(min(180.0, max(1.0, request_timeout)) * 1000)
        provider_options: dict[str, object] = {
            "baseURL": base_url,
            "timeout": timeout_ms,
            "chunkTimeout": timeout_ms,
        }
        model_options: dict[str, object] = {}
        if response_schema is not None:
            # OpenCode's configured model options are forwarded as the
            # openai-compatible provider options for the language model.
            # A provider-level extraBody is ignored by the pinned bundled SDK.
            model_options["response_format"] = {
                "type": "json_schema",
                "schema": dict(response_schema),
            }
        return {
            "$schema": "https://opencode.ai/config.json",
            "model": "local/cleanup-model",
            "provider": {
                "local": {
                    "name": "Local llama.cpp",
                    "npm": "@ai-sdk/openai-compatible",
                    # A model's prompt prefill can leave the SSE stream silent
                    # longer than 30s on two CPU threads. Bound both provider
                    # waits by the caller's request budget; Python still
                    # enforces the outer deadline and terminates child groups.
                    "options": provider_options,
                    "models": {
                        "cleanup-model": {
                            "name": "Local cleanup model",
                            "tool_call": False,
                    "limit": {"context": context_size, "output": 1024},
                            "options": model_options,
                        }
                    },
                }
            },
            "agent": {
                "cleanup_planner": {
                    "name": "cleanup_planner",
                    "description": "Read-only disk cleanup advisor",
                    "mode": "primary",
                    "temperature": 0,
                    # OpenCode injects its MAXIMUM STEPS instruction when
                    # step >= cap. A cap of 1 poisons the very first prompt;
                    # use 2 so the model gets one normal response and at
                    # most one bounded follow-up. Tools remain denied.
                    "steps": 2,
                    "permission": {"*": "deny"},
                    "options": {},
                }
            },
            "tools": {"*": False},
            "permission": {"*": "deny"},
            "compaction": {"auto": False},
            "mcp": {},
        }

    @staticmethod
    def _opencode_environment(
        *,
        config: Mapping[str, object],
        config_home: Path,
        cache_home: Path,
        state_home: Path,
        data_home: Path,
        home: Path,
    ) -> dict[str, str]:
        env = OpenCodeRuntime._minimal_child_environment(home)
        env.update({
            "XDG_CONFIG_HOME": str(config_home),
            "XDG_CACHE_HOME": str(cache_home),
            "XDG_STATE_HOME": str(state_home),
            "XDG_DATA_HOME": str(data_home),
            "OPENCODE_CONFIG_CONTENT": json.dumps(config, separators=(",", ":")),
            "OPENCODE_DISABLE_AUTOUPDATE": "1",
            "OPENCODE_DISABLE_DEFAULT_PLUGINS": "1",
            "OPENCODE_DISABLE_LSP_DOWNLOAD": "1",
            "OPENCODE_DISABLE_MODELS_FETCH": "1",
            "OPENCODE_DISABLE_AUTOCOMPACT": "1",
            "OPENCODE_DISABLE_EXTERNAL_SKILLS": "1",
            "OPENCODE_DISABLE_PROJECT_CONFIG": "1",
            "NO_PROXY": "127.0.0.1,localhost",
            "no_proxy": "127.0.0.1,localhost",
        })
        return env

    @staticmethod
    def _minimal_child_environment(temp_root: Path) -> dict[str, str]:
        # Do not pass host credentials, user config locations, or proxy
        # settings into either local executable. Dynamic-library paths remain
        # available for unpacked release binaries.
        env = {key: os.environ[key] for key in ("PATH", "LD_LIBRARY_PATH", "LANG", "LC_ALL")
               if key in os.environ}
        env.update({"HOME": str(temp_root), "TMPDIR": str(temp_root)})
        return env

    @staticmethod
    def _extract_text(stdout: str) -> str:
        parts: list[str] = []
        for line in stdout.splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict) or event.get("type") != "text":
                continue
            part = event.get("part")
            if isinstance(part, dict) and isinstance(part.get("text"), str):
                parts.append(part["text"])
        return "".join(parts)

    @staticmethod
    def _event_summary(stdout: str) -> dict[str, int]:
        """Count event and part kinds without exposing their contents."""
        counts: dict[str, int] = {}
        for line in stdout.splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                counts["non_json_lines"] = counts.get("non_json_lines", 0) + 1
                continue
            if not isinstance(event, dict):
                counts["non_object_events"] = counts.get("non_object_events", 0) + 1
                continue
            event_type = event.get("type")
            key = event_type if isinstance(event_type, str) else "missing_type"
            counts[key[:48]] = counts.get(key[:48], 0) + 1
            part = event.get("part")
            if isinstance(part, dict) and isinstance(part.get("type"), str):
                part_type = "part:" + part["type"][:40]
                counts[part_type] = counts.get(part_type, 0) + 1
        return counts

    @staticmethod
    def _first_error_event(stdout: str) -> tuple[str, str] | None:
        for line in stdout.splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict) or event.get("type") != "error":
                continue
            error = event.get("error")
            if not isinstance(error, dict):
                return "UnknownError", "OpenCode emitted an error event"
            name = error.get("name")
            data = error.get("data")
            message = data.get("message") if isinstance(data, dict) else None
            return (
                name[:80] if isinstance(name, str) else "UnknownError",
                message[:1000] if isinstance(message, str) else "OpenCode emitted an error event",
            )
        return None

    def _write_diagnostic_dump(
        self,
        stdout: str,
        stderr: str,
        *,
        work_root: Path,
        enabled: bool,
    ) -> str | None:
        """Optionally retain a small, private, redacted dump for local diagnosis."""
        if not enabled:
            return None
        redactions = [
            str(work_root),
            str(self.runtime_base),
            self.opencode_bin,
            self.llama_server_bin,
            str(self.model_path),
        ]
        payload = {
            "format": "disk-cleanup-agent-opencode-diagnostic-v1",
            "events": self._event_summary(stdout),
            "stdout_tail": _redact_diagnostic(stdout, redactions),
            "stderr_tail": _redact_diagnostic(stderr, redactions),
        }
        target = self.runtime_base / f"opencode-diagnostic-{os.getpid()}.json"
        data = (json.dumps(payload, ensure_ascii=True, separators=(",", ":")) + "\n").encode("utf-8")
        try:
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            return str(target)
        except OSError:
            # Diagnostics must never make the inference path fail or mask its
            # actual result. The directory is private and path is predictable.
            return None

    @staticmethod
    def _stop_process_group(process: subprocess.Popen[object], grace: float = 3.0,
                            pgid: int | None = None) -> bool:
        group = process.pid if pgid is None else pgid
        if group == os.getpgrp():
            return False
        if group != process.pid:
            # The runtime always starts its children as session leaders. A
            # mismatched registry PGID is not safe to signal without a live
            # leader identity check.
            return False
        try:
            os.killpg(group, signal.SIGTERM)
        except ProcessLookupError:
            if process.poll() is None:
                try:
                    process.wait(timeout=grace)
                except subprocess.TimeoutExpired:
                    pass
            return process.poll() is not None and OpenCodeRuntime._group_has_live_members(group) is False

        deadline = time.monotonic() + grace
        while time.monotonic() < deadline:
            if process.poll() is None:
                try:
                    process.wait(timeout=0.05)
                except subprocess.TimeoutExpired:
                    pass
            live = OpenCodeRuntime._group_has_live_members(group)
            if live is False:
                return process.poll() is not None
            time.sleep(0.025)

        # SIGTERM can leave a descendant running after the session leader has
        # exited. The stored PGID still identifies this isolated session while
        # members remain; SIGKILL it, then verify that no non-zombie member is
        # left. `killpg(pgid, 0)` alone counts unreaped zombies as alive.
        try:
            os.killpg(group, signal.SIGKILL)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline:
            if process.poll() is None:
                try:
                    process.wait(timeout=0.05)
                except subprocess.TimeoutExpired:
                    pass
            live = OpenCodeRuntime._group_has_live_members(group)
            if live is False:
                return process.poll() is not None
            time.sleep(0.025)
        if process.poll() is None:
            try:
                process.wait(timeout=0.1)
            except subprocess.TimeoutExpired:
                return False
        return OpenCodeRuntime._group_has_live_members(group) is False

    @staticmethod
    def _group_has_live_members(pgid: int) -> bool | None:
        """Return whether /proc shows a live group member; None means unknown."""
        proc = Path("/proc")
        try:
            entries = list(proc.iterdir())
        except OSError:
            return None
        live = False
        unknown = False
        for entry in entries:
            if not entry.name.isdigit():
                continue
            try:
                content = (entry / "stat").read_text(encoding="ascii")
                fields = content.rsplit(")", 1)[1].split()
                state = fields[0]
                process_group = int(fields[2])
            except FileNotFoundError:
                continue
            except PermissionError:
                unknown = True
                continue
            except (OSError, ValueError, IndexError):
                unknown = True
                continue
            if process_group == pgid and state not in {"Z", "X"}:
                live = True
        if live:
            return True
        return None if unknown else False

    @classmethod
    def _stop_and_forget(cls, process: subprocess.Popen[object], registry: "_ChildRegistry") -> bool:
        entry = registry.entries.get(process.pid)
        if entry is None:
            return process.poll() is not None
        if not registry.still_same_child(entry):
            if process.poll() is None or entry.get("pid") != process.pid:
                return False
            # A normal early exit can be reaped before cleanup starts, while
            # children remain in the dedicated session. Clean that exact group
            # using its recorded PGID; never signal a mismatched group.
        clean = cls._stop_process_group(process, pgid=entry["pgid"])
        if clean:
            registry.remove(process.pid)
        return clean


class _SignalGuard:
    """Turn launcher signals into Python unwinding so child cleanup runs."""

    def __init__(self) -> None:
        self._previous: dict[int, object] = {}
        self._active = False

    def install(self) -> None:
        if threading.current_thread() is not threading.main_thread():
            return
        for number in (signal.SIGINT, signal.SIGTERM):
            self._previous[number] = signal.signal(number, self._handle)
        self._active = True

    @staticmethod
    def _handle(number: int, _frame: object) -> None:
        # Ignore repeats while unwinding and terminating the owned children.
        signal.signal(number, signal.SIG_IGN)
        raise RuntimeInterrupted(f"runtime interrupted by signal {number}")

    def protect_cleanup(self) -> None:
        if self._active:
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            signal.signal(signal.SIGTERM, signal.SIG_IGN)

    def restore(self) -> None:
        if self._active:
            for number, handler in self._previous.items():
                signal.signal(number, handler)  # type: ignore[arg-type]
            self._active = False


class _ChildRegistry:
    """Exact PID/PGID handoff for a release launcher hard-timeout fallback."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.entries: dict[int, dict[str, Any]] = {}
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.path.is_symlink():
            raise RuntimeUnavailable("child registry must not be a symlink")
        if self.path.exists():
            try:
                existing = json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise RuntimeUnavailable("child registry is unreadable; refusing to overwrite it") from exc
            if not isinstance(existing, dict) or existing.get("version") != 1 or existing.get("children") != []:
                raise RuntimeUnavailable("child registry is already in use; refusing to overwrite it")
        self._write()

    def _write(self) -> None:
        fd, temporary_name = tempfile.mkstemp(prefix=f".{self.path.name}.", suffix=".tmp", dir=self.path.parent)
        temporary = Path(temporary_name)
        try:
            os.fchmod(fd, 0o600)
            payload = {"version": 1, "children": sorted(self.entries.values(), key=lambda item: item["pid"])}
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(payload, stream, separators=(",", ":"))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    @staticmethod
    def _start_ticks(pid: int) -> int:
        content = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        tail = content.rsplit(")", 1)[1].split()
        return int(tail[19])

    def register(self, process: subprocess.Popen[object], executable: str) -> None:
        if process.poll() is not None:
            return
        try:
            pgid = os.getpgid(process.pid)
            proc_exe = str(Path(f"/proc/{process.pid}/exe").resolve())
            expected_exe = str(Path(executable).resolve())
            if proc_exe != expected_exe:
                raise RuntimeUnavailable("child executable does not match the requested bundled binary")
            entry = {"pid": process.pid, "pgid": pgid, "start_ticks": self._start_ticks(process.pid),
                     "exe": expected_exe}
        except (OSError, ValueError, IndexError) as exc:
            raise RuntimeUnavailable("cannot verify child PID through /proc; refusing an untracked process") from exc
        self.entries[process.pid] = entry
        self._write()

    def still_same_child(self, entry: dict[str, Any]) -> bool:
        try:
            pid = int(entry["pid"])
            return (os.getpgid(pid) == int(entry["pgid"])
                    and self._start_ticks(pid) == int(entry["start_ticks"])
                    and str(Path(f"/proc/{pid}/exe").resolve()) == entry["exe"])
        except (OSError, ValueError, KeyError, IndexError):
            return False

    def remove(self, pid: int) -> None:
        if pid in self.entries:
            del self.entries[pid]
            self._write()

    def cleanup_remaining(self) -> None:
        for pid, entry in list(self.entries.items()):
            if not self.still_same_child(entry):
                # If the verified leader exited but its session still exists,
                # retain the record for the parent launcher to report/handle.
                # Never signal a PGID after its leader identity is unavailable.
                try:
                    os.killpg(int(entry["pgid"]), 0)
                except ProcessLookupError:
                    self.remove(pid)
                continue
            try:
                os.killpg(int(entry["pgid"]), signal.SIGKILL)
            except ProcessLookupError:
                self.remove(pid)
            except OSError:
                continue
            else:
                deadline = time.monotonic() + 1.0
                while time.monotonic() < deadline:
                    try:
                        os.killpg(int(entry["pgid"]), 0)
                    except ProcessLookupError:
                        self.remove(pid)
                        break
                    time.sleep(0.05)

    def remove_file(self) -> None:
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass


class _BoundedPipe:
    """Drain child logs continuously while retaining only the last 80 KiB."""

    def __init__(self, max_chars: int = 80_000) -> None:
        self._lines: deque[str] = deque()
        self._max_chars = max_chars
        self._size = 0
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None

    def start(self, pipe: object) -> None:
        def drain() -> None:
            for raw in pipe:  # type: ignore[union-attr]
                line = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
                with self._lock:
                    self._lines.append(line)
                    self._size += len(line)
                    while self._size > self._max_chars and self._lines:
                        self._size -= len(self._lines.popleft())

        self._thread = threading.Thread(target=drain, name="llama-log-drain", daemon=True)
        self._thread.start()

    def tail(self) -> str:
        with self._lock:
            return "".join(self._lines)


class _CappedPipe:
    """Continuously drain a subprocess pipe while retaining bounded output."""

    def __init__(self, max_bytes: int) -> None:
        self.max_bytes = max_bytes
        self._chunks: list[bytes] = []
        self._size = 0
        self.overflowed = False
        self._thread: threading.Thread | None = None

    def start(self, pipe: object) -> None:
        def drain() -> None:
            while True:
                chunk = pipe.read(64 * 1024)  # type: ignore[union-attr]
                if not chunk:
                    return
                if self._size + len(chunk) > self.max_bytes:
                    self.overflowed = True
                    continue
                self._chunks.append(chunk)
                self._size += len(chunk)

        self._thread = threading.Thread(target=drain, name="opencode-output-drain", daemon=True)
        self._thread.start()

    def join(self) -> None:
        if self._thread:
            self._thread.join(timeout=2.0)

    def text(self) -> str:
        return b"".join(self._chunks).decode("utf-8", "replace")


def _tail(value: str, max_chars: int) -> str:
    return value[-max_chars:]


def _redact_diagnostic(value: str, known_paths: list[str], max_chars: int = 8192) -> str:
    text = _tail(value, max_chars)
    for path in sorted((item for item in known_paths if item), key=len, reverse=True):
        text = text.replace(path, "[LOCAL_PATH]")
    text = re.sub(r"(?i)\bbearer\s+[^\s,;\"']+", "Bearer [REDACTED]", text)
    text = re.sub(
        r"(?i)\b(authorization|api[_-]?key|access[_-]?token|password)\s*([:=])\s*[^\s,;\"']+",
        r"\1\2[REDACTED]",
        text,
    )
    return text
