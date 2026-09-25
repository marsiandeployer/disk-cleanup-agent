"""Bounded, read-only hints about consumers outside the process table.

An empty result means only that the named source was checked. Callers must keep
the scope and any unknown checks visible; these hints never authorize deletion.
"""

from __future__ import annotations

import http.client
import json
import glob
from fnmatch import fnmatchcase
import os
from pathlib import Path
import selectors
import shlex
import signal
import shutil
import socket
import stat
import subprocess
import time
from typing import Any
from urllib.parse import unquote, urlsplit


MAX_OUTPUT = 2_000_000
SERVICE_CONFIG_ROOTS = (Path("/etc/mysql"), Path("/etc/php"), Path("/etc/nginx"))
SERVICE_CONFIG_GLOBS = ("*.cnf", "*.ini", "*.conf", "*.types", "my.cnf",
                        "nginx.conf", "mime.types", "fastcgi_params", "scgi_params",
                        "uwsgi_params")
MAX_SERVICE_CONFIG_SOURCES = 256
MAX_SERVICE_CONFIG_ENTRIES = 20_000
MAX_SERVICE_CONFIG_BYTES = 2 * 1024 * 1024
MAX_DOCKER_USAGE_ROWS = 500
DOCKER_USAGE_TIMEOUT = 10
DOCKER_BUILDX_TIMEOUT = 8
DOCKER_BUILDX_QUERY_TIMEOUT = 5


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


def _run_bounded(argv: list[str], timeout: float) -> tuple[str, str]:
    """Run a local CLI command with one shared stdout/stderr memory limit."""
    if not shutil.which(argv[0]):
        return "unknown", "command_missing"
    process: subprocess.Popen[bytes] | None = None
    selector = selectors.DefaultSelector()
    stdout = bytearray()
    stderr = bytearray()
    total = 0
    deadline = time.monotonic() + max(0.0, timeout)

    def stop_process() -> None:
        if process is None:
            return
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            try:
                process.kill()
            except OSError:
                pass
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            try:
                process.kill()
            except OSError:
                pass
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass

    try:
        process = subprocess.Popen(
            argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
            env={**os.environ, "NO_COLOR": "1"}, start_new_session=True,
        )
        assert process.stdout is not None and process.stderr is not None
        for stream, destination in ((process.stdout, stdout), (process.stderr, stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, destination)

        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                stop_process()
                return "unknown", "timeout"
            events = selector.select(remaining)
            if not events:
                stop_process()
                return "unknown", "timeout"
            for key, _mask in events:
                stream = key.fileobj
                remaining_output = MAX_OUTPUT - total
                try:
                    # Keep retained stdout+stderr at or below MAX_OUTPUT. At
                    # the cap, read one sentinel byte only to detect overflow.
                    chunk = os.read(stream.fileno(), min(65536, max(1, remaining_output)))
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                if len(chunk) > remaining_output:
                    stop_process()
                    return "unknown", "output_limit"
                total += len(chunk)
                key.data.extend(chunk)

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            stop_process()
            return "unknown", "timeout"
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            stop_process()
            return "unknown", "timeout"
        if returncode != 0:
            return "unknown", f"exit_{returncode}"
        return "ok", stdout.decode("utf-8", "replace")
    except OSError as exc:
        stop_process()
        return "unknown", type(exc).__name__
    finally:
        selector.close()
        if process is not None:
            for stream in (process.stdout, process.stderr):
                if stream is not None and not stream.closed:
                    stream.close()


def _overlaps(target: Path, reference: str) -> bool | None:
    if not reference.startswith("/"):
        return None
    try:
        ref = Path(reference).resolve(strict=False)
        return target == ref or target in ref.parents or ref in target.parents
    except (OSError, RuntimeError, ValueError):
        return None


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
        mounts = container.get("Mounts")
        if not isinstance(mounts, list):
            return _result("unknown", "docker inspect Mounts", reason="invalid_mount_list")
        for mount in mounts:
            if not isinstance(mount, dict):
                return _result("unknown", "docker inspect Mounts", reason="invalid_mount")
            if mount.get("Type") == "tmpfs":
                continue
            source = mount.get("Source")
            if not isinstance(source, str) or not source:
                return _result("unknown", "docker inspect Mounts", reason="invalid_mount_source")
            overlaps = _overlaps(target, source)
            if overlaps is None:
                return _result("unknown", "docker inspect Mounts", reason="invalid_mount_source")
            if overlaps:
                matches.append(str(container.get("Name") or container.get("Id") or "container")[:120])
    return _result("in_use" if matches else "clear", "docker inspect Mounts", matches)


def _docker_text(value: Any, *, limit: int = 160) -> str | None:
    if not isinstance(value, str):
        return None
    value = " ".join(value.split())
    return value[:limit] if value else None


def _docker_unix_get(socket_path: str, request_path: str,
                     timeout: float = DOCKER_USAGE_TIMEOUT) -> tuple[int | None, bytes, str | None]:
    deadline = time.monotonic() + max(0.0, timeout)
    sock: socket.socket | None = None

    def set_remaining_timeout() -> None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Docker Engine request deadline exceeded")
        assert sock is not None
        sock.settimeout(remaining)

    try:
        if not request_path.startswith("/") or "\r" in request_path or "\n" in request_path:
            raise http.client.HTTPException("invalid request path")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        set_remaining_timeout()
        sock.connect(socket_path)
        set_remaining_timeout()
        sock.sendall((f"GET {request_path} HTTP/1.1\r\nHost: docker\r\n"
                      "Accept: application/json\r\nConnection: close\r\n\r\n").encode("ascii"))

        buffered = bytearray()

        def receive(max_bytes: int = 65536) -> bytes:
            set_remaining_timeout()
            return sock.recv(max_bytes)

        def read_line(limit: int) -> bytes:
            while True:
                end = buffered.find(b"\r\n")
                if end >= 0:
                    if end > limit:
                        raise http.client.HTTPException("HTTP line exceeds limit")
                    line = bytes(buffered[:end])
                    del buffered[:end + 2]
                    return line
                if len(buffered) > limit:
                    raise http.client.HTTPException("HTTP line exceeds limit")
                chunk = receive(min(4096, limit + 2 - len(buffered)))
                if not chunk:
                    raise http.client.HTTPException("unexpected EOF in HTTP headers")
                buffered.extend(chunk)

        status_line = read_line(8192)
        parts = status_line.split(b" ", 2)
        if len(parts) < 2 or not parts[0].startswith(b"HTTP/1.") or not parts[1].isdigit():
            raise http.client.HTTPException("invalid HTTP status line")
        status = int(parts[1])
        headers: dict[str, str] = {}
        header_bytes = len(status_line) + 2
        while True:
            line = read_line(64 * 1024 - header_bytes)
            header_bytes += len(line) + 2
            if header_bytes > 64 * 1024:
                raise http.client.HTTPException("HTTP headers exceed limit")
            if not line:
                break
            if line[:1] in (b" ", b"\t") or b":" not in line:
                raise http.client.HTTPException("invalid HTTP header")
            name, value = line.split(b":", 1)
            key = name.decode("ascii", "strict").lower()
            text_value = value.decode("iso-8859-1").strip()
            headers[key] = f"{headers[key]},{text_value}" if key in headers else text_value

        def read_exact(count: int) -> bytes:
            while len(buffered) < count:
                chunk = receive(min(65536, count - len(buffered)))
                if not chunk:
                    raise http.client.HTTPException("unexpected EOF in HTTP body")
                buffered.extend(chunk)
            result = bytes(buffered[:count])
            del buffered[:count]
            return result

        transfer_encoding = headers.get("transfer-encoding", "").lower()
        content_length = headers.get("content-length")
        if "chunked" in transfer_encoding:
            body = bytearray()
            while True:
                size_line = read_line(8192)
                try:
                    chunk_size = int(size_line.split(b";", 1)[0], 16)
                except ValueError as exc:
                    raise http.client.HTTPException("invalid chunk size") from exc
                if chunk_size < 0 or len(body) + chunk_size > MAX_OUTPUT:
                    return status, b"", "output_limit"
                if chunk_size == 0:
                    trailer_bytes = 0
                    while True:
                        trailer = read_line(64 * 1024 - trailer_bytes)
                        trailer_bytes += len(trailer) + 2
                        if trailer_bytes > 64 * 1024:
                            raise http.client.HTTPException("HTTP trailers exceed limit")
                        if not trailer:
                            break
                    break
                body.extend(read_exact(chunk_size))
                if read_exact(2) != b"\r\n":
                    raise http.client.HTTPException("invalid chunk terminator")
            result_body = bytes(body)
        elif content_length is not None:
            if not content_length.isdecimal():
                raise http.client.HTTPException("invalid Content-Length")
            length = int(content_length)
            if length > MAX_OUTPUT:
                return status, b"", "output_limit"
            result_body = read_exact(length)
        else:
            body = bytearray(buffered)
            buffered.clear()
            while True:
                chunk = receive(min(65536, MAX_OUTPUT + 1 - len(body)))
                if not chunk:
                    break
                body.extend(chunk)
                if len(body) > MAX_OUTPUT:
                    return status, b"", "output_limit"
            result_body = bytes(body)
        return status, result_body, None
    except (OSError, http.client.HTTPException, TimeoutError, UnicodeError) as exc:
        return None, b"", type(exc).__name__
    finally:
        if sock is not None:
            sock.close()


def _docker_nonnegative_int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _docker_item_id(row: dict[str, Any]) -> str | None:
    return _docker_text(row.get("Id", row.get("ID")), limit=64)


def _docker_image_item(row: dict[str, Any]) -> dict[str, Any] | None:
    image_size = _docker_nonnegative_int(row.get("Size"))
    shared_size = _docker_nonnegative_int(row.get("SharedSize"))
    if image_size is None or shared_size is None or shared_size > image_size:
        return None
    tags = row.get("RepoTags", [])
    if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags):
        return None
    return {"id": _docker_item_id(row), "tags": [_docker_text(tag, limit=160) for tag in tags[:5]],
            "virtual_size_bytes": image_size, "shared_size_bytes": shared_size,
            "unique_size_bytes": image_size - shared_size}


def _docker_container_item(row: dict[str, Any]) -> dict[str, Any] | None:
    writable_size = _docker_nonnegative_int(row.get("SizeRw"))
    names = row.get("Names", [])
    if writable_size is None or not isinstance(names, list) or any(not isinstance(n, str) for n in names):
        return None
    return {"id": _docker_item_id(row), "names": [_docker_text(n, limit=128) for n in names[:5]],
            "image": _docker_text(row.get("Image"), limit=160),
            "state": _docker_text(row.get("State"), limit=64),
            "writable_layer_size_bytes": writable_size}


def _docker_volume_item(row: dict[str, Any]) -> dict[str, Any] | None:
    usage = row.get("UsageData")
    if not isinstance(usage, dict):
        return None
    size = _docker_nonnegative_int(usage.get("Size"))
    refs = _docker_nonnegative_int(usage.get("RefCount"))
    if size is None or refs is None:
        return None
    return {"name": _docker_text(row.get("Name"), limit=128),
            "driver": _docker_text(row.get("Driver"), limit=64),
            "scope": _docker_text(row.get("Scope"), limit=32),
            "size_bytes": size, "reference_count": refs}


def _docker_build_cache_item(row: dict[str, Any]) -> dict[str, Any] | None:
    size = _docker_nonnegative_int(row.get("Size"))
    if size is None:
        return None
    shared = row.get("Shared")
    reclaimable = row.get("Reclaimable")
    mutable = row.get("Mutable")
    return {"id": _docker_item_id(row), "type": _docker_text(row.get("Type", row.get("CacheType")), limit=64),
            "size_bytes": size,
            "shared": shared if isinstance(shared, bool) else None,
            "reclaimable": reclaimable if isinstance(reclaimable, bool) else None,
            "mutable": mutable if isinstance(mutable, bool) else None}


def _docker_buildx_cache(context_name: str) -> dict[str, Any]:
    """Read the selected context's existing Buildx cache, without changing it."""
    state, output = _run_bounded(
        ["docker", "buildx", "du", "--format=json", "--timeout=5s",
         "--builder", context_name],
        timeout=DOCKER_BUILDX_TIMEOUT,
    )
    if state != "ok":
        return {"status": "unknown", "item_count": None, "items": [], "reason": output,
                "source": "docker buildx du"}
    lines = output.splitlines()
    if not lines:
        # Buildx emits one NDJSON object per cache record. Once the local
        # default Docker builder was proven and `du` exited successfully, an
        # empty stream means it has no records; a command failure stays unknown.
        return {"status": "available", "item_count": 0, "items": [],
                "source": "docker buildx du"}
    if len(lines) > MAX_DOCKER_USAGE_ROWS:
        return {"status": "unknown", "item_count": len(lines), "items": [],
                "reason": "row_limit", "source": "docker buildx du"}

    items: list[dict[str, Any]] = []
    try:
        for line in lines:
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError("expected Buildx cache object")
            size_raw = row.get("Size")
            if isinstance(size_raw, str) and size_raw.isdecimal():
                size = int(size_raw)
            else:
                size = _docker_nonnegative_int(size_raw)
            normalized = {
                "ID": row.get("ID"), "Type": row.get("Type"), "Size": size,
                "Shared": row.get("Shared"), "Reclaimable": row.get("Reclaimable"),
                "Mutable": row.get("Mutable"),
            }
            item = _docker_build_cache_item(normalized)
            if (item is None or not item.get("id") or not item.get("type")
                    or not isinstance(item.get("shared"), bool)
                    or not isinstance(item.get("reclaimable"), bool)
                    or not isinstance(item.get("mutable"), bool)):
                raise ValueError("incomplete Buildx cache record")
            items.append(item)
    except (json.JSONDecodeError, ValueError, OverflowError):
        return {"status": "unknown", "item_count": None, "items": [],
                "reason": "invalid_buildx_cache_response", "source": "docker buildx du"}
    return {"status": "available", "item_count": len(items), "items": items,
            "source": "docker buildx du"}


def _docker_buildx_default_is_local(context_name: str) -> tuple[bool, str | None]:
    """Prove that `default` is the Docker driver node for the local context."""
    state, output = _run_bounded(
        ["docker", "buildx", "ls", "--format",
         "{{.Builder.Name}}\t{{.Name}}\t{{.DriverEndpoint}}\t{{.Status}}",
         "--timeout=5s"],
        timeout=DOCKER_BUILDX_TIMEOUT,
    )
    if state != "ok":
        return False, output
    builder_rows = 0
    node_rows = 0
    for line in output.splitlines():
        fields = line.split("\t")
        if len(fields) != 4:
            return False, "unrecognized_builder_inventory"
        if fields[0] != "default":
            continue
        if fields[1] != "default":
            return False, "builder_not_local_default"
        if fields[2] == "docker" and fields[3] in {"", "running"}:
            builder_rows += 1
        elif fields[2] == context_name and fields[3] == "running":
            node_rows += 1
        else:
            # A second node, remote endpoint, non-Docker driver, or inactive
            # builder is not safe evidence for the local Engine cache.
            return False, "builder_not_local_default"
    if builder_rows != 1 or node_rows != 1:
        return False, "ambiguous_builder_inventory"
    return True, None


def _parse_docker_usage_summary(group: Any, *, category: str,
                                item_parser: Any) -> dict[str, Any] | None:
    if not isinstance(group, dict) or not group:
        return None
    items = group.get("Items")
    count = _docker_nonnegative_int(group.get("TotalCount"))
    active = _docker_nonnegative_int(group.get("ActiveCount"))
    total_size = _docker_nonnegative_int(group.get("TotalSize"))
    if not isinstance(items, list) or len(items) > MAX_DOCKER_USAGE_ROWS or count != len(items):
        return None
    if active is None or total_size is None:
        return None
    parsed_items = [item_parser(row) if isinstance(row, dict) else None for row in items]
    incomplete = sum(item is None for item in parsed_items)
    return {"status": "unknown" if incomplete else "available", "item_count": count,
            "active_count": active, "engine_reported_size_bytes": total_size,
            "items": [item for item in parsed_items if item is not None],
            **({"incomplete_item_count": incomplete} if incomplete else {})}


def _parse_legacy_docker_usage(data: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    categories: dict[str, Any] = {}
    unknown: list[str] = []
    layers_size = _docker_nonnegative_int(data.get("LayersSize"))
    if layers_size is None:
        unknown.append("images")
    parsers = {"Images": ("images", _docker_image_item),
               "Containers": ("containers", _docker_container_item),
               "Volumes": ("local_volumes", _docker_volume_item),
               "BuildCache": ("build_cache", _docker_build_cache_item)}
    for source_key, (category, parser) in parsers.items():
        rows = data.get(source_key)
        if not isinstance(rows, list) or len(rows) > MAX_DOCKER_USAGE_ROWS:
            unknown.append(category)
            continue
        if category == "build_cache" and not rows:
            # Empty legacy rows do not distinguish an empty cache from an
            # unavailable builder response; do not invent a zero total.
            unknown.append(category)
            categories[category] = {"status": "unknown", "item_count": 0,
                                    "items": [], "reason": "empty_or_unavailable"}
            continue
        parsed_items = [parser(row) if isinstance(row, dict) else None for row in rows]
        if any(item is None for item in parsed_items):
            unknown.append(category)
            categories[category] = {"status": "unknown", "item_count": len(rows),
                                    "items": [item for item in parsed_items if item is not None],
                                    "reason": "incomplete_item_details"}
            continue
        category_result: dict[str, Any] = {"status": "available", "item_count": len(rows),
                                           "items": parsed_items}
        if category == "images" and layers_size is not None:
            category_result["engine_reported_size_bytes"] = layers_size
        categories[category] = category_result
    return categories, unknown


def docker_storage() -> dict[str, Any]:
    """Read aggregate and per-object Docker storage through one Engine request.

    Local Unix contexts only are supported. API v1.52+ returns typed category
    aggregates with rows; earlier supported APIs return legacy image LayersSize
    plus rows. No shared per-image layer values are summed into a total.
    """
    base = {"status": "unknown", "source": "Docker Engine system df",
            "additivity": "non_additive",
            "accounting_note": (
                "Docker category totals are engine-reported and never combined "
                "into a grand total. Per-image sizes include shared layers; legacy "
                "APIs expose only the image layer aggregate. No physical root-directory "
                "total is derived, and the Engine root path may be remote."
            ),
            "categories": {}}

    state, context_name = _run(["docker", "context", "show"], timeout=3)
    if state != "ok":
        return {**base, "reason": f"context_{context_name}"}
    context_name = context_name.strip()
    if not context_name or len(context_name) > 256:
        return {**base, "reason": "invalid_context_name"}

    state, endpoint_raw = _run(
        ["docker", "context", "inspect", "--format", "{{json .Endpoints.docker}}"],
        timeout=3,
    )
    if state != "ok":
        return {**base, "reason": f"context_endpoint_{endpoint_raw}",
                "context": {"name": context_name}}
    try:
        endpoint_data = json.loads(endpoint_raw)
        endpoint = endpoint_data.get("Host") if isinstance(endpoint_data, dict) else None
        if not isinstance(endpoint, str) or not endpoint or len(endpoint) > 512:
            raise ValueError("invalid context endpoint")
    except (json.JSONDecodeError, ValueError):
        return {**base, "reason": "invalid_context_endpoint",
                "context": {"name": context_name}}
    docker_host_override = os.environ.get("DOCKER_HOST")
    docker_context_override = os.environ.get("DOCKER_CONTEXT")
    if ((docker_host_override and docker_host_override != endpoint) or
            (docker_context_override and docker_context_override != context_name)):
        return {**base, "reason": "docker_environment_context_mismatch",
                "context": {"name": context_name, "endpoint": endpoint}}

    context = {"name": context_name, "endpoint": endpoint}
    parsed_endpoint = urlsplit(endpoint)
    socket_path = unquote(parsed_endpoint.path)
    if (parsed_endpoint.scheme != "unix" or parsed_endpoint.netloc or
            parsed_endpoint.query or parsed_endpoint.fragment or not socket_path.startswith("/")):
        return {**base, "reason": "non_unix_docker_context", "context": context}

    state, version_raw = _run(["docker", "version", "--format", "{{.Server.APIVersion}}"], timeout=5)
    if state != "ok":
        return {**base, "reason": f"docker_api_version_{version_raw}", "context": context}
    try:
        version_parts = tuple(int(part) for part in version_raw.strip().split("."))
        if len(version_parts) != 2 or version_parts < (1, 40):
            raise ValueError("unsupported Docker API version")
    except ValueError:
        return {**base, "reason": "invalid_or_unsupported_docker_api_version", "context": context}

    state, info_raw = _run(["docker", "info", "--format", "{{json .}}"], timeout=5)
    if state != "ok":
        return {**base, "reason": f"docker_info_{info_raw}",
                "context": {"name": context_name, "endpoint": endpoint}}
    try:
        info = json.loads(info_raw)
        if not isinstance(info, dict):
            raise ValueError("expected info object")
        name = _docker_text(info.get("Name"), limit=128)
        root_dir = _docker_text(info.get("DockerRootDir"), limit=512)
        driver = _docker_text(info.get("Driver"), limit=128)
        server_version = _docker_text(info.get("ServerVersion"), limit=64)
        if not name or not root_dir or not driver:
            raise ValueError("missing engine identity fields")
        engine = {"name": name, "root_dir": root_dir, "storage_driver": driver}
        if server_version:
            engine["server_version"] = server_version
    except (json.JSONDecodeError, ValueError):
        return {**base, "reason": "invalid_docker_info",
                "context": {"name": context_name, "endpoint": endpoint}}

    http_status, usage_body, usage_error = _docker_unix_get(
        socket_path, f"/v{version_parts[0]}.{version_parts[1]}/system/df?verbose=1"
    )
    if usage_error:
        return {**base, "reason": usage_error, "context": context, "engine": engine}
    if http_status != 200:
        return {**base, "reason": f"docker_api_http_{http_status}",
                "context": context, "engine": engine}
    try:
        usage_data = json.loads(usage_body)
        if not isinstance(usage_data, dict):
            raise ValueError("expected usage object")
        if version_parts >= (1, 52):
            categories: dict[str, Any] = {}
            unknown: list[str] = []
            specifications = {
                "images": ("ImageUsage", _docker_image_item),
                "containers": ("ContainerUsage", _docker_container_item),
                "local_volumes": ("VolumeUsage", _docker_volume_item),
                "build_cache": ("BuildCacheUsage", _docker_build_cache_item),
            }
            for category, (key, parser) in specifications.items():
                parsed = _parse_docker_usage_summary(usage_data.get(key), category=category,
                                                     item_parser=parser)
                if parsed is None:
                    unknown.append(category)
                    raw = usage_data.get(key)
                    rows = raw.get("Items") if isinstance(raw, dict) else None
                    count = len(rows) if isinstance(rows, list) else None
                    categories[category] = {"status": "unknown", "item_count": count,
                                            "items": [], "reason": "missing_or_incomplete_summary"}
                else:
                    categories[category] = parsed
                    if parsed["status"] != "available":
                        unknown.append(category)
        else:
            categories, unknown = _parse_legacy_docker_usage(usage_data)
    except (json.JSONDecodeError, ValueError):
        return {**base, "reason": "invalid_or_incomplete_docker_api_response",
                "context": context, "engine": engine}

    accounting_note = base["accounting_note"]
    if version_parts < (1, 52):
        accounting_note += " Container, volume and build-cache totals are not present in this API version."
    result = {"status": "available" if not unknown else "unknown",
              "source": "Docker Engine API system df", "api_version": f"{version_parts[0]}.{version_parts[1]}",
              "additivity": "non_additive", "accounting_note": accounting_note,
              "context": context, "engine": engine, "categories": categories}
    # Engine usage is authoritative when its build-cache summary is complete.
    # Buildx supplements API versions / responses which cannot provide a full
    # per-object summary; a failed fallback must not erase any partial Engine
    # records that are still useful for the report.
    engine_build_cache = categories.get("build_cache")
    engine_cache_complete = (
        isinstance(engine_build_cache, dict)
        and engine_build_cache.get("status") == "available"
    )
    if engine_cache_complete:
        build_cache = engine_build_cache
    elif context_name == "default":
        local_default, builder_reason = _docker_buildx_default_is_local(context_name)
        if local_default:
            buildx_cache = _docker_buildx_cache(context_name)
        else:
            buildx_cache = {"status": "unknown", "item_count": None, "items": [],
                            "reason": builder_reason, "source": "docker buildx du"}
        if buildx_cache.get("status") == "available":
            build_cache = buildx_cache
        elif isinstance(engine_build_cache, dict):
            build_cache = dict(engine_build_cache)
            build_cache["buildx_fallback_reason"] = buildx_cache.get("reason", "buildx_query_failed")
        else:
            build_cache = buildx_cache
    else:
        if isinstance(engine_build_cache, dict):
            build_cache = engine_build_cache
        else:
            build_cache = {"status": "unknown", "item_count": None, "items": [],
                           "reason": "non_default_context", "source": "docker buildx du"}
    categories["build_cache"] = build_cache
    if build_cache["status"] == "unknown":
        if "build_cache" not in unknown:
            unknown.append("build_cache")
    else:
        unknown = [category for category in unknown if category != "build_cache"]
    result["status"] = "available" if not unknown else "unknown"
    if unknown:
        result["unknown_categories"] = unknown
    else:
        result.pop("unknown_categories", None)
    return result


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
            return _result("unknown", "pm2 jlist", reason="invalid_process_env")
        refs = [env.get("pm_cwd"), env.get("pm_exec_path")]
        if any(ref is not None and not isinstance(ref, str) for ref in refs):
            return _result("unknown", "pm2 jlist", reason="invalid_process_path")
        valid_refs = [ref for ref in refs if isinstance(ref, str)]
        if not valid_refs:
            return _result("unknown", "pm2 jlist", reason="missing_process_paths")
        overlap_results = [_overlaps(target, ref) for ref in valid_refs]
        if any(result is None for result in overlap_results):
            return _result("unknown", "pm2 jlist", reason="invalid_process_path")
        if any(overlap_results):
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


def _within_roots(path: Path, roots: tuple[Path, ...]) -> bool:
    try:
        resolved = path.resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        return False
    for root in roots:
        try:
            if os.path.commonpath((str(resolved), str(root))) == str(root):
                return True
        except ValueError:
            continue
    return False


def _service_config_path(value: str, family: str) -> str | None:
    """Return one literal absolute data/config path, or None if indirect."""
    value = value.strip().rstrip(";").strip()
    if family == "php" and ";" in value:
        # PHP session.save_path permits N;MODE;PATH.
        value = value.split(";", 2)[-1].strip()
    if not value or not value.startswith("/") or any(char in value for char in "$%*?[]"):
        return None
    try:
        return str(Path(value).resolve(strict=False))
    except (OSError, RuntimeError, ValueError):
        return None


def _include_is_complete(value: str, *, is_directory: bool,
                         roots: tuple[Path, ...]) -> bool:
    """Confirm an include is absolute, exists and is inside scanned roots."""
    value = value.strip().rstrip(";").strip()
    if not value or not value.startswith("/") or any(char in value for char in "$%"):
        return False
    if "**" in value:
        return False
    has_glob = any(char in value for char in "*?[]")
    if is_directory:
        if has_glob:
            return False
        target = Path(value)
        return target.is_dir() and _within_roots(target, roots)
    matched = glob.glob(value) if has_glob else [value]
    if not matched:
        return False
    for item in matched:
        target = Path(item)
        if not target.is_file() or not _within_roots(target, roots):
            return False
        if not any(fnmatchcase(target.name, pattern) for pattern in SERVICE_CONFIG_GLOBS):
            return False
    return True


def service_configs(path: str | Path, *, roots: tuple[Path, ...] | None = None,
                    timeout: float = 5.0) -> dict[str, Any]:
    """Inspect known MySQL, PHP and Nginx config paths without executing them.

    The scope is deliberately limited to these standard config roots. Includes
    outside those roots, indirect variables, inaccessible files and incomplete
    scans are unknown. Exact config source paths are retained in local evidence;
    callers must sanitize them before building model context.
    """
    configured_roots = SERVICE_CONFIG_ROOTS if roots is None else roots
    present: list[Path] = []
    present_families: list[str] = []
    scope: list[str] = []
    for root in configured_roots:
        scope.append(root.name)
        try:
            root_stat = root.stat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            return {**_result("unknown", "MySQL/PHP/Nginx config directives",
                              reason=f"config_root_unreadable:{type(exc).__name__}"),
                    "scope": scope, "inspected_sources": []}
        if not stat.S_ISDIR(root_stat.st_mode):
            return {**_result("unknown", "MySQL/PHP/Nginx config directives",
                              reason="config_root_not_directory"),
                    "scope": scope, "inspected_sources": []}
        try:
            resolved = root.resolve(strict=True)
        except (OSError, RuntimeError, ValueError) as exc:
            return {**_result("unknown", "MySQL/PHP/Nginx config directives",
                              reason=f"config_root_unreadable:{type(exc).__name__}"),
                    "scope": scope, "inspected_sources": []}
        present.append(resolved)
        present_families.append(root.name)
    if not present:
        return {**_result("clear", "MySQL/PHP/Nginx config directives",
                          reason="not_applicable:no_supported_config_roots"),
                "scope": scope, "inspected_sources": []}
    inspected_sources: set[str] = set()
    matched_sources: set[str] = set()
    matched_directives: set[str] = set()
    unknown_reason: str | None = None
    target = Path(path).resolve(strict=False)
    deadline = time.monotonic() + max(0.0, timeout)
    entries_seen = 0
    files_seen = 0
    bytes_seen = 0
    visited_directories: set[tuple[int, int]] = set()

    def inspect_config_file(source_path: Path, family: str, read_path: Path) -> None:
        nonlocal files_seen, bytes_seen, unknown_reason
        if unknown_reason:
            return
        files_seen += 1
        if files_seen > MAX_SERVICE_CONFIG_SOURCES:
            unknown_reason = "config_file_limit"
            return
        try:
            before = read_path.stat()
            if before.st_size > MAX_SERVICE_CONFIG_BYTES - bytes_seen:
                unknown_reason = "config_byte_limit"
                return
            with read_path.open("rb") as stream:
                raw = stream.read(MAX_SERVICE_CONFIG_BYTES - bytes_seen + 1)
            after = read_path.stat()
        except OSError as exc:
            unknown_reason = f"config_unreadable:{type(exc).__name__}"
            return
        if len(raw) > MAX_SERVICE_CONFIG_BYTES - bytes_seen:
            unknown_reason = "config_byte_limit"
            return
        if before.st_size != after.st_size or len(raw) != before.st_size:
            unknown_reason = "config_changed_during_read"
            return
        bytes_seen += len(raw)
        try:
            text = raw.decode("utf-8", "strict")
        except UnicodeDecodeError:
            unknown_reason = "config_not_utf8"
            return
        source_value = str(source_path)
        for raw_line in text.splitlines():
            stripped = raw_line.lstrip()
            if not stripped or stripped.startswith((";", "#")):
                continue
            head = stripped.split(None, 1)[0]
            head_key = head.partition("=")[0].lower()
            relevant = (
                family == "mysql" and head_key in {"datadir", "!include", "!includedir"}
                or family == "php" and head_key == "session.save_path"
                or family == "nginx" and head_key in {"root", "alias", "include"}
            )
            if not relevant:
                continue
            try:
                tokens = shlex.split(raw_line, comments=True, posix=True)
            except ValueError:
                unknown_reason = "config_line_malformed"
                return
            if not tokens:
                continue
            first = tokens[0]
            key, separator, inline_value = first.partition("=")
            key_lower = key.lower()
            directive: str | None = None
            is_directory_include = False
            if family == "mysql" and key_lower in {"datadir", "!include", "!includedir"}:
                directive = f"mysql.{key_lower.lstrip('!')}"
                is_directory_include = key_lower == "!includedir"
            elif family == "php" and key_lower == "session.save_path":
                directive = "php.session.save_path"
            elif family == "nginx" and first in {"root", "alias", "include"}:
                directive = f"nginx.{first}"
            if directive is None:
                continue
            inspected_sources.add(source_value)
            value_tokens = ([inline_value] if separator else
                            tokens[2:] if len(tokens) >= 3 and tokens[1] == "=" else
                            tokens[1:])
            if len(value_tokens) != 1:
                unknown_reason = "config_value_ambiguous"
                return
            value = value_tokens[0]
            if directive.endswith("include") or directive.endswith("includedir"):
                if not _include_is_complete(value, is_directory=is_directory_include,
                                            roots=tuple(present)):
                    unknown_reason = "include_incomplete_or_outside_roots"
                    return
                continue
            resolved_value = _service_config_path(value, family)
            if resolved_value is None:
                unknown_reason = "config_path_indirect_or_unsupported"
                return
            overlaps = _overlaps(target, resolved_value)
            if overlaps is None:
                unknown_reason = "config_path_unresolvable"
                return
            if overlaps:
                matched_sources.add(source_value)
                matched_directives.add(directive)

    try:
        for family, root in zip(present_families, present):
            stack = [root]
            while stack and not unknown_reason:
                if time.monotonic() >= deadline:
                    unknown_reason = "config_timeout"
                    break
                directory = stack.pop()
                try:
                    directory_stat = directory.stat()
                    key = (directory_stat.st_dev, directory_stat.st_ino)
                    if key in visited_directories:
                        continue
                    visited_directories.add(key)
                    with os.scandir(directory) as children:
                        for entry in children:
                            if time.monotonic() >= deadline:
                                unknown_reason = "config_timeout"
                                break
                            entries_seen += 1
                            if entries_seen > MAX_SERVICE_CONFIG_ENTRIES:
                                unknown_reason = "config_entry_limit"
                                break
                            source_path = Path(entry.path)
                            try:
                                entry_stat = entry.stat(follow_symlinks=False)
                                read_path = source_path
                                if stat.S_ISLNK(entry_stat.st_mode):
                                    read_path = source_path.resolve(strict=True)
                                    if not _within_roots(read_path, tuple(present)):
                                        unknown_reason = "config_symlink_outside_roots"
                                        break
                                    entry_stat = read_path.stat()
                                if stat.S_ISDIR(entry_stat.st_mode):
                                    stack.append(source_path)
                                elif (stat.S_ISREG(entry_stat.st_mode) and
                                      any(fnmatchcase(source_path.name, pattern)
                                          for pattern in SERVICE_CONFIG_GLOBS)):
                                    inspect_config_file(source_path, family, read_path)
                                    if unknown_reason:
                                        break
                            except OSError as exc:
                                unknown_reason = f"config_unreadable:{type(exc).__name__}"
                                break
                except OSError as exc:
                    unknown_reason = f"config_unreadable:{type(exc).__name__}"
                    break
    except OSError as exc:
        unknown_reason = f"config_unreadable:{type(exc).__name__}"

    evidence = {"scope": scope, "inspected_sources": sorted(inspected_sources),
                "matched_directives": sorted(matched_directives)}
    if unknown_reason:
        return {**_result("unknown", "MySQL/PHP/Nginx config directives", reason=unknown_reason,
                          matches=sorted(matched_sources)), **evidence}
    return {**_result("in_use" if matched_sources else "clear",
                      "MySQL/PHP/Nginx config directives", matches=sorted(matched_sources)),
            **evidence}


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
        "service_configs": lambda: service_configs(path),
    }
    selected = checks if checks is not None else set(available)
    if not selected <= set(available):
        raise ValueError("unknown consumer check requested")
    return {name: available[name]() for name in available if name in selected}
