from __future__ import annotations

import json
import http.server
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from cleanup_agent.runtime import OpenCodeRuntime, RuntimeFailure, RuntimeUnavailable, _ChildRegistry


class OpenCodeRuntimeTests(unittest.TestCase):
    def test_direct_mode_does_not_require_or_resolve_opencode(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            model = Path(temp) / "model.gguf"
            model.write_bytes(b"fixture")
            runtime = OpenCodeRuntime(
                runtime_mode="llama", opencode_bin="/missing/opencode",
                llama_server_bin=sys.executable, model_path=model, runtime_dir=temp,
            )
            self.assertEqual(runtime.runtime_mode, "llama")
            self.assertIsNone(runtime.opencode_bin)
            with self.assertRaisesRegex(ValueError, "runtime_mode"):
                OpenCodeRuntime(runtime_mode="automatic")

    def test_direct_request_sends_schema_to_numeric_local_endpoint(self) -> None:
        captured: list[dict[str, object]] = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                captured.append(json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0")))))
                content = '{"items":[],"inspect_refs":[],"limitations":[]}'
                encoded = json.dumps({"choices": [{"finish_reason": "stop",
                                                    "message": {"content": content}}]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def log_message(self, *_args: object) -> None:
                return

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            runtime = object.__new__(OpenCodeRuntime)
            runtime.runtime_base = Path("/tmp")
            runtime.model_path = Path("/private/model.gguf")
            runtime.request_timeout = 2.0
            runtime.max_prompt_chars = 1000
            schema = {"type": "object", "required": ["items", "inspect_refs", "limitations"]}
            with patch.dict(os.environ, {"HTTPS_PROXY": "http://proxy.invalid", "HTTP_PROXY": "http://proxy.invalid"}):
                text = runtime._direct_request(
                    f"http://127.0.0.1:{server.server_address[1]}/v1", "Return JSON only.", schema
                )
            self.assertEqual(text, '{"items":[],"inspect_refs":[],"limitations":[]}')
            self.assertEqual(len(captured), 1)
            self.assertEqual(captured[0]["response_format"], {
                "type": "json_schema",
                "json_schema": {"name": "cleanup_plan", "strict": True, "schema": schema},
            })
            self.assertEqual(captured[0]["messages"], [{"role": "user", "content": "Return JSON only."}])
            self.assertEqual(captured[0]["max_tokens"], 1024)
            self.assertIs(captured[0]["stream"], False)
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)

    def test_direct_runtime_stops_owned_server_and_removes_registry(self) -> None:
        class FakeDirectRuntime(OpenCodeRuntime):
            def _llama_command(self, port: int) -> list[str]:
                script = '''
import http.server, json, os, sys
port = int(sys.argv[1])
pid_file = sys.argv[2]
open(pid_file, "w").write(str(os.getpid()))
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        payload = json.dumps({"choices": [{"finish_reason": "stop", "message": {"content": "{\\"value\\":1}"}}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
    def log_message(self, *_args):
        pass
http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
'''
                return [sys.executable, "-c", script, str(port), str(self.pid_file)]

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            model = root / "model.gguf"
            model.write_bytes(b"fixture")
            pid_file = root / "server.pid"
            runtime = FakeDirectRuntime(
                runtime_mode="llama", opencode_bin="/missing/opencode",
                llama_server_bin=sys.executable, model_path=model, runtime_dir=root,
                context_size=4096, threads=1, startup_timeout=5, request_timeout=5,
            )
            runtime.pid_file = pid_file
            result = runtime.generate("Return JSON only.", response_schema={"type": "object"})
            self.assertEqual(result, '{"value":1}')
            self.assertTrue(pid_file.exists())
            server_pid = int(pid_file.read_text())
            self.assertFalse(Path(f"/proc/{server_pid}").exists())
            self.assertEqual(list(root.glob("children-*.json")), [])

    def test_direct_mode_fails_explicitly_when_loopback_is_denied(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            model = Path(temp) / "model.gguf"
            model.write_bytes(b"fixture")
            runtime = OpenCodeRuntime(
                runtime_mode="llama", opencode_bin="/missing/opencode",
                llama_server_bin=sys.executable, model_path=model, runtime_dir=temp,
            )
            with patch.object(OpenCodeRuntime, "_free_loopback_port",
                              side_effect=RuntimeUnavailable("loopback denied")):
                with self.assertRaisesRegex(RuntimeUnavailable, "loopback denied"):
                    runtime.generate("Return exact JSON.", response_schema={"type": "object"})
            self.assertEqual(list(Path(temp).glob("children-*.json")), [])

    def test_direct_mode_rejects_length_finish_without_retry(self) -> None:
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
                encoded = json.dumps({"choices": [{"finish_reason": "length",
                                                    "message": {"content": "{}"}}]}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def log_message(self, *_args: object) -> None:
                return

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            runtime = object.__new__(OpenCodeRuntime)
            runtime.runtime_base = Path("/tmp")
            runtime.model_path = Path("/private/model.gguf")
            runtime.request_timeout = 2.0
            runtime.max_prompt_chars = 1000
            with self.assertRaisesRegex(RuntimeError, "output limit"):
                runtime._direct_request(
                    f"http://127.0.0.1:{server.server_address[1]}/v1", "Return JSON.", None
                )
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)

    def test_extracts_only_json_text_events(self) -> None:
        output = "\n".join([
            json.dumps({"type": "step_start", "part": {"type": "step-start"}}),
            json.dumps({"type": "text", "part": {"type": "text", "text": '{"ok":'}}),
            "not-json",
            json.dumps({"type": "text", "part": {"type": "text", "text": "true}"}}),
            json.dumps({"type": "step_finish", "part": {
                "type": "step-finish", "reason": "stop",
                "tokens": {"input": 20, "output": 2},
            }}),
            json.dumps({"type": "tool", "part": {"text": "must not be used"}}),
        ])
        self.assertEqual(OpenCodeRuntime._extract_text(output), '{"ok":true}')

    def test_step_finish_length_rejects_truncated_text_without_echoing_payload(self) -> None:
        truncated_text = '{"items":{"candidate": {"reason":"private /srv/data/secret.db'
        finish_events = [
            # OpenCode event variants may put the provider finish reason on
            # the event, the part, or expose it as the step part's reason.
            {"type": "step_finish", "finish_reason": "length",
             "part": {"type": "step-finish", "tokens": {"input": 3909, "output": 187}}},
            {"type": "step_finish", "part": {"type": "step-finish",
             "finish_reason": "length", "tokens": {"input": 3909, "output": 187}}},
            {"type": "step_finish", "part": {"type": "step-finish",
             "reason": "length", "tokens": {"input": 3909, "output": 187}}},
        ]
        for finish_event in finish_events:
            with self.subTest(finish_event=finish_event):
                events = "\n".join([
                    json.dumps({"type": "text", "part": {"type": "text", "text": truncated_text}}),
                    json.dumps(finish_event),
                ])
                with self.assertRaisesRegex(RuntimeFailure, "truncated at the output limit") as raised:
                    OpenCodeRuntime._extract_text(events)
                self.assertNotIn("/srv/data/secret.db", str(raised.exception))
                self.assertNotIn(truncated_text, str(raised.exception))

    def test_event_summary_and_opt_in_diagnostic_are_bounded_private_and_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            runtime = object.__new__(OpenCodeRuntime)
            runtime.runtime_base = root
            runtime.opencode_bin = "/bundle/opencode"
            runtime.llama_server_bin = "/bundle/llama-server"
            runtime.model_path = Path("/models/private.gguf")
            events = '\n'.join([
                json.dumps({"type": "step_start", "part": {"type": "step-start"}}),
                json.dumps({"type": "tool", "part": {"type": "tool"}}),
                "not-json",
            ])
            self.assertEqual(OpenCodeRuntime._event_summary(events), {
                "step_start": 1, "part:step-start": 1, "tool": 1, "part:tool": 1,
                "non_json_lines": 1,
            })
            self.assertIsNone(runtime._write_diagnostic_dump(events, "", work_root=root, enabled=False))
            stdout = ("x" * 9000) + "/models/private.gguf Bearer abc123 api_key=secret-value"
            path = runtime._write_diagnostic_dump(stdout, "", work_root=root, enabled=True)
            assert path is not None
            target = Path(path)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            payload = json.loads(target.read_text())
            self.assertLessEqual(len(payload["stdout_tail"]), 8192)
            self.assertNotIn("/models/private.gguf", payload["stdout_tail"])
            self.assertNotIn("abc123", payload["stdout_tail"])
            self.assertNotIn("secret-value", payload["stdout_tail"])

    def test_local_opencode_config_denies_tools_and_permissions(self) -> None:
        config = OpenCodeRuntime._opencode_config("http://127.0.0.1:18123/v1", 4096)
        self.assertEqual(config["permission"], {"*": "deny"})
        self.assertEqual(config["tools"], {"*": False})
        self.assertEqual(config["agent"]["cleanup_planner"]["permission"], {"*": "deny"})
        self.assertEqual(config["agent"]["cleanup_planner"]["steps"], 2)
        self.assertEqual(config["compaction"], {"auto": False})
        self.assertEqual(config["provider"]["local"]["options"]["baseURL"], "http://127.0.0.1:18123/v1")
        self.assertEqual(config["provider"]["local"]["options"]["chunkTimeout"], 110_000)
        bounded = OpenCodeRuntime._opencode_config("http://127.0.0.1:18123/v1", 4096, 9.0)
        self.assertEqual(bounded["provider"]["local"]["options"]["timeout"], 9_000)
        self.assertEqual(bounded["provider"]["local"]["options"]["chunkTimeout"], 9_000)
        self.assertEqual(bounded["provider"]["local"]["models"]["cleanup-model"]["limit"]["output"], 1024)
        long_request = OpenCodeRuntime._opencode_config("http://127.0.0.1:18123/v1", 4096, 500.0)
        self.assertEqual(long_request["provider"]["local"]["options"]["timeout"], 180_000)
        self.assertEqual(long_request["provider"]["local"]["options"]["chunkTimeout"], 180_000)
        schema = {"type": "object", "required": ["action"]}
        constrained = OpenCodeRuntime._opencode_config(
            "http://127.0.0.1:18123/v1", 4096, 9.0, response_schema=schema
        )
        self.assertEqual(
            constrained["provider"]["local"]["models"]["cleanup-model"]["options"]["response_format"],
            {"type": "json_schema", "json_schema": {
                "name": "cleanup_plan", "strict": True, "schema": schema,
            }},
        )

    def test_pinned_opencode_sends_response_schema_to_local_endpoint(self) -> None:
        opencode = shutil.which("opencode")
        if opencode is None:
            self.skipTest("OpenCode is not installed in this test environment")
        version = subprocess.run([opencode, "--version"], capture_output=True, text=True,
                                 timeout=5, check=False)
        if "1.14.21" not in version.stdout:
            self.skipTest("integration probe requires pinned OpenCode 1.14.21")

        captured: list[tuple[str, dict[str, object]]] = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                payload = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
                captured.append((self.path, payload))
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                content = '{"inspect_refs":[],"items":[],"limitations":[]}'
                events = [
                    {"id": "probe", "object": "chat.completion.chunk", "created": 1,
                     "model": "cleanup-model", "choices": [{"index": 0,
                     "delta": {"role": "assistant", "content": content}, "finish_reason": None}]},
                    {"id": "probe", "object": "chat.completion.chunk", "created": 1,
                     "model": "cleanup-model", "choices": [{"index": 0,
                     "delta": {}, "finish_reason": "stop"}]},
                ]
                for event in events:
                    self.wfile.write(("data: " + json.dumps(event) + "\n\n").encode())
                    self.wfile.flush()
                self.wfile.write(b"data: [DONE]\n\n")
                self.wfile.flush()

            def log_message(self, *_args: object) -> None:
                return

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            with tempfile.TemporaryDirectory(prefix="opencode-schema-probe-") as temp:
                root = Path(temp)
                dirs = {name: root / name for name in ("config", "cache", "state", "data", "home", "work")}
                for directory in dirs.values():
                    directory.mkdir(mode=0o700)
                schema = {
                    "type": "object", "additionalProperties": False,
                    "properties": {"inspect_refs": {"type": "array", "maxItems": 0}},
                    "required": ["inspect_refs"],
                }
                config = OpenCodeRuntime._opencode_config(
                    f"http://127.0.0.1:{server.server_address[1]}/v1", 4096, 20,
                    response_schema=schema,
                )
                env = OpenCodeRuntime._opencode_environment(
                    config=config, config_home=dirs["config"], cache_home=dirs["cache"],
                    state_home=dirs["state"], data_home=dirs["data"], home=dirs["home"],
                )
                result = subprocess.run(
                    [opencode, "run", "--pure", "--format", "json", "--model", "local/cleanup-model",
                     "--agent", "cleanup_planner", "--dir", str(dirs["work"]), "Return JSON only."],
                    cwd=dirs["work"], env=env, capture_output=True, text=True,
                    timeout=30, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr[-1000:])
                self.assertGreaterEqual(len(captured), 1, result.stdout[-1000:])
                for path, body in captured:
                    self.assertEqual(path, "/v1/chat/completions")
                    self.assertEqual(body.get("response_format"), {
                        "type": "json_schema",
                        "json_schema": {"name": "cleanup_plan", "strict": True, "schema": schema},
                    })
                    self.assertNotIn("extraBody", body)
                    self.assertIs(body.get("stream"), True)
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)

    def test_llama_server_command_disables_qwen_reasoning(self) -> None:
        runtime = object.__new__(OpenCodeRuntime)
        runtime.llama_server_bin = "/bundle/llama-server"
        runtime.model_path = Path("/models/model.gguf")
        runtime.context_size = 4096
        runtime.threads = 2
        command = runtime._llama_command(12345)
        self.assertEqual(command[command.index("--reasoning") + 1], "off")
        self.assertEqual(command[command.index("--threads") + 1], "2")

    def test_opencode_error_event_is_preserved_without_echoing_paths(self) -> None:
        event = json.dumps({
            "type": "error",
            "error": {"name": "UnknownError", "data": {"message": "SSE read timed out at /private/path"}},
        })
        self.assertEqual(
            OpenCodeRuntime._first_error_event(event),
            ("UnknownError", "SSE read timed out at /private/path"),
        )

    def test_rejects_context_that_triggered_compaction_loop(self) -> None:
        with self.assertRaisesRegex(ValueError, "at least 4096"):
            OpenCodeRuntime(context_size=2048)

    def test_minimal_child_environment_does_not_inherit_credentials_or_proxy(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with patch.dict(os.environ, {
                "PATH": "/usr/bin", "LD_LIBRARY_PATH": "/bundle/lib",
                "GITHUB_TOKEN": "secret", "HTTPS_PROXY": "http://proxy.invalid",
                "OPENAI_API_KEY": "secret2",
            }, clear=True):
                env = OpenCodeRuntime._minimal_child_environment(root)
        self.assertEqual(env["PATH"], "/usr/bin")
        self.assertEqual(env["LD_LIBRARY_PATH"], "/bundle/lib")
        self.assertNotIn("GITHUB_TOKEN", env)
        self.assertNotIn("HTTPS_PROXY", env)
        self.assertNotIn("OPENAI_API_KEY", env)

    def test_socketless_transport_is_explicitly_rejected(self) -> None:
        with patch.dict(os.environ, {"CLEANUP_AGENT_TRANSPORT": "stdio"}):
            with self.assertRaisesRegex(RuntimeUnavailable, "not yet supported"):
                OpenCodeRuntime()

    def test_stop_process_group_removes_child_processes(self) -> None:
        child_code = "import subprocess,sys,time; p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); print(p.pid, flush=True); time.sleep(30)"
        process = subprocess.Popen(
            [sys.executable, "-c", child_code], stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, start_new_session=True,
        )
        assert process.stdout is not None
        try:
            process.stdout.readline()
        finally:
            process.stdout.close()
        with tempfile.TemporaryDirectory() as temp:
            registry = _ChildRegistry(Path(temp) / "children.json")
            registry.register(process, str(Path(sys.executable).resolve()))
            self.assertEqual(registry.path.stat().st_mode & 0o777, 0o600)
            record = json.loads(registry.path.read_text())["children"][0]
            self.assertEqual(record["pid"], process.pid)
            self.assertEqual(record["pgid"], process.pid)
            self.assertIn("start_ticks", record)
            self.assertTrue(OpenCodeRuntime._stop_and_forget(process, registry))
            self.assertEqual(registry.entries, {})
            registry.remove_file()
        self.assertIsNotNone(process.poll())
        self.assertIs(OpenCodeRuntime._group_has_live_members(process.pid), False)

    def test_stop_reaped_leader_still_kills_live_descendant(self) -> None:
        child_code = "import subprocess,sys,time; p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); print(p.pid, flush=True); time.sleep(30)"
        process = subprocess.Popen(
            [sys.executable, "-c", child_code], stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, start_new_session=True,
        )
        assert process.stdout is not None
        child_pid = int(process.stdout.readline().strip())
        process.stdout.close()
        with tempfile.TemporaryDirectory() as temp:
            registry = _ChildRegistry(Path(temp) / "children.json")
            registry.register(process, str(Path(sys.executable).resolve()))
            process.terminate()
            process.wait(timeout=2)
            self.assertTrue(OpenCodeRuntime._group_has_live_members(process.pid))
            self.assertTrue(OpenCodeRuntime._stop_and_forget(process, registry))
            self.assertEqual(registry.entries, {})
            registry.remove_file()
        self.assertIs(OpenCodeRuntime._group_has_live_members(process.pid), False)
        try:
            state = (Path(f"/proc/{child_pid}/stat").read_text().rsplit(")", 1)[1].split()[0])
        except FileNotFoundError:
            state = None
        self.assertIn(state, (None, "Z", "X"), "descendant must be gone or only an unreaped zombie")


if __name__ == "__main__":
    unittest.main()
