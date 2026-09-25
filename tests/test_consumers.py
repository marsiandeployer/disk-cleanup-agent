import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from cleanup_agent import consumers


class ConsumerChecksTest(unittest.TestCase):
    @staticmethod
    def _docker_storage_fixture(api_version="1.52", endpoint="unix:///var/run/docker.sock",
                                build_cache=True):
        context_inspect = json.dumps({"Host": endpoint})
        docker_info = json.dumps({
            "Name": "fixture-engine", "DockerRootDir": "/var/lib/docker",
            "Driver": "overlay2", "ServerVersion": "29.1.3",
        })
        image_a = {"Id": "sha256:image-a", "RepoTags": ["app-a:latest"],
                   "Size": 50, "SharedSize": 20}
        image_b = {"Id": "sha256:image-b", "RepoTags": ["app-b:latest"],
                   "Size": 50, "SharedSize": 20}
        container = {"Id": "container-a", "Names": ["/app-a-1"],
                     "Image": "app-a:latest", "State": "running", "SizeRw": 3}
        volume = {"Name": "db-data", "Driver": "local", "Scope": "local",
                  "UsageData": {"Size": 20, "RefCount": 1}}
        build = {"ID": "cache-a", "Type": "regular", "Size": 1024,
                 "Shared": True, "Reclaimable": False, "Mutable": False}
        if api_version >= "1.52":
            data = {
                "ImageUsage": {"TotalCount": 2, "ActiveCount": 1,
                               "TotalSize": 80, "Items": [image_a, image_b]},
                "ContainerUsage": {"TotalCount": 1, "ActiveCount": 1,
                                   "TotalSize": 3, "Items": [container]},
                "VolumeUsage": {"TotalCount": 1, "ActiveCount": 1,
                                "TotalSize": 20, "Reclaimable": 0, "Items": [volume]},
                "BuildCacheUsage": {"TotalCount": 1, "ActiveCount": 0,
                                    "TotalSize": 1024, "Items": [build]}
                if build_cache else {},
            }
        else:
            data = {"LayersSize": 80, "Images": [image_a, image_b],
                    "Containers": [container], "Volumes": [volume],
                    "BuildCache": [build] if build_cache else []}
        return context_inspect, docker_info, json.dumps(data).encode()

    def _docker_storage_run_values(self, context_inspect, docker_info, api_version="1.52"):
        buildx_ls = "default\tdefault\tdocker\t\ndefault\tdefault\tdefault\trunning\n"
        buildx = json.dumps({"ID": "buildx-cache-a", "Type": "regular", "Size": "1024",
                             "Shared": False, "Reclaimable": True, "Mutable": False}) + "\n"
        return [("ok", "default\n"), ("ok", context_inspect), ("ok", api_version),
                ("ok", docker_info), ("ok", buildx_ls), ("ok", buildx)]

    def test_bounded_runner_caps_combined_stdout_and_stderr_during_read(self):
        code = "import os; os.write(1, b'o' * 600); os.write(2, b'e' * 600)"
        with patch.object(consumers, "MAX_OUTPUT", 1024):
            state, detail = consumers._run_bounded([sys.executable, "-c", code], timeout=2)
        self.assertEqual((state, detail), ("unknown", "output_limit"))

    def test_bounded_runner_kills_timed_out_process(self):
        started = time.monotonic()
        state, detail = consumers._run_bounded(
            [sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.1
        )
        elapsed = time.monotonic() - started
        self.assertEqual((state, detail), ("unknown", "timeout"))
        self.assertLess(elapsed, 2)

    def test_docker_unix_get_reads_normal_response(self):
        with tempfile.TemporaryDirectory() as directory:
            socket_path = str(Path(directory) / "engine.sock")
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(socket_path)
            listener.listen(1)

            def serve():
                connection, _ = listener.accept()
                with connection:
                    connection.recv(4096)
                    body = b'{"Images":[]}'
                    connection.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode()
                        + b"\r\nConnection: close\r\n\r\n" + body
                    )
                listener.close()

            thread = threading.Thread(target=serve)
            thread.start()
            try:
                result = consumers._docker_unix_get(socket_path, "/v1.52/system/df?verbose=1")
            finally:
                thread.join(timeout=1)
                listener.close()
            self.assertFalse(thread.is_alive())
            self.assertEqual(result, (200, b'{"Images":[]}', None))

    def test_docker_unix_get_enforces_absolute_deadline_while_body_trickles(self):
        with tempfile.TemporaryDirectory() as directory:
            socket_path = str(Path(directory) / "engine.sock")
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(socket_path)
            listener.listen(1)

            def serve():
                connection, _ = listener.accept()
                with connection:
                    connection.recv(4096)
                    connection.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n"
                        b"Connection: close\r\n\r\n"
                    )
                    for byte in b"abcdefghijklmnopqrst":
                        time.sleep(0.03)
                        try:
                            connection.sendall(bytes([byte]))
                        except OSError:
                            break
                listener.close()

            thread = threading.Thread(target=serve)
            thread.start()
            started = time.monotonic()
            try:
                result = consumers._docker_unix_get(
                    socket_path, "/v1.52/system/df?verbose=1", timeout=0.1
                )
                elapsed = time.monotonic() - started
            finally:
                thread.join(timeout=1)
                listener.close()
            self.assertFalse(thread.is_alive())
            self.assertEqual(result, (None, b"", "TimeoutError"))
            self.assertGreaterEqual(elapsed, 0.07)
            self.assertLess(elapsed, 0.5)

    def test_docker_mount_under_candidate_blocks(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "volume"
            candidate.mkdir()
            mounts = [{"Name": "/db", "Mounts": [{"Source": str(candidate / "data")}] }]
            with patch.object(consumers, "_run", side_effect=[
                ("ok", "container-id\n"), ("ok", json.dumps(mounts)),
            ]):
                result = consumers.docker_mounts(candidate)
            self.assertEqual(result["status"], "in_use")
            self.assertEqual(result["matches"], ["/db"])

    def test_docker_unavailable_is_unknown(self):
        with patch.object(consumers, "_run", return_value=("unknown", "command_missing")):
            result = consumers.docker_mounts("/tmp/candidate")
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["reason"], "command_missing")

    def test_docker_missing_mount_inventory_is_unknown(self):
        with patch.object(consumers, "_run", side_effect=[
            ("ok", "container-id\n"), ("ok", json.dumps([{"Name": "/db"}]))
        ]):
            result = consumers.docker_mounts("/tmp/candidate")
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["reason"], "invalid_mount_list")

    def test_docker_invalid_mount_source_is_unknown_but_tmpfs_is_ignored(self):
        with patch.object(consumers, "_run", side_effect=[
            ("ok", "container-id\n"),
            ("ok", json.dumps([{"Name": "/db", "Mounts": [{"Type": "bind", "Source": "relative/path"}]}])),
        ]):
            invalid = consumers.docker_mounts("/tmp/candidate")
        self.assertEqual(invalid["status"], "unknown")
        self.assertEqual(invalid["reason"], "invalid_mount_source")

        with patch.object(consumers, "_run", side_effect=[
            ("ok", "container-id\n"),
            ("ok", json.dumps([{"Name": "/db", "Mounts": [{"Type": "tmpfs", "Source": ""}]}])),
        ]):
            tmpfs = consumers.docker_mounts("/tmp/candidate")
        self.assertEqual(tmpfs["status"], "clear")

    def test_docker_storage_separates_non_additive_categories_and_layers(self):
        context_inspect, docker_info, body = self._docker_storage_fixture()
        run_values = self._docker_storage_run_values(context_inspect, docker_info)
        with patch.object(consumers, "_run", side_effect=run_values[:4]) as run, \
             patch.object(consumers, "_run_bounded", return_value=("unknown", "command_missing")) as buildx, \
             patch.object(consumers, "_docker_unix_get",
                          return_value=(200, body, None)) as api_get:
            result = consumers.docker_storage()

        self.assertEqual(result["status"], "available")
        self.assertEqual(result["additivity"], "non_additive")
        self.assertIn("never combined into a grand total", result["accounting_note"])
        self.assertEqual(result["engine"]["root_dir"], "/var/lib/docker")
        self.assertEqual(result["engine"]["storage_driver"], "overlay2")
        self.assertEqual(result["categories"]["images"]["engine_reported_size_bytes"], 80)
        images = result["categories"]["images"]["items"]
        self.assertEqual(images[0]["shared_size_bytes"], 20)
        self.assertEqual(images[0]["unique_size_bytes"], 30)
        self.assertEqual(
            result["categories"]["containers"]["items"][0]["writable_layer_size_bytes"], 3
        )
        self.assertEqual(result["categories"]["local_volumes"]["item_count"], 1)
        self.assertEqual(result["categories"]["build_cache"]["items"][0]["id"], "cache-a")
        self.assertFalse(any(key in result for key in ("total", "total_bytes", "total_gb")))
        self.assertEqual(run.call_count, 4)
        # A complete Engine summary wins even when Buildx is unavailable.
        buildx.assert_not_called()
        api_get.assert_called_once_with("/var/run/docker.sock", "/v1.52/system/df?verbose=1")

    def test_docker_storage_supports_legacy_v140_response(self):
        context_inspect, docker_info, body = self._docker_storage_fixture(api_version="1.40")
        run_values = self._docker_storage_run_values(context_inspect, docker_info, api_version="1.40")
        with patch.object(consumers, "_run", side_effect=run_values[:4]), \
             patch.object(consumers, "_run_bounded") as buildx, \
             patch.object(consumers, "_docker_unix_get",
                          return_value=(200, body, None)) as api_get:
            result = consumers.docker_storage()

        self.assertEqual(result["status"], "available")
        self.assertEqual(result["api_version"], "1.40")
        self.assertEqual(result["categories"]["images"]["engine_reported_size_bytes"], 80)
        self.assertEqual(result["categories"]["containers"]["items"][0]["writable_layer_size_bytes"], 3)
        self.assertNotIn("engine_reported_size_bytes", result["categories"]["containers"])
        self.assertEqual(result["categories"]["build_cache"]["items"][0]["id"], "cache-a")
        buildx.assert_not_called()
        api_get.assert_called_once_with("/var/run/docker.sock", "/v1.40/system/df?verbose=1")

    def test_docker_buildx_failure_preserves_partial_engine_cache_as_unknown(self):
        context_inspect, docker_info, body = self._docker_storage_fixture()
        usage = json.loads(body)
        usage["BuildCacheUsage"]["TotalCount"] = 2
        usage["BuildCacheUsage"]["Items"].append({
            "ID": "incomplete-cache", "Type": "regular", "Size": "invalid",
            "Shared": False, "Reclaimable": True, "Mutable": False,
        })
        run_values = self._docker_storage_run_values(context_inspect, docker_info)
        run_values[-1] = ("unknown", "command_missing")
        with patch.object(consumers, "_run", side_effect=run_values[:4]), \
             patch.object(consumers, "_run_bounded", side_effect=run_values[4:]) as buildx, \
             patch.object(consumers, "_docker_unix_get",
                          return_value=(200, json.dumps(usage).encode(), None)):
            result = consumers.docker_storage()

        cache = result["categories"]["build_cache"]
        self.assertEqual(result["status"], "unknown")
        self.assertIn("build_cache", result["unknown_categories"])
        self.assertEqual(cache["status"], "unknown")
        self.assertEqual([item["id"] for item in cache["items"]], ["cache-a"])
        self.assertEqual(cache["incomplete_item_count"], 1)
        self.assertEqual(cache["buildx_fallback_reason"], "command_missing")
        self.assertEqual(buildx.call_count, 2)

    def test_docker_storage_daemon_failure_or_incomplete_detail_is_unknown(self):
        with patch.object(consumers, "_run", side_effect=[
            ("ok", "default\n"), ("ok", json.dumps({"Host": "tcp://engine:2376"})),
        ]):
            unavailable = consumers.docker_storage()
        self.assertEqual(unavailable["status"], "unknown")
        self.assertEqual(unavailable["reason"], "non_unix_docker_context")
        self.assertEqual(unavailable["context"]["endpoint"], "tcp://engine:2376")

        context_inspect, docker_info, body = self._docker_storage_fixture()
        malformed = json.loads(body)
        malformed["ImageUsage"]["Items"].pop()
        run_values = self._docker_storage_run_values(context_inspect, docker_info)
        with patch.object(consumers, "_run", side_effect=run_values[:4]), patch.object(consumers, "_docker_unix_get",
                         return_value=(200, json.dumps(malformed).encode(), None)):
            incomplete = consumers.docker_storage()
        self.assertEqual(incomplete["status"], "unknown")
        self.assertIn("images", incomplete["unknown_categories"])

    def test_docker_storage_timeout_and_malformed_context_fail_closed(self):
        with patch.object(consumers, "_run", return_value=("unknown", "timeout")):
            timeout = consumers.docker_storage()
        self.assertEqual(timeout["status"], "unknown")
        self.assertEqual(timeout["reason"], "context_timeout")

        with patch.object(consumers, "_run", side_effect=[("ok", "default\n"), ("ok", "not json")]):
            malformed = consumers.docker_storage()
        self.assertEqual(malformed["status"], "unknown")
        self.assertEqual(malformed["reason"], "invalid_context_endpoint")

    def test_docker_storage_api_http_or_transport_failure_is_unknown(self):
        context_inspect, docker_info, _body = self._docker_storage_fixture()
        run_values = self._docker_storage_run_values(context_inspect, docker_info)
        with patch.object(consumers, "_run", side_effect=run_values[:4]), patch.object(
            consumers, "_docker_unix_get", return_value=(400, b"", None)
        ):
            http_error = consumers.docker_storage()
        self.assertEqual(http_error["status"], "unknown")
        self.assertEqual(http_error["reason"], "docker_api_http_400")

        with patch.object(consumers, "_run", side_effect=run_values[:4]), patch.object(
            consumers, "_docker_unix_get", return_value=(None, b"", "TimeoutError")
        ):
            timeout = consumers.docker_storage()
        self.assertEqual(timeout["status"], "unknown")
        self.assertEqual(timeout["reason"], "TimeoutError")

    def test_docker_storage_environment_endpoint_override_is_unknown(self):
        context_inspect, docker_info, _body = self._docker_storage_fixture()
        with patch.dict(os.environ, {"DOCKER_HOST": "tcp://remote:2376"}), patch.object(
            consumers, "_run", side_effect=self._docker_storage_run_values(context_inspect, docker_info)[:4]
        ), patch.object(consumers, "_docker_unix_get") as api_get:
            result = consumers.docker_storage()
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["reason"], "docker_environment_context_mismatch")
        api_get.assert_not_called()

    def test_docker_storage_row_limit_is_unknown(self):
        context_inspect, docker_info, body = self._docker_storage_fixture()
        usage = json.loads(body)
        usage["ImageUsage"]["Items"] *= 2
        usage["ImageUsage"]["TotalCount"] = len(usage["ImageUsage"]["Items"])
        with patch.object(consumers, "MAX_DOCKER_USAGE_ROWS", 1), patch.object(
            consumers, "_run", side_effect=self._docker_storage_run_values(context_inspect, docker_info)[:4]
        ), patch.object(consumers, "_docker_unix_get",
                        return_value=(200, json.dumps(usage).encode(), None)):
            result = consumers.docker_storage()
        self.assertEqual(result["status"], "unknown")
        self.assertIn("images", result["unknown_categories"])

    def test_docker_storage_empty_successful_buildx_output_is_an_empty_cache(self):
        context_inspect, docker_info, body = self._docker_storage_fixture(build_cache=False)
        run_values = self._docker_storage_run_values(context_inspect, docker_info)
        run_values[-1] = ("ok", "")
        with patch.object(consumers, "_run", side_effect=run_values[:4]), \
             patch.object(consumers, "_run_bounded", side_effect=run_values[4:]) as buildx, \
             patch.object(consumers, "_docker_unix_get", return_value=(200, body, None)):
            result = consumers.docker_storage()
        self.assertEqual(result["categories"]["build_cache"]["status"], "available")
        self.assertEqual(result["categories"]["build_cache"]["item_count"], 0)
        self.assertEqual(result["categories"]["build_cache"]["items"], [])
        self.assertNotIn("engine_reported_size_bytes", result["categories"]["build_cache"])
        self.assertEqual(buildx.call_count, 2)

    def test_docker_buildx_cache_marks_missing_cli_unknown(self):
        with patch.object(consumers, "_run_bounded", return_value=("unknown", "command_missing")) as run:
            result = consumers._docker_buildx_cache("default")
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["reason"], "command_missing")
        run.assert_called_once_with(
            ["docker", "buildx", "du", "--format=json", "--timeout=5s", "--builder", "default"],
            timeout=consumers.DOCKER_BUILDX_TIMEOUT,
        )

    def test_docker_buildx_default_requires_one_local_default_docker_node(self):
        local_rows = "default\tdefault\tdocker\t\ndefault\tdefault\tdefault\trunning\n"
        with patch.object(consumers, "_run_bounded", return_value=("ok", local_rows)) as run:
            self.assertEqual(consumers._docker_buildx_default_is_local("default"), (True, None))
        self.assertEqual(run.call_count, 1)
        remote_rows = "default\tdefault\tdocker\t\ndefault\tdefault\tssh://host\trunning\n"
        with patch.object(consumers, "_run_bounded", return_value=("ok", remote_rows)):
            local, reason = consumers._docker_buildx_default_is_local("default")
        self.assertFalse(local)
        self.assertEqual(reason, "builder_not_local_default")
        duplicated = local_rows + "default\tdefault\tdefault\trunning\n"
        with patch.object(consumers, "_run_bounded", return_value=("ok", duplicated)):
            local, reason = consumers._docker_buildx_default_is_local("default")
        self.assertFalse(local)
        self.assertEqual(reason, "ambiguous_builder_inventory")

    def test_docker_buildx_cache_requires_reclaimable_unshared_immutable_records(self):
        rows = [
            {"ID": "private", "Type": "regular", "Size": "4096", "Shared": False,
             "Reclaimable": True, "Mutable": False},
            {"ID": "shared", "Type": "regular", "Size": "2048", "Shared": True,
             "Reclaimable": True, "Mutable": False},
            {"ID": "mutable", "Type": "regular", "Size": "1024", "Shared": False,
             "Reclaimable": True, "Mutable": True},
        ]
        output = "\n".join(json.dumps(row) for row in rows) + "\n"
        with patch.object(consumers, "_run_bounded", return_value=("ok", output)):
            result = consumers._docker_buildx_cache("default")
        self.assertEqual(result["status"], "available")
        self.assertEqual(len(result["items"]), 3)
        self.assertEqual(result["items"][0]["mutable"], False)
        self.assertEqual(result["items"][1]["shared"], True)
        self.assertEqual(result["items"][2]["mutable"], True)

    def test_docker_buildx_cache_malformed_output_timeout_and_limit_stay_unknown(self):
        for outcome, expected_reason in [
            (("ok", "{bad json}\n"), "invalid_buildx_cache_response"),
            (("unknown", "timeout"), "timeout"),
            (("unknown", "output_limit"), "output_limit"),
        ]:
            with self.subTest(expected_reason=expected_reason), patch.object(
                consumers, "_run_bounded", return_value=outcome
            ):
                result = consumers._docker_buildx_cache("default")
            self.assertEqual(result["status"], "unknown")
            self.assertEqual(result["reason"], expected_reason)
            self.assertEqual(result["items"], [])

    def test_docker_storage_preserves_partial_container_rows_but_marks_category_unknown(self):
        context_inspect, docker_info, body = self._docker_storage_fixture()
        usage = json.loads(body)
        usage["ContainerUsage"]["Items"].append({
            "Id": "container-without-size", "Names": ["/partial"],
            "Image": "app:latest", "State": "created",
        })
        usage["ContainerUsage"]["TotalCount"] = 2
        with patch.object(consumers, "_run", side_effect=self._docker_storage_run_values(
            context_inspect, docker_info
        )), patch.object(consumers, "_docker_unix_get",
                         return_value=(200, json.dumps(usage).encode(), None)):
            result = consumers.docker_storage()
        self.assertEqual(result["status"], "unknown")
        self.assertIn("containers", result["unknown_categories"])
        self.assertEqual(result["categories"]["containers"]["status"], "unknown")
        self.assertEqual(result["categories"]["containers"]["incomplete_item_count"], 1)
        self.assertEqual(len(result["categories"]["containers"]["items"]), 1)

    def test_pm2_cwd_under_candidate_blocks_without_exposing_env(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "project"
            candidate.mkdir()
            processes = [{"name": "web", "pm2_env": {
                "pm_cwd": str(candidate / "app"), "API_TOKEN": "private-value",
            }}]
            with socket.socket(socket.AF_UNIX) as sock:
                sock.bind(str(Path(directory) / "rpc.sock"))
                with patch.dict(os.environ, {"PM2_HOME": directory}):
                    with patch.object(consumers, "_pm2_daemon_verified", return_value=True):
                        with patch.object(consumers, "_run", return_value=("ok", json.dumps(processes))):
                            result = consumers.pm2_processes(candidate)
            self.assertEqual(result["status"], "in_use")
            self.assertNotIn("private-value", json.dumps(result))

    def test_pm2_missing_daemon_does_not_run_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {"PM2_HOME": directory}):
                with patch.object(consumers, "_run") as run:
                    result = consumers.pm2_processes(directory)
            self.assertEqual(result["status"], "unknown")
            run.assert_not_called()

    def test_pm2_invalid_path_reference_is_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            with socket.socket(socket.AF_UNIX) as sock:
                sock.bind(str(Path(directory) / "rpc.sock"))
                with patch.dict(os.environ, {"PM2_HOME": directory}):
                    with patch.object(consumers, "_pm2_daemon_verified", return_value=True):
                        with patch.object(consumers, "_run", return_value=("ok", json.dumps([
                            {"name": "web", "pm2_env": {"pm_cwd": "relative/path"}}
                        ]))):
                            result = consumers.pm2_processes("/tmp/candidate")
            self.assertEqual(result["status"], "unknown")
            self.assertEqual(result["reason"], "invalid_process_path")

    def test_code_roots_required_for_literal_search(self):
        result = consumers.literal_code_refs("/tmp/candidate")
        self.assertEqual(result["status"], "unknown")

    def test_service_config_data_roots_block_mysql_php_and_nginx_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cases = [
                ("mysql", "my.cnf", "[mysqld]\ndatadir = /var/lib/mysql\n",
                 "/var/lib/mysql/ibdata1", "mysql.datadir"),
                ("php", "php.ini", 'session.save_path = "2;0600;/var/lib/php/sessions"\n',
                 "/var/lib/php/sessions/sess_demo", "php.session.save_path"),
                ("nginx", "nginx.conf", "server {\n root /srv/site;\n}\n",
                 "/srv/site/media/a.jpg", "nginx.root"),
                ("nginx", "alias.conf", "location /media/ {\n alias /srv/site/media/;\n}\n",
                 "/srv/site/media/a.jpg", "nginx.alias"),
            ]
            for family, filename, content, candidate, directive in cases:
                with self.subTest(family=family, directive=directive):
                    case_dir = root / directive.replace(".", "-")
                    config_root = case_dir / family
                    config_root.mkdir(parents=True)
                    source = config_root / filename
                    source.write_text(content)
                    result = consumers.service_configs(candidate, roots=(config_root,))
                    self.assertEqual(result["status"], "in_use", result)
                    self.assertEqual(result["matches"], [str(source)])
                    self.assertIn(str(source), result["inspected_sources"])
                    self.assertIn(directive, result["matched_directives"])

    def test_service_config_in_root_include_is_scanned(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "nginx"
            included = root / "conf.d" / "site.conf"
            included.parent.mkdir(parents=True)
            main = root / "nginx.conf"
            main.write_text(f"include {included};\n")
            included.write_text("root /srv/site;\n")

            result = consumers.service_configs("/srv/site/index.html", roots=(root,))
            self.assertEqual(result["status"], "in_use", result)
            self.assertEqual(result["matches"], [str(included)])
            self.assertIn(str(main), result["inspected_sources"])
            self.assertIn(str(included), result["inspected_sources"])

    def test_service_config_out_of_root_or_variable_include_is_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "nginx"
            root.mkdir()
            outside = base / "outside.conf"
            outside.write_text("root /srv/site;\n")
            (root / "nginx.conf").write_text(f"include {outside};\n")
            result = consumers.service_configs("/srv/site/index.html", roots=(root,))
            self.assertEqual(result["status"], "unknown")
            self.assertEqual(result["reason"], "include_incomplete_or_outside_roots")

            (root / "nginx.conf").write_text("root $document_root;\n")
            result = consumers.service_configs("/srv/site/index.html", roots=(root,))
            self.assertEqual(result["status"], "unknown")
            self.assertEqual(result["reason"], "config_path_indirect_or_unsupported")

    def test_service_config_permission_and_timeout_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "mysql"
            root.mkdir()
            source = root / "my.cnf"
            source.write_text("[mysqld]\ndatadir=/var/lib/mysql\n")
            original_open = Path.open

            def deny_config_read(path, *args, **kwargs):
                if path == source:
                    raise PermissionError("fixture unreadable")
                return original_open(path, *args, **kwargs)

            with patch.object(Path, "open", deny_config_read):
                unreadable = consumers.service_configs("/var/lib/mysql/ibdata1", roots=(root,))
            self.assertEqual(unreadable["status"], "unknown")
            self.assertEqual(unreadable["reason"], "config_unreadable:PermissionError")
            timeout = consumers.service_configs("/var/lib/mysql/ibdata1", roots=(root,), timeout=0)
            self.assertEqual(timeout["status"], "unknown")
            self.assertEqual(timeout["reason"], "config_timeout")

    def test_service_configs_do_not_require_rg(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "mysql"
            root.mkdir()
            source = root / "my.cnf"
            source.write_text("[mysqld]\ndatadir=/var/lib/mysql\n")
            with patch.object(consumers.shutil, "which", return_value=None):
                result = consumers.service_configs("/var/lib/mysql/ibdata1", roots=(root,))
            self.assertEqual(result["status"], "in_use", result)
            self.assertEqual(result["matches"], [str(source)])

    def test_service_config_file_byte_and_entry_caps_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "mysql"
            root.mkdir()
            (root / "my.cnf").write_text("[mysqld]\ndatadir=/var/lib/mysql\n")
            with patch.object(consumers, "MAX_SERVICE_CONFIG_SOURCES", 0):
                too_many_files = consumers.service_configs("/tmp/candidate", roots=(root,))
            self.assertEqual(too_many_files["status"], "unknown")
            self.assertEqual(too_many_files["reason"], "config_file_limit")

            with patch.object(consumers, "MAX_SERVICE_CONFIG_BYTES", 0):
                too_many_bytes = consumers.service_configs("/tmp/candidate", roots=(root,))
            self.assertEqual(too_many_bytes["status"], "unknown")
            self.assertEqual(too_many_bytes["reason"], "config_byte_limit")

            with patch.object(consumers, "MAX_SERVICE_CONFIG_ENTRIES", 0):
                too_many_entries = consumers.service_configs("/tmp/candidate", roots=(root,))
            self.assertEqual(too_many_entries["status"], "unknown")
            self.assertEqual(too_many_entries["reason"], "config_entry_limit")

    def test_absent_standard_service_config_roots_are_explicitly_not_applicable(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "not-installed"
            result = consumers.service_configs("/tmp/candidate", roots=(missing,))
            self.assertEqual(result["status"], "clear")
            self.assertEqual(result["reason"], "not_applicable:no_supported_config_roots")
            self.assertEqual(result["scope"], ["not-installed"])

    def test_collect_runs_only_requested_checks(self):
        with patch.object(consumers, "git_state", return_value={"status": "clear"}) as git_check:
            with patch.object(consumers, "docker_mounts") as docker_check:
                result = consumers.collect("/tmp/candidate", checks={"git_state"})
        self.assertEqual(result, {"git_state": {"status": "clear"}})
        git_check.assert_called_once()
        docker_check.assert_not_called()

    def test_git_repository_directory_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "checkout"
            repo.mkdir()
            (repo / ".git").mkdir()
            with patch.object(consumers, "_run") as run:
                result = consumers.git_state(repo)
            self.assertEqual(result["status"], "in_use")
            run.assert_not_called()

    def test_git_command_failure_inside_repo_is_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / ".git").mkdir()
            target = Path(directory) / "untracked.bin"
            target.write_bytes(b"data")
            with patch.object(consumers, "_run", return_value=("unknown", "exit_128")):
                result = consumers.git_state(target)
            self.assertEqual(result["status"], "unknown")


if __name__ == "__main__":
    unittest.main()
