import json
import os
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cleanup_agent import consumers


class ConsumerChecksTest(unittest.TestCase):
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

    def test_code_roots_required_for_literal_search(self):
        result = consumers.literal_code_refs("/tmp/candidate")
        self.assertEqual(result["status"], "unknown")

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
