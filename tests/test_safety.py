from __future__ import annotations

import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from cleanup_agent.inventory import scan
from cleanup_agent import safety
from cleanup_agent.safety import execute_delete, inspect

CLEAR_CONSUMERS = {name: {"status": "clear"} for name in (
    "docker_mounts", "pm2_processes", "systemd_units", "cron_jobs", "git_state",
    "literal_code_refs")}


def candidate_for(path: Path) -> dict:
    result = scan(path.parent, {"min_file_bytes": 0, "min_directory_bytes": 0,
                                "inspect_candidates": 0})
    return next(item for item in result["candidates"] if item["path"] == str(path))


class SafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.proc_tmp = tempfile.TemporaryDirectory(prefix="safety-proc-")
        self.old_proc_root = safety.PROC_ROOT
        safety.PROC_ROOT = Path(self.proc_tmp.name)

    def tearDown(self) -> None:
        safety.PROC_ROOT = self.old_proc_root
        self.proc_tmp.cleanup()

    def fake_process(self, pid: int, *, cmdline: bytes = b"/worker\0",
                     cwd: str = "/", maps: bytes = b"") -> Path:
        process = safety.PROC_ROOT / str(pid)
        (process / "fd").mkdir(parents=True)
        (process / "cmdline").write_bytes(cmdline)
        (process / "cwd").symlink_to(cwd)
        (process / "maps").write_bytes(maps)
        return process

    def test_mmap_is_detected_by_device_inode_after_fd_is_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mapped.bin"
            path.write_bytes(b"x" * 65536)
            st = path.stat()
            device = f"{os.major(st.st_dev):02x}:{os.minor(st.st_dev):02x}"
            maps = f"1000-2000 r--p 0 {device} {st.st_ino} {path}\n".encode()
            self.fake_process(31337, maps=maps)

            proc = safety.PROC_ROOT / "31337"
            self.assertEqual(list((proc / "fd").iterdir()), [])
            evidence = safety._proc_evidence(path, safety._caps(None))
            self.assertEqual(evidence["status"], "active")
            self.assertEqual(evidence["references"][0]["kind"], "mmap")

            candidate = candidate_for(path)
            config = {"approved_paths": [{
                "path": str(path), "identity": candidate["identity"],
                "required_consumer_checks": ["processes", "mounts"],
            }]}
            result = execute_delete(candidate, config, apply=True, run_state={},
                                    consumer_evidence=CLEAR_CONSUMERS)
            self.assertEqual(result["status"], "rejected", result)
            self.assertIn("active_process_reference", result["evidence"]["unsafe"])
            self.assertTrue(path.exists())

    def test_unreadable_or_over_budget_maps_are_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            maps = Path(tmp) / "maps"
            maps.write_text("0000-1000 r--p 0 08:01 17 /item\n")
            with patch.object(Path, "open", side_effect=PermissionError):
                _, unreadable = safety._mapped_inodes(Path(tmp), {(1, 17)}, 4096)
            self.assertEqual(unreadable, ["maps_inaccessible"])

            matched, truncated = safety._mapped_inodes(Path(tmp), {(1, 17)}, 4)
            self.assertEqual(matched, [])
            self.assertEqual(truncated, ["maps_budget_exhausted"])

    def test_container_mount_visibility_uses_mountinfo_and_container_signals(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidate = root / "host-data" / "old.bin"
            candidate.parent.mkdir()
            mountinfo = root / "mountinfo"
            marker = root / ".dockerenv"
            marker.touch()
            root_mount = "36 25 0:32 / / rw - overlay overlay rw\n"
            bind_mount = (f"45 25 0:33 / {candidate.parent} rw - ext4 /dev/sdb1 rw\n")
            mountinfo.write_text(root_mount + bind_mount)

            reason = safety._container_mount_scope_unknown(
                candidate, mountinfo_path=mountinfo, marker_paths=(marker,))
            self.assertEqual(reason, "container_mount_process_visibility_unknown")

            # An overlay root is itself a container signal without marker files.
            reason = safety._container_mount_scope_unknown(
                candidate, mountinfo_path=mountinfo, marker_paths=())
            self.assertEqual(reason, "container_mount_process_visibility_unknown")

            # A separate mount is allowed on a normal host ext4 root.
            marker.unlink()
            mountinfo.write_text("36 25 8:1 / / rw - ext4 /dev/sda1 rw\n" + bind_mount)
            reason = safety._container_mount_scope_unknown(
                candidate, mountinfo_path=mountinfo, marker_paths=(marker,))
            self.assertIsNone(reason)

            # Container-private rootfs paths remain eligible for process checks.
            mountinfo.write_text(root_mount)
            reason = safety._container_mount_scope_unknown(
                candidate, mountinfo_path=mountinfo, marker_paths=(marker,))
            self.assertIsNone(reason)

    def test_container_bind_mount_is_core_unknown_and_apply_rejects(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "old.bin"
            path.write_bytes(b"old data")
            marker = root / ".dockerenv"
            marker.touch()
            mountinfo = root / "mountinfo"
            mountinfo.write_text(
                "36 25 0:32 / / rw - overlay overlay rw\n"
                f"45 25 0:33 / {root} rw - ext4 /dev/sdb1 rw\n")
            candidate = candidate_for(path)
            config = {"approved_paths": [{
                "path": str(path), "identity": candidate["identity"],
                "required_consumer_checks": ["processes", "mounts"],
            }]}
            with patch.object(safety, "MOUNTINFO_PATH", mountinfo), patch.object(
                safety, "CONTAINER_MARKER_PATHS", (marker,)):
                evidence = inspect(str(path))
                self.assertEqual(evidence["processes"]["status"], "unknown")
                self.assertIn("container_mount_process_visibility_unknown",
                              evidence["core_unknown"])
                result = execute_delete(candidate, config, apply=True, run_state={},
                                        consumer_evidence=CLEAR_CONSUMERS)
            self.assertEqual(result["status"], "rejected", result)
            self.assertTrue(path.exists())

    def test_user_supplied_caps_cannot_remove_hard_budgets(self) -> None:
        with self.assertRaisesRegex(ValueError, "hard safety limit"):
            safety._caps({"max_delete_milliseconds": 10_001})

    def test_late_open_between_recheck_and_unlink_blocks_delete(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "late-open.bin"
            path.write_bytes(b"payload")
            candidate = candidate_for(path)
            config = {"approved_paths": [{
                "path": str(path), "identity": candidate["identity"],
                "required_consumer_checks": ["processes", "mounts"],
            }]}
            original = safety._recheck
            process = self.fake_process(31338)
            opened_fd = process / "fd" / "7"

            def open_after_recheck(*args, **kwargs):
                result = original(*args, **kwargs)
                opened_fd.symlink_to(path)
                return result

            try:
                with patch("cleanup_agent.safety._recheck", side_effect=open_after_recheck):
                    result = execute_delete(candidate, config, apply=True, run_state={},
                                            consumer_evidence=CLEAR_CONSUMERS)
                self.assertEqual(result["status"], "rejected", result)
                self.assertEqual(result["reason"], "active_process_reference_before_unlink")
                self.assertTrue(path.exists())
            finally:
                opened_fd.unlink(missing_ok=True)

    def test_directory_tree_is_deleted_from_rechecked_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            folder = root / "old-cache"
            nested = folder / "nested"
            nested.mkdir(parents=True)
            (nested / "one.bin").write_bytes(b"one" * 1024)
            (folder / "two.bin").write_bytes(b"two" * 1024)
            candidate = next(item for item in scan(
                root, {"min_file_bytes": 0, "min_directory_bytes": 0,
                       "inspect_candidates": 0})["candidates"]
                if item["path"] == str(folder))
            config = {"approved_paths": [{
                "path": str(folder), "identity": candidate["identity"],
                "required_consumer_checks": ["processes", "mounts"],
            }]}
            result = execute_delete(candidate, config, apply=True, run_state={},
                                    consumer_evidence=CLEAR_CONSUMERS)
            self.assertEqual(result["status"], "deleted", result)
            self.assertFalse(folder.exists())
            self.assertGreater(result["allocated_bytes"], 0)

    def test_new_nested_file_after_recheck_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            folder = root / "old-cache"
            nested = folder / "nested"
            nested.mkdir(parents=True)
            (nested / "old.bin").write_bytes(b"old data")
            candidate = next(item for item in scan(
                root, {"min_file_bytes": 0, "min_directory_bytes": 0,
                       "inspect_candidates": 0})["candidates"]
                if item["path"] == str(folder))
            config = {"approved_paths": [{
                "path": str(folder), "identity": candidate["identity"],
                "required_consumer_checks": ["processes", "mounts"],
            }]}
            original = safety._unlink_tree
            fresh = nested / "new.bin"

            def create_after_recheck(*args, **kwargs):
                fresh.write_bytes(b"fresh")
                return original(*args, **kwargs)

            with patch("cleanup_agent.safety._unlink_tree", side_effect=create_after_recheck):
                result = execute_delete(candidate, config, apply=True, run_state={},
                                        consumer_evidence=CLEAR_CONSUMERS)
            self.assertEqual(result["status"], "rejected", result)
            self.assertEqual(result["reason"], "tree_entry_not_in_rechecked_inventory")
            self.assertTrue(fresh.exists())
            self.assertTrue((nested / "old.bin").exists())

    def test_partial_directory_removal_reports_deleted_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            folder = root / "old-cache"
            folder.mkdir()
            first, second = folder / "a.bin", folder / "b.bin"
            first.write_bytes(b"a" * 4096)
            second.write_bytes(b"b" * 4096)
            old = time.time() - 60
            os.utime(first, (old, old))
            os.utime(second, (old, old))
            os.utime(folder, (old, old))
            candidate = next(item for item in scan(
                root, {"min_file_bytes": 0, "min_directory_bytes": 0,
                       "inspect_candidates": 0})["candidates"]
                if item["path"] == str(folder))
            config = {"enabled_categories": ["qa"], "category_rules": [{
                "id": "qa", "parent_dir": str(root), "basename": folder.name,
                "owner_uid": os.getuid(), "min_age_seconds": 1,
                "max_bytes": 1_000_000, "max_count": 1,
                "required_consumer_checks": ["processes", "mounts"],
            }]}
            clear = {"status": "clear", "references": [], "unknown": []}
            active = {"status": "active",
                      "references": [{"pid": 99, "kind": "open_fd"}], "unknown": []}
            run_state: dict = {}
            with patch("cleanup_agent.safety._proc_evidence",
                       side_effect=[clear, clear, active]):
                result = execute_delete(candidate, config, apply=True, run_state=run_state,
                                        consumer_evidence=CLEAR_CONSUMERS)
            self.assertEqual(result["status"], "partial", result)
            self.assertGreater(result["partial_deleted_bytes"], 0)
            self.assertNotEqual(first.exists(), second.exists())
            self.assertEqual(run_state["category_counts"]["qa"], 1)
            self.assertEqual(run_state["category_bytes"]["qa"], result["partial_deleted_bytes"])

    def test_inspect_marks_open_file_unknown_or_active(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "open.bin"
            path.write_bytes(b"payload")
            process = self.fake_process(31339)
            (process / "fd" / "3").symlink_to(path)
            with path.open("rb") as stream:
                evidence = inspect(str(path))
            self.assertIn(evidence["status"], {"active", "unsafe", "unknown"})
            if evidence["processes"].get("process_visibility") == "complete":
                self.assertTrue(evidence["processes"]["references"])

    def test_inaccessible_proc_is_unknown_and_never_clear(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "item"
            path.write_text("x")
            with patch("cleanup_agent.safety._proc_processes",
                       return_value=([], ["proc_unavailable:PermissionError"])):
                result = inspect(str(path))
            self.assertEqual(result["status"], "unknown")
            self.assertIn("proc_unavailable:PermissionError", result["unknown"])

    def test_dry_run_is_default_and_exact_approval_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "old.tmp"
            path.write_text("old")
            candidate = candidate_for(path)
            self.assertEqual(execute_delete(candidate, {})["status"], "rejected")
            config = {"approved_paths": [{"path": str(path), "identity": candidate["identity"]}]}
            result = execute_delete(candidate, config)
            self.assertEqual(result["status"], "dry_run")
            self.assertTrue(path.exists())

    def test_exact_approved_delete_rechecks_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "old.tmp"
            path.write_text("old")
            candidate = candidate_for(path)
            config = {"approved_paths": [{"path": str(path), "identity": candidate["identity"],
                                          "required_consumer_checks": ["processes", "mounts"]}]}
            result = execute_delete(candidate, config, apply=True,
                                    consumer_evidence=CLEAR_CONSUMERS)
            self.assertEqual(result["status"], "deleted", result)
            self.assertFalse(path.exists())

    def test_replaced_file_fails_identity_recheck(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "old.tmp"
            path.write_text("before")
            candidate = candidate_for(path)
            config = {"approved_paths": [{"path": str(path), "identity": candidate["identity"]}]}
            replacement = Path(tmp) / "replacement"
            replacement.write_text("after")
            replacement.replace(path)
            result = execute_delete(candidate, config, apply=True)
            self.assertEqual(result["status"], "rejected")
            self.assertTrue(path.exists())

    def test_category_requires_enabled_exact_parent_owner_age_and_run_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "qa-run-one.tmp"
            path.write_text("old")
            old = time.time() - 60
            os.utime(path, (old, old))
            candidate = candidate_for(path)
            rule = {"id": "qa", "parent_dir": str(root), "basename_prefix": "qa-run-",
                    "owner_uid": os.getuid(), "min_age_seconds": 1,
                    "max_bytes": 8192, "max_count": 1,
                    "required_consumer_checks": ["processes", "mounts"]}
            config = {"enabled_categories": ["qa"], "category_rules": [rule]}
            result = execute_delete(candidate, config, apply=True, run_state={},
                                    consumer_evidence=CLEAR_CONSUMERS)
            self.assertEqual(result["status"], "deleted", result)

    def test_category_limits_are_enforced_across_one_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = [root / "qa-run-one", root / "qa-run-two"]
            for path in paths:
                path.write_text("old")
                old = time.time() - 60
                os.utime(path, (old, old))
            candidates = [candidate_for(path) for path in paths]
            config = {"enabled_categories": ["qa"], "category_rules": [{
                "id": "qa", "parent_dir": str(root), "basename_prefix": "qa-run-",
                "owner_uid": os.getuid(), "min_age_seconds": 1,
                "max_bytes": 8192, "max_count": 1,
                "required_consumer_checks": ["processes", "mounts"],
            }]}
            state: dict = {}
            first = execute_delete(candidates[0], config, apply=True, run_state=state,
                                   consumer_evidence=CLEAR_CONSUMERS)
            second = execute_delete(candidates[1], config, apply=True, run_state=state,
                                    consumer_evidence=CLEAR_CONSUMERS)
            self.assertEqual(first["status"], "deleted")
            self.assertEqual(second["reason"], "category_count_limit_exceeded")
            self.assertTrue(paths[1].exists())

    def test_new_nested_file_keeps_directory_category(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            folder = root / "qa-run-snapshot"
            nested = folder / "nested"
            nested.mkdir(parents=True)
            leaf = nested / "old.txt"
            leaf.write_text("content")
            old = time.time() - 120
            os.utime(leaf, (old, old))
            os.utime(nested, (old, old))
            os.utime(folder, (old, old))
            candidate = next(item for item in scan(
                root, {"min_file_bytes": 0, "min_directory_bytes": 0,
                       "inspect_candidates": 0})["candidates"]
                if item["path"] == str(folder))
            # A nested, newly produced file makes the entire approved tree recent.
            leaf.write_text("new content")
            rule = {"id": "qa", "parent_dir": str(root), "basename": folder.name,
                    "owner_uid": os.getuid(), "min_age_seconds": 30,
                    "max_bytes": 16384, "max_count": 1,
                    "required_consumer_checks": ["processes", "mounts"]}
            config = {"enabled_categories": ["qa"], "category_rules": [rule]}
            result = execute_delete(candidate, config, apply=True, run_state={},
                                    consumer_evidence=CLEAR_CONSUMERS)
            self.assertEqual(result["reason"], "candidate_too_recent")
            self.assertTrue(leaf.exists())

    def test_hardlinked_candidate_is_never_deleted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "approved.tmp"
            path.write_text("shared")
            alias = Path(tmp) / "alias.tmp"
            os.link(path, alias)
            result = scan(path.parent, {"min_file_bytes": 0, "min_directory_bytes": 0,
                                        "inspect_candidates": 0})
            candidate = next(item for item in result["candidates"]
                             if item["identity"]["nlink"] > 1)
            config = {"approved_paths": [{"path": candidate["path"], "identity": candidate["identity"],
                                          "required_consumer_checks": ["processes", "mounts"]}]}
            result = execute_delete(candidate, config, apply=True,
                                    consumer_evidence=CLEAR_CONSUMERS)
            self.assertEqual(result["reason"], "safety_recheck_failed")
            self.assertTrue(path.exists())
            self.assertTrue(alias.exists())

    def test_symlink_candidate_mount_root_and_owner_mismatch_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            path = Path(tmp) / "link"
            path.symlink_to(outside)
            self.assertEqual(inspect(str(path))["status"], "unsafe")
            self.assertEqual(inspect("/")["status"], "unsafe")
            regular = Path(tmp) / "regular"
            regular.write_text("x")
            candidate = candidate_for(regular)
            config = {"enabled_categories": ["qa"], "category_rules": [{
                "id": "qa", "parent_dir": tmp, "basename": "regular",
                "owner_uid": candidate["identity"]["uid"] + 1,
                "min_age_seconds": 1, "max_bytes": 1024, "max_count": 1,
            }]}
            config["enabled_categories"] = ["qa"]
            result = execute_delete(candidate, config, apply=True, run_state={})
            self.assertEqual(result["reason"], "category_owner_mismatch")
            self.assertTrue(regular.exists())


if __name__ == "__main__":
    unittest.main()
