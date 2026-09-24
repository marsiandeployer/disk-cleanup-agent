from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cleanup_agent.inventory import scan


class InventoryTests(unittest.TestCase):
    def test_reports_large_files_directories_and_extension_without_reading_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nested = root / "archive"
            nested.mkdir()
            media = nested / "clip.MP4"
            media.write_bytes(b"not actually a media payload")
            result = scan(root, {"min_file_bytes": 1, "min_directory_bytes": 1,
                                 "inspect_candidates": 0})

            file_item = next(item for item in result["candidates"] if item["kind"] == "file")
            dir_item = next(item for item in result["candidates"] if item["path"] == str(nested))
            self.assertEqual(file_item["extension"], ".mp4")
            self.assertEqual(dir_item["kind"], "directory")
            self.assertEqual(dir_item["allocated_bytes"],
                             file_item["allocated_bytes"] + os.stat(nested).st_blocks * 512)
            self.assertEqual(result["status"], "complete")

    def test_never_follows_symlink_and_marks_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = Path(tmp)
            outside_file = Path(outside) / "payload.bin"
            outside_file.write_bytes(b"large")
            link = root / "linked-outside"
            link.symlink_to(outside)
            result = scan(root, {"min_file_bytes": 1, "min_directory_bytes": 1,
                                 "inspect_candidates": 0})
            self.assertFalse(any(item["path"].startswith(str(outside)) for item in result["candidates"]))
            skipped = next(item for item in result["skipped"] if item.get("path") == str(link))
            self.assertEqual(skipped["reason"], "symlink_not_followed")
            self.assertTrue(skipped["unknown"])

    def test_hardlink_allocation_is_counted_once_and_alias_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = root / "first.dat"
            first.write_bytes(b"big enough")
            second = root / "second.dat"
            os.link(first, second)
            result = scan(root, {"min_file_bytes": 1, "min_directory_bytes": 1,
                                 "inspect_candidates": 0})
            files = [item for item in result["candidates"] if item["kind"] == "file"]
            self.assertEqual(len(files), 1)
            self.assertEqual({files[0]["path"], *files[0]["hardlink_paths"]},
                             {str(first), str(second)})
            self.assertEqual(len(files[0]["hardlink_paths"]), 1)
            self.assertEqual(result["totals"]["allocated_bytes"],
                             os.stat(root).st_blocks * 512 + os.stat(first).st_blocks * 512)

    def test_budget_exhaustion_is_partial_and_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for index in range(8):
                (root / f"f{index}").write_bytes(b"x")
            result = scan(root, {"max_entries": 3, "min_file_bytes": 0,
                                 "min_directory_bytes": 0, "inspect_candidates": 0})
            self.assertEqual(result["status"], "partial")
            self.assertTrue(any("entry" in x["reason"] and "budget" in x["reason"]
                                for x in result["skipped"]))

    def test_default_scan_does_not_run_proc_inspection_for_every_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "large.bin"
            path.write_bytes(b"x")
            with patch("cleanup_agent.inventory.inspect") as inspect_mock:
                result = scan(tmp, {"min_file_bytes": 0})
            inspect_mock.assert_not_called()
            candidate = next(item for item in result["candidates"] if item["path"] == str(path))
            self.assertEqual(candidate["evidence"]["status"], "not_checked")
            self.assertTrue(candidate["unknown"])

    def test_sparse_large_logical_file_is_a_fact_not_a_reclaim_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "large-sparse.pdf"
            with path.open("wb") as stream:
                stream.truncate(70 * 1024 * 1024)
            result = scan(tmp, {"min_file_bytes": 64 * 1024 * 1024,
                                "min_directory_bytes": 1, "inspect_candidates": 0})
            self.assertFalse(any(item["path"] == str(path) for item in result["candidates"]))
            fact = next(item for item in result["sparse_files"] if item["path"] == str(path))
            self.assertEqual(fact["logical_size_bytes"], 70 * 1024 * 1024)
            self.assertLess(fact["allocated_bytes"], 64 * 1024 * 1024)

    def test_root_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "real"
            target.mkdir()
            link = root / "link"
            link.symlink_to(target)
            with self.assertRaises(ValueError):
                scan(link)

    def test_root_scan_respects_small_entry_budget(self) -> None:
        result = scan("/", {"max_entries": 1, "max_depth": 1,
                            "min_file_bytes": 1, "min_directory_bytes": 1,
                            "inspect_candidates": 0})
        self.assertEqual(result["root"], "/")
        self.assertEqual(result["status"], "partial")
        self.assertLessEqual(result["totals"]["entries"], 1)

    def test_mount_table_unavailable_does_not_descend(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nested = root / "nested"
            nested.mkdir()
            (nested / "large.bin").write_bytes(b"secret content")
            with patch("cleanup_agent.inventory._mountpoints", return_value=(set(), "hidden")):
                result = scan(root, {"min_file_bytes": 1, "min_directory_bytes": 1,
                                     "inspect_candidates": 0})
            self.assertEqual(result["status"], "partial")
            self.assertFalse(any(item["path"].startswith(str(nested / "large.bin"))
                                 for item in result["candidates"]))
            self.assertIn("mount_visibility_unknown", {x["reason"] for x in result["skipped"]})


if __name__ == "__main__":
    unittest.main()
