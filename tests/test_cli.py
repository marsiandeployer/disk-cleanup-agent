from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

from cleanup_agent import cli


def _candidate(path: str) -> dict:
    return {
        "path": path,
        "identity": {"dev": 1, "ino": 2, "mode": 0o100600, "uid": 1000, "gid": 1000,
                     "size": 4096, "mtime_ns": 1, "ctime_ns": 2, "nlink": 1},
        "allocated_bytes": 4096,
        "newest_mtime_ns": 1,
        "entry_count": 1,
        "kind": "file",
        "category": "inventory_large_file",
        "extension": ".bin",
        "unknown": False,
        "evidence": {"status": "clear", "unknown": [], "unsafe": [], "processes": {"references": []}},
    }


def _snapshot(candidate: dict) -> dict:
    scan = {"root": "/tmp/sandbox", "status": "complete", "capabilities": {},
            "totals": {"candidate_count": 1}, "skipped": [], "candidates": [candidate]}
    return {"format": cli.SCAN_FORMAT, "caps": {}, "scan": scan, "scan_sha256": cli._sha256(scan)}


class CliTests(unittest.TestCase):
    def test_model_inspection_summarizes_large_proc_unknown_without_clearing_it(self) -> None:
        per_pid_unknown = [f"proc_fd_unavailable:{index}:private-path" for index in range(600)]
        evidence = {
            "status": "unknown",
            "identity_matches_scan": True,
            "unsafe": [],
            "unknown": per_pid_unknown,
            "core_unknown": per_pid_unknown,
            "tree": {"status": "clear", "entries": 1, "allocated_bytes": 4096,
                     "newest_mtime_ns": 1, "owner_uids": [1000], "symlink_count": 0,
                     "hardlink_count": 0, "unknown": [], "unsafe": []},
            "processes": {"status": "unknown", "process_visibility": "partial",
                          "processes_seen": 10, "fds_seen": 2, "references": [],
                          "unknown": per_pid_unknown},
        }
        prompt_evidence = cli._safe_inspection(
            "C-12345678", "E-12345678", evidence,
            {"docker_mounts": {"status": "unknown", "source": "docker ps -aq",
                               "reason": "private path " + "x" * 5000, "matches": []}},
        )
        serialized = json.dumps(prompt_evidence)
        self.assertLess(len(serialized), 2_000)
        self.assertNotIn("private-path", serialized)
        self.assertNotIn("private path", serialized)
        self.assertEqual(prompt_evidence["unknown_count"], 600)
        self.assertEqual(prompt_evidence["core_unknown_count"], 600)
        self.assertEqual(prompt_evidence["processes"]["unknown_count"], 600)
        self.assertEqual(prompt_evidence["status"], "unknown")
        self.assertEqual(prompt_evidence["processes"]["status"], "unknown")

    def test_output_is_atomic_private_and_does_not_overwrite_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "scan.json"
            cli._write_json({"private": True}, str(output))
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                cli._write_json({"private": False}, str(output))
            self.assertEqual(json.loads(output.read_text()), {"private": True})
            self.assertEqual(list(Path(temp).glob("*.tmp")), [])

    def test_scan_checksum_rejects_modified_snapshot(self) -> None:
        snapshot = _snapshot(_candidate("/tmp/secret/data.bin"))
        snapshot["scan"]["root"] = "/tmp/changed"
        with self.assertRaisesRegex(ValueError, "checksum"):
            cli._read_scan(snapshot)

    def test_prompt_uses_opaque_ids_and_never_shares_absolute_path(self) -> None:
        candidate = _candidate("/tmp/secret/client-identity/backup.bin")
        prompt = cli._model_request(_snapshot(candidate), [], [])
        self.assertNotIn(candidate["path"], prompt)
        self.assertIn(cli._candidate_ref(candidate), prompt)
        self.assertIn("UNTRUSTED_JSON_DATA", prompt)

    def test_model_schema_rejects_invented_candidate_and_evidence(self) -> None:
        candidate = _candidate("/tmp/secret.bin")
        ref = cli._candidate_ref(candidate)
        valid = {"inspect_refs": [], "items": [{"ref": ref, "assessment": "keep", "reason": "active", "evidence_refs": []}], "limitations": []}
        parsed = cli._parse_model_round(json.dumps(valid), {ref: candidate}, set())
        self.assertEqual(parsed["items"][0]["assessment"], "keep")
        valid["items"][0]["ref"] = "C-invented"
        with self.assertRaisesRegex(ValueError, "unknown"):
            cli._parse_model_round(json.dumps(valid), {ref: candidate}, set())
        valid["items"][0]["ref"] = ref
        valid["items"][0]["evidence_refs"] = ["E-invented"]
        with self.assertRaisesRegex(ValueError, "evidence"):
            cli._parse_model_round(json.dumps(valid), {ref: candidate}, set())

    def test_incomplete_scan_requires_a_clear_inspection_before_review_recommendation(self) -> None:
        candidate = _candidate("/tmp/qa/large.bin")
        candidate["unknown"] = True
        candidate["evidence"] = {"status": "not_checked", "unknown": ["not_inspected"]}
        ref = cli._candidate_ref(candidate)
        answer = {"inspect_refs": [], "items": [{"ref": ref, "assessment": "candidate_for_review",
                  "reason": "large", "evidence_refs": []}], "limitations": []}
        with self.assertRaisesRegex(ValueError, "clear inspection"):
            cli._parse_model_round(json.dumps(answer), {ref: candidate}, set())
        clear = {"status": "clear", "unknown": []}
        parsed = cli._parse_model_round(json.dumps(answer), {ref: candidate}, set(), {ref: clear})
        self.assertEqual(parsed["items"][0]["assessment"], "candidate_for_review")

    def test_unknown_optional_preinspection_cannot_be_promoted(self) -> None:
        candidate = _candidate("/tmp/qa/large.bin")
        candidate["unknown"] = True
        candidate["evidence"] = {"status": "not_checked", "unknown": ["not_inspected"]}
        ref = cli._candidate_ref(candidate)
        inspection = {"status": "unknown", "unknown": ["consumer_check_unavailable"], "unsafe": []}
        evidence_ref = cli._evidence_ref(ref, {"inspection": inspection,
                                              "consumer_checks": {"docker_mounts": {"status": "unknown"}}},
                                        "preinspect")
        valid_evidence = {evidence_ref}
        promoted = {"inspect_refs": [], "items": [{"ref": ref, "assessment": "candidate_for_review",
                    "reason": "large and old", "evidence_refs": [evidence_ref]}], "limitations": []}
        with self.assertRaisesRegex(ValueError, "clear inspection"):
            cli._parse_model_round(json.dumps(promoted), {ref: candidate}, valid_evidence, {ref: inspection})
        promoted["items"][0]["assessment"] = "unknown"
        accepted = cli._parse_model_round(json.dumps(promoted), {ref: candidate}, valid_evidence, {ref: inspection})
        self.assertEqual(accepted["items"][0]["assessment"], "unknown")

    def test_plan_preinspects_top_two_and_sends_opaque_evidence_to_model(self) -> None:
        candidates = [_candidate(f"/tmp/private/secret-{i}.bin") for i in range(3)]
        candidates[0]["allocated_bytes"] = 4096
        candidates[1]["allocated_bytes"] = 16384
        candidates[2]["allocated_bytes"] = 8192
        scan = _snapshot(candidates[0])["scan"]
        scan["candidates"] = candidates
        scan["totals"]["candidate_count"] = 3
        snapshot = {"format": cli.SCAN_FORMAT, "caps": {}, "scan": scan,
                    "scan_sha256": cli._sha256(scan)}
        top_two = sorted(candidates, key=lambda candidate: candidate["allocated_bytes"], reverse=True)[:2]
        inspection = {"status": "unknown", "identity_matches_scan": True,
                      "unknown": ["consumer_checks_missing"], "unsafe": [],
                      "tree": {"status": "clear", "entries": 1, "allocated_bytes": 16384,
                               "newest_mtime_ns": 1, "owner_uids": [1000], "symlink_count": 0,
                               "hardlink_count": 0, "unknown": [], "unsafe": []},
                      "processes": {"status": "clear", "process_visibility": "complete",
                                    "processes_seen": 1, "fds_seen": 1, "references": [], "unknown": []}}
        consumer_checks = {"docker_mounts": {"status": "unknown", "source": "docker ps -aq",
                                             "reason": "daemon socket unavailable", "matches": []}}
        captured_prompts: list[str] = []
        captured_schemas: list[dict] = []

        class FakeRuntime:
            def __init__(self, **_kwargs):
                pass

            def generate(self, prompt, *, response_schema=None):
                captured_prompts.append(prompt)
                captured_schemas.append(response_schema)
                payload = json.loads(prompt.split("UNTRUSTED_JSON_DATA:\n", 1)[1])
                rows = payload["read_only_inspections"]
                self_test = rows
                assert len(self_test) == 2
                assert all(row["status"] == "unknown" for row in rows)
                assert all(row["consumer_checks"]["docker_mounts"]["status"] == "unknown" for row in rows)
                assert all("/tmp/private/" not in json.dumps(row) for row in rows)
                ref = rows[0]["ref"]
                evidence_ref = rows[0]["evidence_ref"]
                return json.dumps({"inspect_refs": [], "items": [{"ref": ref, "assessment": "unknown",
                                   "reason": "optional consumer check unavailable",
                                   "evidence_refs": [evidence_ref]}], "limitations": []})

        with tempfile.TemporaryDirectory() as temp:
            snapshot_path, output_path = Path(temp) / "scan.json", Path(temp) / "plan.json"
            snapshot_path.write_text(json.dumps(snapshot))
            args = Namespace(snapshot=str(snapshot_path), output=str(output_path), overwrite=False,
                             opencode_bin=None, llama_server_bin=None, model=None, runtime_dir=None,
                             context_size=4096, threads=2, request_timeout=10, total_timeout=180,
                             max_prompt_chars=10_000, code_root=None, preinspect_candidates=2)
            with patch.object(cli, "OpenCodeRuntime", FakeRuntime), \
                 patch.object(cli.consumers, "collect", return_value=consumer_checks) as collect, \
                 patch.object(cli.safety, "inspect", return_value=inspection) as inspect:
                result = cli.command_plan(args)
            self.assertEqual(result, 2)
            self.assertEqual(collect.call_count, 2)
            self.assertEqual(inspect.call_count, 2)
            self.assertEqual([call.args[0]["path"] for call in inspect.call_args_list],
                             [candidate["path"] for candidate in top_two])
            self.assertEqual(len(captured_prompts), 1)
            self.assertFalse(any(candidate["path"] in captured_prompts[0] for candidate in candidates))
            self.assertEqual(captured_schemas[0]["properties"]["inspect_refs"]["maxItems"], 1)
            inspect_enum = captured_schemas[0]["properties"]["inspect_refs"]["items"]["enum"]
            self.assertEqual(inspect_enum, [cli._candidate_ref(candidates[0])])
            plan = json.loads(output_path.read_text())
            self.assertEqual(len(plan["inspections"]), 2)
            model_item = next(item for item in plan["items"] if item["assessment"] == "unknown"
                              and item["reason"] == "optional consumer check unavailable")
            self.assertEqual(model_item["evidence_refs"], [plan["inspections"][0]["evidence_ref"]])
            self.assertEqual(model_item["assessment"], "unknown")

    def test_plan_skips_preinspection_when_time_reserve_is_insufficient(self) -> None:
        candidate = _candidate("/tmp/private/large.bin")
        snapshot = _snapshot(candidate)

        class FakeRuntime:
            def __init__(self, **_kwargs):
                pass

            def generate(self, _prompt, *, response_schema=None):
                return json.dumps({"inspect_refs": [], "items": [], "limitations": []})

        with tempfile.TemporaryDirectory() as temp:
            snapshot_path, output_path = Path(temp) / "scan.json", Path(temp) / "plan.json"
            snapshot_path.write_text(json.dumps(snapshot))
            args = Namespace(snapshot=str(snapshot_path), output=str(output_path), overwrite=False,
                             opencode_bin=None, llama_server_bin=None, model=None, runtime_dir=None,
                             context_size=4096, threads=2, request_timeout=10, total_timeout=30,
                             max_prompt_chars=10_000, code_root=None, preinspect_candidates=2)
            with patch.object(cli, "OpenCodeRuntime", FakeRuntime), \
                 patch.object(cli.consumers, "collect") as collect, \
                 patch.object(cli.safety, "inspect") as inspect:
                result = cli.command_plan(args)
            collect.assert_not_called()
            inspect.assert_not_called()
            self.assertEqual(result, 2)
            plan = json.loads(output_path.read_text())
            self.assertEqual(plan["inspections"], [])
            self.assertTrue(any("preinspection skipped" in row for row in plan["limitations"]))

    def test_plan_runs_bounded_inspection_round_then_final_answer(self) -> None:
        candidate = _candidate("/tmp/secret/customer.tar")
        snapshot = _snapshot(candidate)
        with tempfile.TemporaryDirectory() as temp:
            snapshot_path = Path(temp) / "scan.json"
            output_path = Path(temp) / "plan.json"
            snapshot_path.write_text(json.dumps(snapshot))
            ref = cli._candidate_ref(candidate)
            inspect = {"status": "clear", "path": candidate["path"], "identity_matches_scan": True,
                       "unknown": [], "unsafe": [], "tree": {"status": "clear", "entries": 1,
                       "allocated_bytes": 4096, "newest_mtime_ns": 1, "owner_uids": [1000],
                       "symlink_count": 0, "hardlink_count": 0, "unknown": [], "unsafe": []},
                       "processes": {"status": "clear", "process_visibility": "complete", "processes_seen": 1,
                                     "fds_seen": 1, "references": [], "unknown": []}}
            consumer_checks = {"docker_mounts": {"status": "unknown", "source": "docker", "reason": "command_missing", "matches": []}}
            inspection_payload = {"inspection": inspect, "consumer_checks": consumer_checks}
            evidence_ref = cli._evidence_ref(ref, inspection_payload, "inspect-1")
            first = {"inspect_refs": [ref], "items": [], "limitations": []}
            second = {"inspect_refs": [], "items": [{"ref": ref, "assessment": "candidate_for_review",
                      "reason": "old large file; consumer status should be reviewed", "evidence_refs": [evidence_ref]}], "limitations": []}

            class FakeRuntime:
                prompts = []
                responses = [json.dumps(first), json.dumps(second)]

                def __init__(self, **kwargs):
                    pass

                def generate(self, prompt, *, response_schema=None):
                    self.schemas.append(response_schema)
                    self.prompts.append(prompt)
                    return self.responses.pop(0)

                schemas = []

            args = Namespace(snapshot=str(snapshot_path), output=str(output_path), overwrite=False,
                             opencode_bin=None, llama_server_bin=None, model=None, runtime_dir=None,
                             context_size=4096, threads=2, request_timeout=10, total_timeout=30,
                             max_prompt_chars=10_000,
                             code_root=None, preinspect_candidates=0)
            with patch.object(cli, "OpenCodeRuntime", FakeRuntime), \
                 patch.object(cli.safety, "inspect", return_value=inspect) as inspect_mock, \
                 patch.object(cli.consumers, "collect", return_value=consumer_checks):
                result = cli.command_plan(args)
            self.assertEqual(result, 0)
            self.assertEqual(len(FakeRuntime.prompts), 2)
            self.assertEqual(len(FakeRuntime.schemas), 2)
            self.assertEqual(FakeRuntime.schemas[0]["additionalProperties"], False)
            self.assertIn(ref, FakeRuntime.schemas[0]["properties"]["inspect_refs"]["items"]["enum"])
            self.assertTrue(all(candidate["path"] not in prompt for prompt in FakeRuntime.prompts))
            inspect_mock.assert_called_once()
            plan = json.loads(output_path.read_text())
            self.assertEqual(plan["agentic_rounds"], 2)
            self.assertFalse(plan["deletion_authorized"])
            self.assertEqual(plan["items"][0]["assessment"], "candidate_for_review")
            self.assertEqual(output_path.stat().st_mode & 0o777, 0o600)

    def test_unrelated_category_approval_does_not_select_exactly_approved_path(self) -> None:
        candidate = _candidate("/tmp/private/specific.bin")
        scan = _snapshot(candidate)["scan"]
        item = {"ref": cli._candidate_ref(candidate), "path": candidate["path"],
                "identity": candidate["identity"], "candidate": candidate,
                "assessment": "candidate_for_review", "reason": "review", "evidence_refs": []}
        plan = {"format": "disk-cleanup-agent-plan-v1", "scan_sha256": cli._sha256(scan),
                "scan": scan, "caps": {}, "deletion_authorized": False, "status": "complete", "items": [item]}
        with tempfile.TemporaryDirectory() as temp:
            plan_path, config_path, output_path = (Path(temp) / name for name in ("plan.json", "consent.json", "out.json"))
            plan_path.write_text(json.dumps(plan))
            config_path.write_text(json.dumps({
                "enabled_categories": ["allowed-category"],
                "category_rules": [{"id": "allowed-category", "parent_dir": "/tmp/other", "basename_prefix": "qa-",
                                    "owner_uid": 1000, "min_age_seconds": 0, "max_bytes": 1_000_000, "max_count": 1}],
                "approved_paths": [{"path": candidate["path"], "identity": candidate["identity"]}],
            }))
            args = Namespace(plan=str(plan_path), config=str(config_path),
                             approve_category=["allowed-category"], approve_path=None,
                             output=str(output_path), overwrite=False)
            with patch.object(cli.inventory, "scan", return_value=scan), \
                 patch.object(cli.safety, "execute_delete") as execute:
                result = cli.command_apply(args)
            execute.assert_not_called()
            payload = json.loads(output_path.read_text())
            self.assertEqual(payload["deleted_count"], 0)
            self.assertEqual(payload["results"], [])
            self.assertEqual(result, 0)

    def test_manual_plan_is_explicit_model_free_and_binds_scan_and_consent_sources(self) -> None:
        approved = _candidate("/tmp/sandbox/qa-old-run-a.bin")
        unconfigured = _candidate("/tmp/sandbox/other.bin")
        scan = _snapshot(approved)["scan"]
        scan["candidates"] = [approved, unconfigured]
        snapshot = {"format": cli.SCAN_FORMAT, "caps": {}, "scan": scan,
                    "scan_sha256": cli._sha256(scan)}
        config = {
            "enabled_categories": ["qa-old"],
            "category_rules": [{"id": "qa-old", "parent_dir": "/tmp/sandbox",
                                "basename_prefix": "qa-old-run-", "owner_uid": 1000,
                                "min_age_seconds": 60, "max_bytes": 100_000, "max_count": 2,
                                "required_consumer_checks": ["processes", "mounts"]}],
            "approved_paths": [],
        }
        evidence = {"status": "unknown", "unknown": ["process_visibility_unknown"], "unsafe": []}
        consumer_rows = {"docker_mounts": {"status": "unknown", "source": "docker", "matches": []}}
        with tempfile.TemporaryDirectory() as temp:
            snapshot_path = Path(temp) / "scan.json"
            config_path = Path(temp) / "consent.json"
            output_path = Path(temp) / "manual-plan.json"
            snapshot_path.write_text(json.dumps(snapshot))
            config_path.write_text(json.dumps(config))
            args = Namespace(snapshot=str(snapshot_path), config=str(config_path),
                             output=str(output_path), overwrite=False)
            with patch.object(cli.consumers, "collect", return_value=consumer_rows) as collect, \
                 patch.object(cli.safety, "inspect", return_value=evidence) as inspect, \
                 patch.object(cli, "OpenCodeRuntime", side_effect=AssertionError("manual plan called model")):
                result = cli.command_manual_plan(args)
            self.assertEqual(result, 0)
            collect.assert_called_once_with(approved["path"], code_roots=None, checks=set())
            inspect.assert_called_once()
            plan = json.loads(output_path.read_text())
            self.assertEqual(plan["planning_mode"], "manual_config")
            self.assertFalse(plan["deletion_authorized"])
            self.assertEqual(plan["items"][0]["assessment"], cli.MANUAL_ASSESSMENT)
            self.assertEqual(plan["items"][0]["inspection"]["status"], "unknown")
            self.assertEqual(plan["items"][1]["assessment"], "unknown")
            self.assertEqual(plan["consent_sha256"], cli._sha256(cli._load_consent_config(config_path)))
            self.assertEqual(plan["plan_sha256"], cli._plan_sha256(plan))
            self.assertEqual(output_path.stat().st_mode & 0o777, 0o600)

    def test_manual_plan_partial_scan_is_written_but_cannot_be_applied(self) -> None:
        candidate = _candidate("/tmp/sandbox/qa-old-run-a.bin")
        snapshot = _snapshot(candidate)
        snapshot["scan"]["status"] = "partial"
        snapshot["scan_sha256"] = cli._sha256(snapshot["scan"])
        config = {"enabled_categories": [], "category_rules": [], "approved_paths": []}
        with tempfile.TemporaryDirectory() as temp:
            snapshot_path, config_path, output_path = (Path(temp) / name for name in ("scan.json", "consent.json", "plan.json"))
            snapshot_path.write_text(json.dumps(snapshot))
            config_path.write_text(json.dumps(config))
            with patch.object(cli.consumers, "collect") as collect:
                result = cli.command_manual_plan(Namespace(snapshot=str(snapshot_path), config=str(config_path),
                                                            output=str(output_path), overwrite=False))
            self.assertEqual(result, 2)
            collect.assert_not_called()
            plan = json.loads(output_path.read_text())
            self.assertEqual(plan["status"], "partial")
            apply_args = Namespace(plan=str(output_path), config=str(config_path), approve_category=["x"],
                                   approve_path=None, output=None, overwrite=False)
            with self.assertRaisesRegex(ValueError, "partial"):
                cli.command_apply(apply_args)

    def test_manual_plan_rejects_changed_config_and_candidate_source(self) -> None:
        candidate = _candidate("/tmp/sandbox/qa-old-run-a.bin")
        snapshot = _snapshot(candidate)
        config = {"enabled_categories": [], "category_rules": [],
                  "approved_paths": [{"path": candidate["path"], "identity": candidate["identity"]}]}
        plan = {"format": "disk-cleanup-agent-plan-v1", "planning_mode": "manual_config",
                "scan_sha256": cli._sha256(snapshot["scan"]), "consent_sha256": cli._sha256(config),
                "scan": snapshot["scan"], "caps": {}, "deletion_authorized": False, "status": "complete",
                "items": [{"ref": cli._candidate_ref(candidate), "path": candidate["path"],
                           "identity": candidate["identity"], "candidate": candidate,
                           "assessment": cli.MANUAL_ASSESSMENT, "configured_category": None,
                           "configured_exact_path": True}]}
        plan["plan_sha256"] = cli._plan_sha256(plan)
        with tempfile.TemporaryDirectory() as temp:
            plan_path, config_path = Path(temp) / "plan.json", Path(temp) / "consent.json"
            plan_path.write_text(json.dumps(plan))
            changed = {**config, "approved_paths": []}
            config_path.write_text(json.dumps(changed))
            args = Namespace(plan=str(plan_path), config=str(config_path), approve_category=None,
                             approve_path=[candidate["path"]], output=None, overwrite=False)
            with self.assertRaisesRegex(ValueError, "config changed"):
                cli.command_apply(args)

            config_path.write_text(json.dumps(config))
            altered = json.loads(plan_path.read_text())
            altered["items"][0]["candidate"]["path"] = "/tmp/outside.bin"
            altered["items"][0]["path"] = "/tmp/outside.bin"
            altered["plan_sha256"] = cli._plan_sha256(altered)
            plan_path.write_text(json.dumps(altered))
            with patch.object(cli.inventory, "scan") as fresh_scan, \
                 self.assertRaisesRegex(ValueError, "checksummed scan source"):
                cli.command_apply(args)
            fresh_scan.assert_not_called()

    def test_scan_manual_plan_apply_e2e_respects_process_visibility(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cleanup-agent-qa-") as temp:
            root = Path(temp)
            candidate_path = root / "qa-old-run-fixture.bin"
            candidate_path.write_bytes(b"qa fixture" * 1024)
            old = time.time() - 3600
            os.utime(candidate_path, (old, old))
            caps = {**cli.inventory.DEFAULT_CAPS, "min_file_bytes": 1,
                    "min_directory_bytes": 1_000_000_000, "inspect_candidates": 0}
            scan = cli.inventory.scan(root, caps)
            self.assertEqual(scan["status"], "complete", scan)
            self.assertEqual([item["path"] for item in scan["candidates"]], [str(candidate_path)])
            snapshot = {"format": cli.SCAN_FORMAT, "caps": caps, "scan": scan,
                        "scan_sha256": cli._sha256(scan)}
            config = {
                "enabled_categories": ["qa-fixture"],
                "category_rules": [{"id": "qa-fixture", "parent_dir": str(root),
                                    "basename_prefix": "qa-old-run-", "owner_uid": os.getuid(),
                                    "min_age_seconds": 1, "max_bytes": 1_000_000, "max_count": 2,
                                    "required_consumer_checks": ["processes", "mounts"]}],
                "approved_paths": [],
            }
            with tempfile.TemporaryDirectory() as files:
                snapshot_path, config_path, plan_path, result_path = (
                    Path(files) / name for name in ("scan.json", "consent.json", "plan.json", "apply.json")
                )
                snapshot_path.write_text(json.dumps(snapshot))
                config_path.write_text(json.dumps(config))
                result = cli.command_manual_plan(Namespace(snapshot=str(snapshot_path), config=str(config_path),
                                                            output=str(plan_path), overwrite=False))
                self.assertEqual(result, 0)
                plan = json.loads(plan_path.read_text())
                self.assertEqual(plan["items"][0]["assessment"], cli.MANUAL_ASSESSMENT)
                self.assertTrue(candidate_path.exists(), "planning must never delete")
                apply_args = Namespace(plan=str(plan_path), config=str(config_path),
                                       approve_category=["qa-fixture"], approve_path=None,
                                       output=str(result_path), overwrite=False)
                result = cli.command_apply(apply_args)
                payload = json.loads(result_path.read_text())
                if result == 0:
                    self.assertEqual(payload["deleted_count"], 1)
                    self.assertFalse(candidate_path.exists())
                else:
                    # CI may not see other users' /proc entries. The real
                    # safety guard must preserve the fixture in that case.
                    self.assertEqual(result, 2, payload)
                    self.assertEqual(payload["deleted_count"], 0)
                    self.assertTrue(candidate_path.exists())
                    self.assertEqual(payload["results"][0]["reason"], "safety_recheck_failed")
                    self.assertTrue(payload["results"][0]["evidence"]["core_unknown"])


if __name__ == "__main__":
    unittest.main()
