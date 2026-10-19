# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Pure observation checks; these never launch a probe or a custody wrapper."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_SPEC = importlib.util.spec_from_file_location("windows_psec_live", Path(__file__).with_name("run_live.py"))
assert _SPEC is not None and _SPEC.loader is not None
live = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(live)


class ObservationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.mode = "loader-only"
        self.receipt = {
            "binary_sha256": "b" * 64,
            "build_commit": "a" * 40,
            "build_run": 123,
            "artifact_id": 456,
            "combined_lock_sha256": "c" * 64,
        }
        cases = [
            {"case": mode, "outcome": outcome, "direct_handle_signaled": True, "stdout": marker, "stderr": ""}
            for mode, outcome, marker in [
                ("loader", "Exited(23)", "FIXED_PSEC_LOADER_STARTED\n"),
            ]
        ]
        cases.append(
            {
                "axis_commit": live.artifact_verifier.AXIS_COMMIT,
                "mxc_commit": live.artifact_verifier.MXC_COMMIT,
                "translation_contract": "fixed-axis-hard-block-to-mxc-typed-1.0.0",
                "backend": "native_windows_psec_only",
                "production_qualification": False,
                "loader_only_diagnostic": True,
                "checks": sorted(live.CHECKS),
            }
        )
        self.record = {
            **self.receipt,
            "passed": True,
            "production_certification": False,
            "scope": live.artifact_verifier.SCOPE,
            "variant": live.artifact_verifier.VARIANT,
            "mode": "loader-only",
            "exit_code": 0,
            "outer_job_active_before_final_cleanup": 0,
            "outer_job_empty": True,
            "assigned_before_resume": True,
            "stdout": "\n".join(json.dumps(value) for value in cases),
        }

    def validate(self, record: object) -> bool:
        return live.valid_observations(record, self.receipt, self.mode)

    def test_complete_fixed_observations_accepted(self) -> None:
        self.assertTrue(self.validate(self.record))

    def test_job_empty_or_pre_resume_assignment_missing_refused(self) -> None:
        for name in ("outer_job_empty", "assigned_before_resume"):
            with self.subTest(name=name):
                changed = {**self.record, name: False}
                self.assertFalse(self.validate(changed))

    def test_boolean_is_not_zero_exit_or_active_count(self) -> None:
        for name in ("exit_code", "outer_job_active_before_final_cleanup"):
            with self.subTest(name=name):
                self.assertFalse(self.validate({**self.record, name: False}))

    def test_diagnostic_without_actual_payload_marker_refused(self) -> None:
        changed = copy.deepcopy(self.record)
        values = [json.loads(line) for line in changed["stdout"].splitlines()]
        values[0]["stdout"] = ""
        changed["stdout"] = "\n".join(json.dumps(value) for value in values)
        self.assertFalse(self.validate(changed))

    def test_missing_check_refused(self) -> None:
        changed = copy.deepcopy(self.record)
        values = [json.loads(line) for line in changed["stdout"].splitlines()]
        values[-1]["checks"].pop()
        changed["stdout"] = "\n".join(json.dumps(value) for value in values)
        self.assertFalse(self.validate(changed))

    def test_wrong_or_incomplete_check_set_refused(self) -> None:
        changed = copy.deepcopy(self.record)
        values = [json.loads(line) for line in changed["stdout"].splitlines()]
        values[-1]["checks"] = [
            "private_environment",
            "allowed_write",
            "outside_read_write_denied",
            "readonly_write_denied",
            "loopback_ipv4_ipv6_tcp_udp",
            "exit23",
            "timeout",
            "retained_direct_process_handles_signaled",
            "owned_fixture_removed",
        ]
        changed["stdout"] = "\n".join(json.dumps(value) for value in values)
        self.assertFalse(self.validate(changed))


class BoundaryObservationTests(ObservationTests):
    def setUp(self) -> None:
        super().setUp()
        self.mode = "standalone-boundary"
        cases = [
            {"case": case, "outcome": outcome, "direct_handle_signaled": True, "stdout": marker, "stderr": ""}
            for case, outcome, marker in [
                ("argv", "Exited(0)", "FIXED_ARGV_PASS\n"),
                ("boundary", "Exited(0)", "FIXED_NATIVE_ENV_BINDING_PASS\nFIXED_BOUNDARIES_PASS\n"),
                ("exit23", "Exited(23)", "FIXED_EXIT23_STARTED\n"),
                ("timeout", "TimedOut", "FIXED_TIMEOUT_STARTED\n"),
            ]
        ]
        cases[1]["stderr"] = "FIXED_CANONICALIZE result=ok\n"
        final = json.loads(self.record["stdout"].splitlines()[-1])
        final["loader_only_diagnostic"] = False
        final["psec_attribute_attached"] = True
        final["checks"] = sorted(live.BOUNDARY_CHECKS)
        cases.append(final)
        self.record.update(
            scope=live.artifact_verifier.BOUNDARY_SCOPE,
            variant=live.artifact_verifier.BOUNDARY_VARIANT,
            mode=self.mode,
            stdout="\n".join(json.dumps(case) for case in cases),
        )

    def test_boundary_transcript_cannot_certify_loader_mode(self) -> None:
        self.assertFalse(live.valid_observations(self.record, self.receipt, "loader-only"))

    def test_native_binding_and_attached_psec_are_required(self) -> None:
        cases = [json.loads(line) for line in self.record["stdout"].splitlines()]
        cases[1]["stdout"] = "FIXED_BOUNDARIES_PASS\n"
        self.assertFalse(self.validate({**self.record, "stdout": "\n".join(json.dumps(case) for case in cases)}))
        for value in (None, False, 1, "true"):
            with self.subTest(value=value):
                cases = [json.loads(line) for line in self.record["stdout"].splitlines()]
                cases[-1]["psec_attribute_attached"] = value
                self.assertFalse(
                    self.validate({**self.record, "stdout": "\n".join(json.dumps(case) for case in cases)})
                )

    def test_closed_path_free_canonicalization_diagnostic(self) -> None:
        template = (
            "FIXED_CANONICALIZE win32=5\n"
            "FIXED_CANON_OPEN result=ok\n"
            "FIXED_CANON_NORMALIZED_DOS win32=5\n"
            "FIXED_CANON_OPENED_DOS win32=5\n"
            "FIXED_CANON_NORMALIZED_NT result=ok length={length}\n"
            "FIXED_CANON_CLOSE result=ok\n"
            "FIXED_CANON_SEAL_READ result=ok match=true\n"
        )
        for length in (1, 189, 32767):
            with self.subTest(length=length):
                cases = [json.loads(line) for line in self.record["stdout"].splitlines()]
                cases[1]["stderr"] = template.format(length=length)
                self.assertTrue(self.validate({**self.record, "stdout": "\n".join(json.dumps(case) for case in cases)}))
        diagnostic = template.format(length=189)
        invalid = [
            "",
            None,
            True,
            diagnostic + "unexpected\n",
            diagnostic.replace("match=true", "match=false"),
            diagnostic.replace("win32=5", "win32=2", 1),
            diagnostic.replace("FIXED_CANON_CLOSE result=ok\n", ""),
            diagnostic.replace("length=189", "path=fixed-public-path"),
            *[template.format(length=value) for value in (0, -1, "+1", "01", 32768, 4294967295, "1\x00")],
        ]
        for value in invalid:
            with self.subTest(value=value):
                cases = [json.loads(line) for line in self.record["stdout"].splitlines()]
                cases[1]["stderr"] = value
                self.assertFalse(
                    self.validate({**self.record, "stdout": "\n".join(json.dumps(case) for case in cases)})
                )
        cases = [json.loads(line) for line in self.record["stdout"].splitlines()]
        cases[0]["stderr"] = diagnostic
        self.assertFalse(self.validate({**self.record, "stdout": "\n".join(json.dumps(case) for case in cases)}))

    def test_every_fixed_payload_marker_and_typed_timeout_is_required(self) -> None:
        for index in range(4):
            with self.subTest(index=index):
                cases = [json.loads(line) for line in self.record["stdout"].splitlines()]
                cases[index]["stdout"] = ""
                changed = {**self.record, "stdout": "\n".join(json.dumps(case) for case in cases)}
                self.assertFalse(self.validate(changed))
        cases = [json.loads(line) for line in self.record["stdout"].splitlines()]
        cases[3]["outcome"] = "Exited(124)"
        self.assertFalse(self.validate({**self.record, "stdout": "\n".join(json.dumps(case) for case in cases)}))


class DLLObservationTests(ObservationTests):
    def setUp(self) -> None:
        super().setUp()
        self.mode = "dll-startup-only"
        cases = [
            {
                "case": "dll-" + label,
                "outcome": "Exited(0)",
                "direct_handle_signaled": True,
                "stdout": f"FIXED_DLL_START:{label}\nFIXED_DLL_RETURN:{label}:loaded\n",
                "stderr": "",
            }
            for label in live.DLL_CASES
        ]
        final = json.loads(self.record["stdout"].splitlines()[-1])
        final.update(
            loader_only_diagnostic=False,
            dll_startup_only_diagnostic=True,
            dll_initialization_all_succeeded=True,
            checks=sorted(live.DLL_CHECKS),
        )
        cases.append(final)
        self.record.update(
            mode=self.mode,
            variant=live.artifact_verifier.DLL_VARIANT,
            scope=live.artifact_verifier.DLL_SCOPE,
            stdout="\n".join(json.dumps(case) for case in cases),
        )

    def with_cases(self, cases: list[dict]) -> dict:
        return {**self.record, "stdout": "\n".join(json.dumps(case) for case in cases)}

    def test_returned_dll_error_is_observed_without_claiming_compatibility(self) -> None:
        cases = [json.loads(line) for line in self.record["stdout"].splitlines()]
        cases[0]["stdout"] = "FIXED_DLL_START:user32\nFIXED_DLL_RETURN:user32:error:1114\n"
        cases[-1]["dll_initialization_all_succeeded"] = False
        self.assertTrue(self.validate(self.with_cases(cases)))
        cases[-1]["dll_initialization_all_succeeded"] = True
        self.assertFalse(self.validate(self.with_cases(cases)))

    def test_missing_return_timeout_abnormal_exit_or_cleanup_never_pass(self) -> None:
        for index in range(3):
            for key, changed in [
                ("stdout", ""),
                ("stdout", f"FIXED_DLL_START:{live.DLL_CASES[index]}\n"),
                ("outcome", "TimedOut"),
                ("outcome", "Exited(-1073741502)"),
                ("direct_handle_signaled", False),
                ("stderr", "fixed synthetic failure"),
            ]:
                with self.subTest(index=index, key=key, changed=changed):
                    cases = [json.loads(line) for line in self.record["stdout"].splitlines()]
                    cases[index][key] = changed
                    self.assertFalse(self.validate(self.with_cases(cases)))
        self.assertFalse(self.validate({**self.record, "exit_code": 1}))

    def test_wrong_case_duplicate_extra_marker_and_noncanonical_error_refuse(self) -> None:
        for suffix in ["0", "00", "01114", "+1114", "4294967296", "1114\0", "1114\nextra"]:
            with self.subTest(suffix=suffix):
                cases = [json.loads(line) for line in self.record["stdout"].splitlines()]
                cases[0]["stdout"] = f"FIXED_DLL_START:user32\nFIXED_DLL_RETURN:user32:error:{suffix}\n"
                cases[-1]["dll_initialization_all_succeeded"] = False
                self.assertFalse(self.validate(self.with_cases(cases)))
        cases = [json.loads(line) for line in self.record["stdout"].splitlines()]
        cases[1] = cases[0]
        self.assertFalse(self.validate(self.with_cases(cases)))
        self.assertFalse(self.validate(self.with_cases(cases + [cases[0]])))

    def test_exact_three_case_order_matches_the_rust_protocol_source(self) -> None:
        source = (Path(__file__).parent / "src" / "dll_startup_protocol.rs").read_text(encoding="utf-8")
        matches = re.findall(r"pub const CASES: \[FixedDll; 3\] = \[([^\]]+)\];", source)
        self.assertEqual(len(matches), 1)
        self.assertEqual(tuple(name.lower() for name in re.findall(r"FixedDll::(\w+)", matches[0])), live.DLL_CASES)
        self.assertEqual(live.DLL_CASES, ("user32", "gdi32", "shell32"))


class ClaudeObservationTests(ObservationTests):
    def setUp(self) -> None:
        super().setUp()
        self.mode = "claude-version-only"
        self.local_receipt = "d" * 64
        contract = live.artifact_verifier.artifact_contract(self.mode)
        self.record.update(
            mode=self.mode,
            variant=contract["variant"],
            scope=contract["scope"],
            local_image_sha256=live.CLAUDE_IMAGE_SHA256,
            local_image_size=live.CLAUDE_IMAGE_SIZE,
            local_image_product_version=live.CLAUDE_PRODUCT_VERSION,
            local_image_review_receipt_sha256=self.local_receipt,
        )
        self.record["stdout"] = "\n".join(
            json.dumps(x)
            for x in [
                {
                    "case": "claude-version",
                    "outcome": "Exited(0)",
                    "direct_handle_signaled": True,
                    "stdout": "2.1.292 (Claude Code)\n",
                    "stderr": "",
                },
                {
                    "axis_commit": live.artifact_verifier.AXIS_COMMIT,
                    "mxc_commit": live.artifact_verifier.MXC_COMMIT,
                    "translation_contract": "fixed-axis-hard-block-to-mxc-typed-1.0.0",
                    "backend": "native_windows_psec_only",
                    "production_qualification": False,
                    "loader_only_diagnostic": False,
                    "dll_startup_only_diagnostic": False,
                    "claude_version_only": True,
                    "checks": sorted(live.CLAUDE_CHECKS),
                },
            ]
        )

    def validate(self, record: object) -> bool:
        return live.valid_observations(record, self.receipt, self.mode, self.local_receipt)

    def test_fixed_local_image_identity_and_external_receipt_are_required(self) -> None:
        for field, value in [
            ("local_image_sha256", "e" * 64),
            ("local_image_size", True),
            ("local_image_product_version", "other"),
            ("local_image_review_receipt_sha256", "e" * 64),
        ]:
            with self.subTest(field=field):
                self.assertFalse(self.validate({**self.record, field: value}))
        self.assertFalse(live.valid_observations(self.record, self.receipt, self.mode))

    def test_only_exact_native_newline_and_exit_zero_are_accepted(self) -> None:
        for output, outcome, error, accepted in [
            ("2.1.292 (Claude Code)\r\n", "Exited(0)", "", True),
            ("2.1.292 (Claude Code)\nextra", "Exited(0)", "", False),
            ("2.1.292 (Claude Code)\n", "Exited(23)", "", False),
            ("2.1.292 (Claude Code)\n", "Exited(0)", "unexpected", False),
        ]:
            changed = copy.deepcopy(self.record)
            rows = [json.loads(x) for x in changed["stdout"].splitlines()]
            rows[0].update(stdout=output, outcome=outcome, stderr=error)
            changed["stdout"] = "\n".join(json.dumps(x) for x in rows)
            self.assertIs(self.validate(changed), accepted)

    def test_malformed_or_missing_claude_output_refuses(self) -> None:
        for value in [None, [], {}, True]:
            changed = copy.deepcopy(self.record)
            rows = [json.loads(x) for x in changed["stdout"].splitlines()]
            rows[0]["stdout"] = value
            changed["stdout"] = "\n".join(json.dumps(x) for x in rows)
            self.assertFalse(self.validate(changed))

    def test_fixed_rust_success_checks_match_driver(self) -> None:
        source = Path(__file__).with_name("src").joinpath("probe.rs").read_text(encoding="utf-8")
        blocks = re.findall(r"\} else if claude_only \{\s*vec!\[(.*?)\]", source, re.DOTALL)
        self.assertEqual(len(blocks), 1)
        names = re.findall(r'"([a-z0-9_]+)"', blocks[0])
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(set(names), live.CLAUDE_CHECKS)


class FixedClaudeArgumentTests(unittest.TestCase):
    def test_missing_or_cross_mode_local_receipts_fail_before_process_or_file_access(self) -> None:
        base = [
            "run_live.py",
            "--custody",
            "fixed.exe",
            "--custody-sha256",
            "a" * 64,
            "--receipt",
            "receipt.json",
            "--receipt-sha256",
            "b" * 64,
            "--evidence",
            "fresh",
        ]
        for extra in [
            ["--claude-version-only"],
            ["--claude-version-only", "--local-image-receipt", "image.json"],
            ["--loader-only", "--local-image-receipt", "image.json", "--local-image-receipt-sha256", "c" * 64],
        ]:
            with (
                self.subTest(extra=extra),
                mock.patch.object(live.sys, "argv", base + extra),
                mock.patch.object(live.sys, "stderr", io.StringIO()),
                mock.patch.object(live.artifact_verifier, "ordinary_file") as read,
                mock.patch.object(live.subprocess, "Popen") as process,
                self.assertRaises(SystemExit) as failure,
            ):
                live.main()
            self.assertEqual(failure.exception.code, 2)
            read.assert_not_called()
            process.assert_not_called()


class BoundedCleanupTests(unittest.TestCase):
    def test_failed_poll_kill_and_second_wait_are_recorded_without_raising(self) -> None:
        process = mock.Mock()
        process.poll.side_effect = OSError("synthetic poll failure")
        process.kill.side_effect = OSError("synthetic kill failure")
        process.wait.side_effect = subprocess.TimeoutExpired("fixed", 5)
        errors = []
        self.assertIsNone(live.stop_owned(process, errors))
        self.assertEqual(len(errors), 3)
        process.kill.assert_called_once_with()
        process.wait.assert_called_once_with(timeout=5)

    def test_stopped_owned_process_needs_no_kill(self) -> None:
        process = mock.Mock()
        process.poll.return_value = 7
        errors = []
        self.assertEqual(live.stop_owned(process, errors), 7)
        self.assertEqual(errors, [])
        process.kill.assert_not_called()

    def test_close_failure_is_retained_and_live_reader_is_never_closed(self) -> None:
        stream, reader = mock.Mock(), mock.Mock()
        reader.is_alive.return_value = True
        errors = []
        live.close_finished_stream(stream, reader, errors)
        stream.close.assert_not_called()
        reader.is_alive.return_value = False
        stream.close.side_effect = OSError("synthetic close failure")
        live.close_finished_stream(stream, reader, errors)
        self.assertEqual(errors, ["custody stream close failed: OSError"])


class CustodyPinTests(unittest.TestCase):
    def test_hash_mismatch_closes_the_held_image_before_launch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "synthetic-not-a-pe.bin"
            path.write_bytes(b"fixed synthetic image")
            source = path.open("rb")
            with mock.patch.object(live, "open_custody_pin", return_value=source):
                with self.assertRaisesRegex(ValueError, "custody binary differs"):
                    live.pin_custody(path, "0" * 64)
            self.assertTrue(source.closed)

    def test_oversize_image_is_closed_without_hashing_or_launch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "synthetic-not-a-pe.bin"
            path.write_bytes(b"fixed synthetic image")
            source = path.open("rb")
            metadata = mock.Mock(st_mode=live.stat.S_IFREG, st_size=live.artifact_verifier.MAX_FILE_BYTES + 1)
            with (
                mock.patch.object(live, "open_custody_pin", return_value=source),
                mock.patch.object(live.os, "fstat", return_value=metadata),
            ):
                with self.assertRaisesRegex(ValueError, "image type or size differs"):
                    live.pin_custody(path, "0" * 64)
            self.assertTrue(source.closed)

    @unittest.skipUnless(live.sys.platform == "win32", "native Windows file sharing fixture")
    def test_mocked_launch_and_wait_keep_the_verified_wrapper_pinned(self) -> None:
        self.assert_mocked_launch_and_wait(keep_private_record=False)

    @unittest.skipUnless(live.sys.platform == "win32", "native Windows file sharing fixture")
    def test_failed_retained_private_record_contents_do_not_enter_result(self) -> None:
        self.assert_mocked_launch_and_wait(keep_private_record=True)

    def assert_mocked_launch_and_wait(self, keep_private_record: bool) -> None:
        # This is an inert byte file. Popen is mocked: no PE or process executes.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            custody = root / "synthetic-not-a-pe.bin"
            image = b"fixed public synthetic wrapper bytes"
            custody.write_bytes(image)
            receipt = root / "receipt.json"
            raw = json.dumps(
                {
                    "verified": True,
                    "execution_performed": False,
                    "variant": live.artifact_verifier.VARIANT,
                    "scope": live.artifact_verifier.SCOPE,
                }
            ).encode()
            receipt.write_bytes(raw)
            process = mock.Mock(stdout=io.BytesIO(b"{}"), stderr=io.BytesIO(b""))
            private = (
                root / "evidence/psec-headless-01/tmp/dc-axis-windows-psec-fixed/native-folder-refusal.private.bin"
            )
            marker = b"fixed-public-synthetic-private-path-record-marker"

            def held(*_args, **_kwargs):
                if keep_private_record and not private.exists():
                    private.parent.mkdir(parents=True)
                    private.write_bytes(marker)
                with self.assertRaises(PermissionError):
                    custody.write_bytes(b"replacement")
                with self.assertRaises(PermissionError):
                    custody.rename(root / "replacement.bin")
                return process

            def wait(*_args, **_kwargs):
                held()
                return 0

            process.wait.side_effect = wait
            argv = [
                "run_live.py",
                "--loader-only",
                "--custody",
                str(custody),
                "--custody-sha256",
                hashlib.sha256(image).hexdigest(),
                "--receipt",
                str(receipt),
                "--receipt-sha256",
                hashlib.sha256(raw).hexdigest(),
                "--evidence",
                str(root / "evidence"),
            ]
            with (
                mock.patch.object(live.sys, "argv", argv),
                mock.patch.object(live.platform, "machine", return_value="AMD64"),
                mock.patch.dict(live.os.environ, {"SYSTEMROOT": str(root)}, clear=True),
                mock.patch.object(live.subprocess, "Popen", side_effect=held) as launch,
                mock.patch.object(live, "valid_observations", return_value=True),
                mock.patch("builtins.print"),
            ):
                if keep_private_record:
                    with self.assertRaises(SystemExit) as refusal:
                        live.main()
                    self.assertEqual(refusal.exception.code, 1)
                else:
                    live.main()
            launch.assert_called_once()
            process.wait.assert_called_once_with(timeout=55)
            custody.write_bytes(b"pin released after bounded wait")
            result = json.loads((root / "evidence" / "live-result.json").read_text())
            self.assertEqual(result["passed"], not keep_private_record)
            self.assertNotIn(marker.decode(), json.dumps(result))
            if keep_private_record:
                self.assertEqual(private.read_bytes(), marker)
                self.assertEqual(result["retained_owned_fixtures"], [str(private.parent)])
            else:
                self.assertEqual(result["retained_owned_fixtures"], [])


class FixedControlObservationTests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = ClaudeObservationTests()
        fixture.setUp()
        self.receipt, self.local_receipt = fixture.receipt, fixture.local_receipt
        self.record = fixture.record
        self.mode = "claude-create-control-only"
        self.receipt["probe_cargo_features"] = ["fixed-claude-create-control"]
        self.record["probe_cargo_features"] = ["fixed-claude-create-control"]
        contract = live.artifact_verifier.artifact_contract(self.mode)
        self.record.update(mode=self.mode, variant=contract["variant"], scope=contract["scope"])
        self.rows = [live.CONTROL_INPUT_EVIDENCE.copy(), *map(json.loads, self.record["stdout"].splitlines())]
        self.rows[-1].update(
            backend="uncontained_fixed_create_control",
            claude_version_only=False,
            claude_create_control_only=True,
            psec_attribute_attached=False,
            control_reference_plan_executed=False,
            checks=sorted(live.CONTROL_CHECKS),
        )
        self.encode()

    def encode(self) -> None:
        self.record["stdout"] = "\n".join(json.dumps(row) for row in self.rows)

    def test_exact_control_passes_but_never_as_psec(self) -> None:
        self.assertTrue(live.valid_observations(self.record, self.receipt, self.mode, self.local_receipt))
        self.assertFalse(live.valid_observations(self.record, self.receipt, "claude-version-only", self.local_receipt))

    def test_equality_marker_types_counts_omissions_and_duplicates_refuse(self) -> None:
        for field, changed in [
            ("fixed_create_control_inputs_equal", 1),
            ("psec_attribute_attached", 0),
            ("constructed_psec_attribute_count", True),
            ("selected_attribute_count", 2),
        ]:
            with self.subTest(field=field):
                rows = copy.deepcopy(self.rows)
                self.rows[0][field] = changed
                self.encode()
                self.assertFalse(live.valid_observations(self.record, self.receipt, self.mode, self.local_receipt))
                self.rows = rows
        for rows in [self.rows[1:], [self.rows[0], *self.rows], [*self.rows, self.rows[0]]]:
            self.record["stdout"] = "\n".join(map(json.dumps, rows))
            self.assertFalse(live.valid_observations(self.record, self.receipt, self.mode, self.local_receipt))

    def test_false_containment_or_reference_execution_claim_refuses(self) -> None:
        for key, value in [
            ("backend", "native_windows_psec_only"),
            ("psec_attribute_attached", True),
            ("control_reference_plan_executed", True),
        ]:
            rows = copy.deepcopy(self.rows)
            self.rows[-1][key] = value
            self.encode()
            self.assertFalse(live.valid_observations(self.record, self.receipt, self.mode, self.local_receipt))
            self.rows = rows

    def test_control_rust_success_checks_match_driver(self) -> None:
        source = Path(__file__).with_name("src").joinpath("probe.rs").read_text(encoding="utf-8")
        blocks = re.findall(r"let checks = if create_control_only \{(.*?)\} else", source, re.DOTALL)
        self.assertEqual(len(blocks), 1)
        names = re.findall(r'"([a-z0-9_]+)"', blocks[0])
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(set(names), live.CONTROL_CHECKS)


if __name__ == "__main__":
    unittest.main()
