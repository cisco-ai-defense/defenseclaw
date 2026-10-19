#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Bound one verified fixed PSEC probe through the reviewed owned-Job wrapper."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

import verify_live_artifact as artifact_verifier

OUTPUT_BOUND = 1024 * 1024
CHECKS = {
    "separate_std_loader_marker",
    "exit23",
    "retained_direct_process_handles_signaled",
    "owned_fixture_removed",
}

BOUNDARY_CHECKS = {
    "literal_windows_argv",
    "private_environment",
    "allowed_write",
    "outside_read_write_denied",
    "readonly_write_denied",
    "loopback_ipv4_ipv6_tcp_udp",
    "exit23",
    "timeout",
    "retained_direct_process_handles_signaled",
    "owned_fixture_removed",
}
DLL_CHECKS = {
    "three_fixed_dll_start_markers",
    "three_fixed_dll_return_observations",
    "retained_direct_process_handles_signaled",
    "owned_fixture_removed",
}
DLL_CASES = ("user32", "gdi32", "shell32")
CLAUDE_CHECKS = {
    "fixed_signed_claude_version_output",
    "retained_direct_process_handles_signaled",
    "owned_fixture_removed",
}
CONTROL_CHECKS = CLAUDE_CHECKS | {"constructed_launch_inputs_equal_except_psec_attribute"}
CONTROL_INPUT_EVIDENCE = {
    "fixed_create_control_inputs_equal": True,
    "psec_attribute_attached": False,
    "constructed_psec_attribute_count": 2,
    "selected_attribute_count": 1,
}
CLAUDE_IMAGE_SHA256 = "eb95bb65955f8b1702e800815f9a2c0388a5de0f196c354c7ee1dd5cb9a2ba23"
CLAUDE_IMAGE_SIZE = 254858400
CLAUDE_PRODUCT_VERSION = "2.1.292.0"
CLAUDE_VERSION_OUTPUT = "2.1.292 (Claude Code)"
PROCESS_ERRORS = (OSError, subprocess.SubprocessError, ValueError, RuntimeError)


def open_custody_pin(path: Path):
    """Open the ordinary local wrapper without permitting image writes or deletion."""
    import ctypes
    import msvcrt
    from ctypes import wintypes

    for component in [path, *path.parents]:
        metadata = component.lstat()
        if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, "st_file_attributes", 0) & 0x400:
            raise ValueError("custody reparse-point path refused")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    handle = create_file(str(path), 0x80000000, 1, None, 3, 0x00200000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    close_handle = kernel32.CloseHandle
    close_handle.argtypes, close_handle.restype = [wintypes.HANDLE], wintypes.BOOL
    descriptor = None
    try:
        # The held handle was opened on the leaf itself, without following a
        # reparse point. Inspect that same object before converting ownership.
        class AttributeTagInfo(ctypes.Structure):
            _fields_ = [("attributes", wintypes.DWORD), ("tag", wintypes.DWORD)]

        information = AttributeTagInfo()
        get_information = kernel32.GetFileInformationByHandleEx
        get_information.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        get_information.restype = wintypes.BOOL
        if not get_information(handle, 9, ctypes.byref(information), ctypes.sizeof(information)):
            raise ctypes.WinError(ctypes.get_last_error())
        if information.attributes & (0x400 | 0x10):
            raise ValueError("custody image is a reparse point or directory")
        descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
        handle = None  # The CRT descriptor now owns the native handle.
        source = os.fdopen(descriptor, "rb")
        descriptor = None  # The file object now owns the CRT descriptor.
        return source
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if handle is not None:
            close_handle(handle)


def pin_custody(path: Path, expected_sha256: str):
    source = open_custody_pin(path)
    try:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= artifact_verifier.MAX_FILE_BYTES:
            raise ValueError("custody image type or size differs")
        digest = hashlib.sha256()
        while chunk := source.read(64 * 1024):
            digest.update(chunk)
        if digest.hexdigest() != expected_sha256:
            raise ValueError("the explicitly pinned contributor custody binary differs")
        return source
    except BaseException:
        source.close()
        raise


def stop_owned(process, errors: list[str]) -> int | None:
    """One bounded attempt against the retained Popen handle; never raises a cleanup error."""
    try:
        code = process.poll()
        if code is not None:
            return code
    except PROCESS_ERRORS as error:
        errors.append("owned custody poll failed: " + type(error).__name__)
    try:
        process.kill()
    except PROCESS_ERRORS as error:
        errors.append("owned custody kill failed: " + type(error).__name__)
    try:
        return process.wait(timeout=5)
    except PROCESS_ERRORS as error:
        errors.append("owned custody wait failed: " + type(error).__name__)
        return None


def close_finished_stream(stream, reader, errors: list[str]) -> None:
    # A live reader owns its synchronous pipe. Closing it here could block.
    if stream is not None and not reader.is_alive():
        try:
            stream.close()
        except (OSError, ValueError) as error:
            errors.append("custody stream close failed: " + type(error).__name__)


def valid_boundary_diagnostic(value: object) -> bool:
    """Accept only the fixed child's closed, path-free canonicalization report."""
    if value == "FIXED_CANONICALIZE result=ok\n":
        return True
    if not isinstance(value, str):
        return False
    match = re.fullmatch(
        r"FIXED_CANONICALIZE win32=5\n"
        r"FIXED_CANON_OPEN result=ok\n"
        r"FIXED_CANON_NORMALIZED_DOS win32=5\n"
        r"FIXED_CANON_OPENED_DOS win32=5\n"
        r"FIXED_CANON_NORMALIZED_NT result=ok length=([1-9][0-9]{0,4})\n"
        r"FIXED_CANON_CLOSE result=ok\n"
        r"FIXED_CANON_SEAL_READ result=ok match=true\n",
        value,
    )
    # The Rust diagnostic uses a fixed 32,768-unit path buffer. Its success
    # length excludes NUL and must fit that buffer. These compatibility labels
    # never replace the child's separate environment and boundary assertions.
    return match is not None and int(match[1]) < 32768


def valid_observations(
    record: object, receipt: dict, mode: str = "loader-only", local_receipt_sha256: str | None = None
) -> bool:
    if mode not in {
        "loader-only",
        "standalone-boundary",
        "dll-startup-only",
        "claude-version-only",
        "claude-create-control-only",
    }:
        return False
    contract = artifact_verifier.artifact_contract(mode)
    boundary = mode == "standalone-boundary"
    dll = mode == "dll-startup-only"
    control = mode == "claude-create-control-only"
    claude = mode in {"claude-version-only", "claude-create-control-only"}
    checks = (
        CONTROL_CHECKS
        if control
        else CLAUDE_CHECKS
        if claude
        else DLL_CHECKS
        if dll
        else BOUNDARY_CHECKS
        if boundary
        else CHECKS
    )
    if not isinstance(record, dict):
        return False
    if not {"binary_sha256", "build_commit", "build_run", "combined_lock_sha256", "artifact_id"} <= receipt.keys():
        return False
    if any(
        record.get(name) != value or type(record.get(name)) is not type(value)
        for name, value in {
            "passed": True,
            "production_certification": False,
            "scope": contract["scope"],
            "variant": contract["variant"],
            "mode": mode,
            "exit_code": 0,
            "outer_job_active_before_final_cleanup": 0,
            "outer_job_empty": True,
            "assigned_before_resume": True,
            "binary_sha256": receipt["binary_sha256"],
            "build_commit": receipt["build_commit"],
            "build_run": receipt["build_run"],
            "combined_lock_sha256": receipt["combined_lock_sha256"],
            "artifact_id": receipt["artifact_id"],
        }.items()
    ):
        return False
    if control and (
        receipt.get("probe_cargo_features") != ["fixed-claude-create-control"]
        or record.get("probe_cargo_features") != ["fixed-claude-create-control"]
    ):
        return False
    if claude:
        if not isinstance(local_receipt_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", local_receipt_sha256) is None:
            return False
        if any(
            record.get(key) != value or type(record.get(key)) is not type(value)
            for key, value in {
                "local_image_sha256": CLAUDE_IMAGE_SHA256,
                "local_image_size": CLAUDE_IMAGE_SIZE,
                "local_image_product_version": CLAUDE_PRODUCT_VERSION,
                "local_image_review_receipt_sha256": local_receipt_sha256,
            }.items()
        ):
            return False
    elif local_receipt_sha256 is not None:
        return False
    try:
        lines = [json.loads(line) for line in record["stdout"].splitlines() if line]
    except (KeyError, ValueError, TypeError, AttributeError):
        return False
    if control:
        if (
            not lines
            or not isinstance(lines[0], dict)
            or lines[0] != CONTROL_INPUT_EVIDENCE
            or any(type(lines[0].get(key)) is not type(value) for key, value in CONTROL_INPUT_EVIDENCE.items())
        ):
            return False
        lines = lines[1:]
    dll_all_loaded = False
    if dll:
        # A returned nonzero loader error is an observation, not compatibility
        # success. Missing START/return, abnormal exit, timeout or cleanup still
        # fails this fixed measurement contract.
        if len(lines) != 4 or not all(isinstance(line, dict) for line in lines):
            return False
        dll_all_loaded = True
        for observation, label in zip(lines[:-1], DLL_CASES, strict=True):
            output = observation.get("stdout")
            if not isinstance(output, str):
                return False
            loaded = output == f"FIXED_DLL_START:{label}\nFIXED_DLL_RETURN:{label}:loaded\n"
            if not loaded:
                match = re.fullmatch(
                    rf"FIXED_DLL_START:{label}\nFIXED_DLL_RETURN:{label}:error:([1-9][0-9]{{0,9}})\n", output
                )
                if match is None or int(match[1]) > 0xFFFFFFFF:
                    return False
                dll_all_loaded = False
            if (
                observation
                != {
                    "case": "dll-" + label,
                    "outcome": "Exited(0)",
                    "direct_handle_signaled": True,
                    "stdout": output,
                    "stderr": "",
                }
                or observation.get("direct_handle_signaled") is not True
            ):
                return False
    claude_output = None
    if claude:
        if len(lines) != 2 or not all(isinstance(line, dict) for line in lines):
            return False
        claude_output = lines[0].get("stdout")
        if not isinstance(claude_output, str) or claude_output not in {
            CLAUDE_VERSION_OUTPUT + "\n",
            CLAUDE_VERSION_OUTPUT + "\r\n",
        }:
            return False
    expected_cases = (
        [("claude-version", "Exited(0)", claude_output)]
        if claude
        else (
            [
                ("argv", "Exited(0)", "FIXED_ARGV_PASS\n"),
                ("boundary", "Exited(0)", "FIXED_NATIVE_ENV_BINDING_PASS\nFIXED_BOUNDARIES_PASS\n"),
                ("exit23", "Exited(23)", "FIXED_EXIT23_STARTED\n"),
                ("timeout", "TimedOut", "FIXED_TIMEOUT_STARTED\n"),
            ]
            if boundary
            else [("loader", "Exited(23)", "FIXED_PSEC_LOADER_STARTED\n")]
        )
    )
    if not dll:
        if len(lines) != len(expected_cases) + 1 or not all(isinstance(line, dict) for line in lines):
            return False
        for observation, (case, outcome, marker) in zip(lines[:-1], expected_cases, strict=True):
            diagnostic = ""
            if boundary and case == "boundary":
                diagnostic = observation.get("stderr")
                if not valid_boundary_diagnostic(diagnostic):
                    return False
            if observation.get("direct_handle_signaled") is not True or observation != {
                "case": case,
                "outcome": outcome,
                "direct_handle_signaled": True,
                "stdout": marker,
                "stderr": diagnostic,
            }:
                return False
    final = lines[-1]
    return (
        final.get("axis_commit") == artifact_verifier.AXIS_COMMIT
        and final.get("mxc_commit") == artifact_verifier.MXC_COMMIT
        and final.get("translation_contract") == "fixed-axis-hard-block-to-mxc-typed-1.0.0"
        and final.get("backend") == ("uncontained_fixed_create_control" if control else "native_windows_psec_only")
        and final.get("production_qualification") is False
        and final.get("loader_only_diagnostic") is (mode == "loader-only")
        and (not boundary or final.get("psec_attribute_attached") is True)
        and (
            not claude
            or (
                final.get("claude_version_only") is (not control)
                and final.get("dll_startup_only_diagnostic") is False
                and (
                    not control
                    or (
                        final.get("claude_create_control_only") is True
                        and final.get("psec_attribute_attached") is False
                        and final.get("control_reference_plan_executed") is False
                    )
                )
            )
        )
        and (
            not dll
            or (
                final.get("dll_startup_only_diagnostic") is True
                and final.get("dll_initialization_all_succeeded") is dll_all_loaded
            )
        )
        and isinstance(final.get("checks"), list)
        and all(isinstance(check, str) for check in final["checks"])
        and len(final["checks"]) == len(checks)
        and set(final["checks"]) == checks
    )


class Capture:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.data = bytearray()
        self.overflow = False
        self.error: str | None = None

    def drain(self, source) -> None:
        try:
            while chunk := source.read(4096):
                with self.lock:
                    if len(self.data) + len(chunk) <= OUTPUT_BOUND:
                        self.data.extend(chunk)
                    else:
                        self.overflow = True
        except OSError as error:
            with self.lock:
                self.error = type(error).__name__

    def snapshot(self) -> tuple[bytes, bool, str | None]:
        with self.lock:
            return bytes(self.data), self.overflow, self.error


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--loader-only", action="store_true")
    modes.add_argument("--standalone-boundary", action="store_true")
    modes.add_argument("--dll-startup-only", action="store_true")
    modes.add_argument("--claude-version-only", action="store_true")
    modes.add_argument("--claude-create-control-only", action="store_true")
    parser.add_argument("--custody", type=Path, required=True)
    parser.add_argument("--custody-sha256", type=artifact_verifier.digest_argument, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--receipt-sha256", type=artifact_verifier.digest_argument, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--local-image-receipt", type=Path)
    parser.add_argument("--local-image-receipt-sha256", type=artifact_verifier.digest_argument)
    args = parser.parse_args()
    if args.claude_version_only or args.claude_create_control_only:
        if args.local_image_receipt is None or args.local_image_receipt_sha256 is None:
            parser.error("the fixed Claude case requires both independent local-image receipt pins")
    elif args.local_image_receipt is not None or args.local_image_receipt_sha256 is not None:
        parser.error("local-image receipt options require the fixed Claude case")
    mode = (
        "claude-create-control-only"
        if args.claude_create_control_only
        else "claude-version-only"
        if args.claude_version_only
        else "dll-startup-only"
        if args.dll_startup_only
        else "standalone-boundary"
        if args.standalone_boundary
        else "loader-only"
    )
    contract = artifact_verifier.artifact_contract(mode)
    if sys.platform != "win32" or platform.machine().lower() not in {"amd64", "x86_64"}:
        raise RuntimeError("live probe requires native Windows x86_64")
    custody = args.custody.absolute()
    receipt_path = args.receipt.absolute()
    receipt_raw = artifact_verifier.ordinary_file(receipt_path, 64 * 1024)
    if hashlib.sha256(receipt_raw).hexdigest() != args.receipt_sha256:
        raise ValueError("the independently pinned verification receipt differs")
    receipt = json.loads(receipt_raw)
    if (
        not isinstance(receipt, dict)
        or receipt.get("verified") is not True
        or receipt.get("execution_performed") is not False
        or receipt.get("variant") != contract["variant"]
        or receipt.get("scope") != contract["scope"]
    ):
        raise ValueError("an independently verified non-executing receipt is required")
    if args.claude_create_control_only and receipt.get("probe_cargo_features") != ["fixed-claude-create-control"]:
        raise ValueError("the separate uncontained build feature receipt is required")
    if args.claude_version_only or args.claude_create_control_only:
        local_raw = artifact_verifier.ordinary_file(args.local_image_receipt.absolute(), 64 * 1024)
        if hashlib.sha256(local_raw).hexdigest() != args.local_image_receipt_sha256:
            raise ValueError("the independently reviewed local-image receipt differs")
    evidence = args.evidence.absolute()
    evidence.mkdir(mode=0o700)
    for name in ("wrapper-home", "wrapper-tmp"):
        (evidence / name).mkdir(mode=0o700)
    system = os.environ.get("SYSTEMROOT", "")
    if not Path(system).is_absolute():
        raise ValueError("native Windows system directory is missing")
    environment = {
        "SYSTEMROOT": system,
        "WINDIR": system,
        "HOME": str(evidence / "wrapper-home"),
        "USERPROFILE": str(evidence / "wrapper-home"),
        "TEMP": str(evidence / "wrapper-tmp"),
        "TMP": str(evidence / "wrapper-tmp"),
    }
    command = [
        str(custody),
        "-" + mode,
        "-receipt",
        str(receipt_path),
        "-receipt-sha256",
        args.receipt_sha256,
        "-case-root",
        str(evidence / "psec-headless-01"),
    ]
    if args.claude_version_only or args.claude_create_control_only:
        command += [
            "-local-image-receipt",
            str(args.local_image_receipt.absolute()),
            "-local-image-receipt-sha256",
            args.local_image_receipt_sha256,
        ]
    output, diagnostic = Capture(), Capture()
    started = time.monotonic()
    deadline = False
    errors = []
    exit_code = None
    process = None
    readers = []
    custody_pin = pin_custody(custody, args.custody_sha256)
    try:
        process = subprocess.Popen(
            command,
            cwd=evidence,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            bufsize=0,
        )
        assert process.stdout is not None and process.stderr is not None
        for capture, stream in [(output, process.stdout), (diagnostic, process.stderr)]:
            reader = threading.Thread(target=capture.drain, args=(stream,), daemon=True)
            reader.start()
            readers.append(reader)
        try:
            exit_code = process.wait(timeout=55)
        except subprocess.TimeoutExpired:
            deadline = True
            # This Popen retains the exact helper process handle. Killing it
            # closes its non-inherited Job handle; never signal an inferred PID.
            exit_code = stop_owned(process, errors)
    except PROCESS_ERRORS as error:
        errors.append(type(error).__name__)
        if process is not None:
            exit_code = stop_owned(process, errors)
    finally:
        for reader in readers:
            reader.join(timeout=2)
            if reader.is_alive():
                errors.append("bounded custody reader did not stop")
        if process is not None:
            for stream, reader in zip((process.stdout, process.stderr), readers, strict=False):
                # Do not block closing a stream concurrently owned by a stuck
                # reader. That path is a failed qualification, with daemon
                # readers and handles reclaimed when this CLI process exits.
                close_finished_stream(stream, reader, errors)
        try:
            custody_pin.close()
        except (OSError, ValueError) as error:
            errors.append("custody image pin close failed: " + type(error).__name__)
    output_bytes, output_overflow, output_error = output.snapshot()
    diagnostic_bytes, diagnostic_overflow, diagnostic_error = diagnostic.snapshot()
    for name, data in [("custody-stdout.json", output_bytes), ("custody-stderr.txt", diagnostic_bytes)]:
        with (evidence / name).open("xb") as destination:
            destination.write(data)
    result = None
    try:
        result = json.loads(output_bytes)
    except (ValueError, UnicodeDecodeError):
        errors.append("custody JSON missing or invalid")
    fixtures = sorted(str(path) for path in (evidence / "psec-headless-01" / "tmp").glob("dc-axis-windows-psec-*"))
    passed = (
        not errors
        and not deadline
        and exit_code == 0
        and not output_overflow
        and not diagnostic_overflow
        and output_error is None
        and diagnostic_error is None
        and not fixtures
        and valid_observations(result, receipt, mode, args.local_image_receipt_sha256)
    )
    record = {
        "passed": passed,
        "command": command,
        "exit_code": exit_code,
        "errors": errors,
        "outer_deadline": deadline,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "custody_sha256": args.custody_sha256,
        "receipt_sha256": args.receipt_sha256,
        "output_overflow": output_overflow or diagnostic_overflow,
        "output_read_errors": [output_error, diagnostic_error],
        "retained_owned_fixtures": fixtures,
        "observations": result,
        "production_or_claude_qualification": False,
        "local_image_review_receipt_sha256": args.local_image_receipt_sha256,
        "fixed_claude_version_smoke_only": args.claude_version_only,
        "fixed_uncontained_create_control_only": args.claude_create_control_only,
        "mode": mode,
        "scope": (
            "UNCONTAINED fixed signed Claude --version creation control; PSEC object constructed but not attached; "
            "exact constructed input equality except security-environment attribute; "
            "eight private values requested; "
            "realized Claude environment unverified; no filesystem/network/UI policy enforcement "
            "or runtime qualification"
            if args.claude_create_control_only
            else "fixed independently reviewed signed Claude --version only; eight private values requested, "
            "realized Claude environment unverified; offline/default UI configured; "
            "no authentication, model, hooks, terminal or general Claude/runtime qualification"
            if args.claude_version_only
            else "fixed local canaries and literal argv only; loopback endpoints only; "
            "no terminal, credentials, model or general resource audit"
            if mode == "standalone-boundary"
            else "fixed std-only loader diagnostic; marker, exit23 and owned custody only; "
            "no filesystem/network boundary, terminal, proxy, secrets, model or general resource audit"
        ),
    }
    with (evidence / "live-result.json").open("x", encoding="utf-8") as destination:
        destination.write(json.dumps(record, indent=2) + "\n")
    print(json.dumps(record, indent=2))
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
