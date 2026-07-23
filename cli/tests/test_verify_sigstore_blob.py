# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import io
import runpy
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
MODULE = runpy.run_path(str(ROOT / "scripts/verify-sigstore-blob.py"))
VERIFY_WITH_RETRY = MODULE["verify_with_retry"]
WORKFLOW = ROOT / ".github/workflows/release.yaml"
CERTIFICATION_WORKFLOW = ROOT / ".github/workflows/pre-release-certification.yml"


def test_release_workflow_routes_every_sigstore_verification_through_retry() -> None:
    required_steps = {
        WORKFLOW: {
            ("assemble-release-candidate", "Resolve immutable published bridge provenance"),
            ("assemble-release-candidate", "Sign and authenticate public checksum manifest"),
            ("publish-release", "Verify the exact tested candidate"),
        },
        CERTIFICATION_WORKFLOW: {
            ("posix-fresh-install", "Verify and install exact signed bytes"),
            ("posix-upgrade", "Exercise authenticated upgrade baseline"),
            ("windows-fresh-install", "Verify and exercise install.ps1"),
        },
    }

    for workflow_path, pairs in required_steps.items():
        workflow_text = workflow_path.read_text(encoding="utf-8")
        assert "cosign verify-blob" not in workflow_text
        jobs = yaml.safe_load(workflow_text)["jobs"]
        for job_name, step_name in pairs:
            matching_steps = [step for step in jobs[job_name]["steps"] if step.get("name") == step_name]
            assert len(matching_steps) == 1, f"missing unique {job_name} / {step_name}"
            assert "scripts/verify-sigstore-blob.py" in matching_steps[0].get("run", "")


def test_transient_tls_failure_retries_the_exact_mandatory_verification() -> None:
    command = [
        "cosign",
        "verify-blob",
        "--certificate",
        "checksums.txt.pem",
        "--signature",
        "checksums.txt.sig",
        "--certificate-identity",
        "workflow-identity",
        "--certificate-oidc-issuer",
        "issuer",
        "checksums.txt",
    ]
    responses = iter(
        (
            subprocess.CompletedProcess(
                command,
                1,
                stdout=b"first stdout\n",
                stderr=b"tuf: failed to download root: TLS handshake timeout\n",
            ),
            subprocess.CompletedProcess(
                command,
                0,
                stdout=b"Verified OK\n",
                stderr=b"",
            ),
        )
    )
    observed_commands: list[list[str]] = []
    observed_sleeps: list[float] = []
    stdout = io.BytesIO()
    stderr = io.BytesIO()

    def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        observed_commands.append(argv)
        assert kwargs == {
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "check": False,
            "timeout": 120.0,
        }
        return next(responses)

    result = VERIFY_WITH_RETRY(
        command,
        runner=run,
        sleeper=observed_sleeps.append,
        stdout=stdout,
        stderr=stderr,
    )

    assert result == 0
    assert observed_commands == [command, command]
    assert observed_sleeps == [2.0]
    assert stdout.getvalue() == b"first stdout\nVerified OK\n"
    assert b"TLS handshake timeout" in stderr.getvalue()
    assert b"retrying mandatory verification (2/3)" in stderr.getvalue()


def test_permanent_signature_failure_is_not_retried_or_hidden() -> None:
    command = ["cosign", "verify-blob", "checksums.txt"]
    observed_commands: list[list[str]] = []
    observed_sleeps: list[float] = []
    stdout = io.BytesIO()
    stderr = io.BytesIO()

    def run(argv: list[str], **_: object) -> subprocess.CompletedProcess[bytes]:
        observed_commands.append(argv)
        return subprocess.CompletedProcess(
            argv,
            1,
            stdout=b"",
            stderr=b"verification failed: invalid signature\n",
        )

    result = VERIFY_WITH_RETRY(
        command,
        runner=run,
        sleeper=observed_sleeps.append,
        stdout=stdout,
        stderr=stderr,
    )

    assert result == 1
    assert observed_commands == [command]
    assert observed_sleeps == []
    assert stdout.getvalue() == b""
    assert stderr.getvalue() == b"verification failed: invalid signature\n"


def test_transient_failures_remain_fatal_after_three_attempts() -> None:
    command = ["cosign", "verify-blob", "checksums.txt"]
    observed_commands: list[list[str]] = []
    observed_sleeps: list[float] = []
    stderr = io.BytesIO()

    def run(argv: list[str], **_: object) -> subprocess.CompletedProcess[bytes]:
        observed_commands.append(argv)
        return subprocess.CompletedProcess(
            argv,
            1,
            stdout=b"",
            stderr=b"TLS handshake timeout\n",
        )

    result = VERIFY_WITH_RETRY(
        command,
        runner=run,
        sleeper=observed_sleeps.append,
        stdout=io.BytesIO(),
        stderr=stderr,
    )

    assert result == 1
    assert observed_commands == [command, command, command]
    assert observed_sleeps == [2.0, 4.0]
    assert stderr.getvalue().count(b"TLS handshake timeout") == 3
    assert b"retrying mandatory verification (4/3)" not in stderr.getvalue()


def test_timed_out_verification_is_retried_with_a_per_attempt_deadline() -> None:
    command = ["cosign", "verify-blob", "checksums.txt"]
    responses: list[object] = [
        subprocess.TimeoutExpired(
            command,
            timeout=7.0,
            output=b"partial stdout\n",
            stderr=b"partial stderr\n",
        ),
        subprocess.CompletedProcess(command, 0, stdout=b"Verified OK\n", stderr=b""),
    ]
    observed_timeouts: list[float] = []
    observed_sleeps: list[float] = []
    stdout = io.BytesIO()
    stderr = io.BytesIO()

    def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        assert argv == command
        observed_timeouts.append(float(kwargs["timeout"]))
        response = responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        assert isinstance(response, subprocess.CompletedProcess)
        return response

    result = VERIFY_WITH_RETRY(
        command,
        attempt_timeout_seconds=7.0,
        runner=run,
        sleeper=observed_sleeps.append,
        stdout=stdout,
        stderr=stderr,
    )

    assert result == 0
    assert observed_timeouts == [7.0, 7.0]
    assert observed_sleeps == [2.0]
    assert stdout.getvalue() == b"partial stdout\nVerified OK\n"
    assert b"partial stderr\n" in stderr.getvalue()
    assert b"timed out after 7s (attempt 1/3)" in stderr.getvalue()
    assert b"retrying mandatory verification (2/3)" in stderr.getvalue()


def test_repeated_timeouts_remain_fatal_after_bounded_retries() -> None:
    command = ["cosign", "verify-blob", "checksums.txt"]
    observed_sleeps: list[float] = []
    stderr = io.BytesIO()

    def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        raise subprocess.TimeoutExpired(argv, timeout=float(kwargs["timeout"]))

    result = VERIFY_WITH_RETRY(
        command,
        attempt_timeout_seconds=5.0,
        runner=run,
        sleeper=observed_sleeps.append,
        stdout=io.BytesIO(),
        stderr=stderr,
    )

    assert result == 124
    assert observed_sleeps == [2.0, 4.0]
    assert stderr.getvalue().count(b"mandatory verification did not complete") == 3
    assert b"retrying mandatory verification (4/3)" not in stderr.getvalue()


def test_attempt_timeout_must_be_finite_positive_and_bounded() -> None:
    for invalid in (0.0, -1.0, float("nan"), float("inf"), 301.0):
        try:
            VERIFY_WITH_RETRY(["cosign"], attempt_timeout_seconds=invalid)
        except ValueError as exc:
            assert "attempt_timeout_seconds" in str(exc)
        else:
            raise AssertionError(f"timeout {invalid!r} was accepted")
