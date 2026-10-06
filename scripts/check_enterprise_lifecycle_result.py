#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Check one standalone enterprise lifecycle result for the CI install lanes.

The deb, rpm, macOS pkg and Windows Setup install lanes save the JSON result
(packaging/mdm/contract/lifecycle-result.schema.json) of every lifecycle step
and call this script with what that step must have produced. It uses only the
standard library, so it runs on a bare runner, inside a distribution
container and on Windows.

A result passes only without errors and without warnings: `ok` means "no
errors", and the lifecycle reports a failed guardian target, an unverified hook
contract or a rejected config as a warning. Pass --allow-warning for each
warning code the step may report, and --complete to require coverage_complete
and security_complete. A step that must fail (the upgrade gate's rollback
drill) passes --expect-error for each error code it must report instead.
--policy-applied and --config-generation-above check the effective policy the
step reports (the result's optional policy object).

Exit codes: 0 the result matches, 1 it does not, 2 unreadable input or bad
arguments.

Example:
  check_enterprise_lifecycle_result.py result.json --label second-ensure \
      --action ensure --platform linux --noop --installed --version 1.4.0 --ready \
      --complete
"""

# Python 3.6 compatible: RHEL 8 ships only /usr/libexec/platform-python 3.6.

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

SCHEMA_VERSION = 2
REQUIRED_KEYS = (
    "schema_version",
    "ok",
    "action",
    "noop",
    "profile",
    "platform",
    "product_version",
    "installed",
    "transaction_pending",
    "services",
    "readiness",
    "inspection",
    "machine_policy",
    "enrollment",
    "coverage_complete",
    "security_complete",
    "errors",
    "exit_code",
)
READINESS_KEYS = ("gateway", "guardian", "enumerator", "sensor_helper")
BOOLEAN_KEYS = ("ok", "noop", "installed", "transaction_pending", "coverage_complete", "security_complete")
MAX_INPUT_BYTES = 4 << 20


def load_result(path: Path) -> Dict[str, Any]:
    """Read one lifecycle result. The file must hold exactly one JSON object:
    MDMs parse the lifecycle's stdout, so any other text is a defect too."""
    raw = path.read_bytes()
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError(f"{path} is larger than {MAX_INPUT_BYTES} bytes")
    # PowerShell redirection can add a byte order mark; nothing else is allowed.
    text = raw.decode("utf-8-sig")
    if not text.strip():
        raise ValueError(f"{path} is empty")
    document = json.loads(text)
    if not isinstance(document, dict):
        raise ValueError(f"{path} does not hold a JSON object")
    return document


def healthy_service_state(state: str) -> bool:
    # launchd and the Windows SCM report "running"; systemd reports
    # "<ActiveState>/<SubState>", for example "active/running" or, for a
    # timer or path unit, "active/waiting".
    state = state.strip().lower()
    return state == "running" or state.startswith("active/")


def structural_problems(document: Dict[str, Any]) -> List[str]:
    problems = [f"missing key {key!r}" for key in REQUIRED_KEYS if key not in document]
    if problems:
        return problems
    if document["schema_version"] != SCHEMA_VERSION:
        problems.append(f"schema_version is {document['schema_version']!r}, want {SCHEMA_VERSION}")
    for key in BOOLEAN_KEYS:
        if not isinstance(document[key], bool):
            problems.append(f"{key} is not a boolean")
    if not isinstance(document["exit_code"], int) or isinstance(document["exit_code"], bool):
        problems.append("exit_code is not an integer")
    readiness = document["readiness"]
    if not isinstance(readiness, dict) or any(not isinstance(readiness.get(key), bool) for key in READINESS_KEYS):
        problems.append("readiness does not report gateway, guardian, enumerator and sensor_helper")
    if not isinstance(document["services"], list) or any(
        not isinstance(service, dict) or not {"name", "kind", "state", "required"} <= service.keys()
        for service in document["services"]
    ):
        problems.append("services is not a list of service entries")
    if not isinstance(document["machine_policy"], dict):
        problems.append("machine_policy is not an object")
    for key in ("errors", "warnings"):
        messages = document.get(key, [])
        if not isinstance(messages, list) or any(
            not isinstance(message, dict) or not isinstance(message.get("code"), str) for message in messages
        ):
            problems.append(f"{key} is not a list of coded messages")
    return problems


def check(document: Dict[str, Any], args: argparse.Namespace) -> List[str]:
    problems = structural_problems(document)
    if problems:
        return problems
    if args.expect_error:
        if document["ok"] is not False:
            problems.append("ok is true, want a failed step")
        if document["exit_code"] == 0:
            problems.append("exit_code is 0, want a failure")
        reported = {message["code"] for message in document["errors"]}
        for code in args.expect_error:
            if code not in reported:
                problems.append(f"error {code} was not reported")
    else:
        if document["ok"] is not True:
            problems.append("ok is false")
        if document["errors"]:
            problems.append(f"{len(document['errors'])} error(s) reported")
        if document["exit_code"] != 0:
            problems.append(f"exit_code is {document['exit_code']}")
    if document["transaction_pending"]:
        problems.append("a transaction is still pending")
    if document["profile"] != "standalone":
        problems.append(f"profile is {document['profile']!r}, want 'standalone'")
    if args.action and document["action"] != args.action:
        problems.append(f"action is {document['action']!r}, want {args.action!r}")
    if args.platform and document["platform"] != args.platform:
        problems.append(f"platform is {document['platform']!r}, want {args.platform!r}")
    if args.noop and document["noop"] is not True:
        problems.append("noop is false, want a no-op")
    if args.changed and document["noop"] is not False:
        problems.append(f"noop is true ({document.get('noop_reason', '')}), want a change")
    if args.installed and document["installed"] is not True:
        problems.append("installed is false")
    if args.not_installed and document["installed"] is not False:
        problems.append("installed is true, want not installed")
    if args.version and document.get("installed_version") != args.version:
        problems.append(f"installed_version is {document.get('installed_version')!r}, want {args.version!r}")
    if args.product_version and document["product_version"] != args.product_version:
        problems.append(f"product_version is {document['product_version']!r}, want {args.product_version!r}")
    if args.ready:
        for key in READINESS_KEYS:
            if document["readiness"][key] is not True:
                problems.append(f"readiness.{key} is false")
        for service in document["services"]:
            if service["required"] and not healthy_service_state(str(service["state"])):
                problems.append(f"required service {service['name']} is {service['state']!r}")
    if (args.complete or args.coverage_complete) and document["coverage_complete"] is not True:
        problems.append("coverage_complete is false")
    if args.complete and document["security_complete"] is not True:
        problems.append("security_complete is false")
    if args.security_incomplete and document["security_complete"] is not False:
        problems.append("security_complete is true, want false")
    # The warning texts follow the problems in the failure output.
    allowed = set(args.allow_warning)
    # security_incomplete explains a false security_complete, which
    # --complete and --security-incomplete check on their own.
    if document["security_complete"] is False:
        allowed.add("security_incomplete")
    for message in document.get("warnings") or []:
        if message["code"] not in allowed:
            problems.append(f"unexpected warning {message['code']}")
    problems.extend(machine_policy_problems(document["machine_policy"], args))
    problems.extend(policy_problems(document.get("policy"), args))
    return problems


def policy_problems(policy: Any, args: argparse.Namespace) -> List[str]:
    if not args.policy_applied and args.config_generation_above is None:
        return []
    if not isinstance(policy, dict):
        return ["the result reports no policy"]
    problems = []  # type: List[str]
    digest = policy.get("effective_digest")
    generation = policy.get("config_generation")
    if not isinstance(digest, str) or not digest:
        problems.append("policy.effective_digest is missing")
    if not isinstance(generation, int) or isinstance(generation, bool):
        problems.append("policy.config_generation is not an integer")
    elif args.config_generation_above is not None and generation <= args.config_generation_above:
        problems.append(f"policy.config_generation is {generation}, want more than {args.config_generation_above}")
    if args.policy_applied and policy.get("applied") is not True:
        problems.append("policy.applied is false")
    return problems


def machine_policy_problems(policies: Dict[str, Any], args: argparse.Namespace) -> List[str]:
    problems = []  # type: List[str]
    connectors = []  # type: List[str]
    for connector in args.machine_policy_target + args.machine_policy + args.machine_policy_enforced:
        if connector not in connectors:
            connectors.append(connector)
    for connector in connectors:
        entry = policies.get(connector)
        if not isinstance(entry, dict):
            problems.append(f"machine_policy has no {connector} entry")
            continue
        owned = entry.get("owned_entries")
        if connector in args.machine_policy and (not isinstance(owned, int) or isinstance(owned, bool) or owned < 1):
            problems.append(f"machine_policy.{connector} owns no entries")
        if connector in args.machine_policy_enforced and entry.get("effective_lock") != "enforce":
            problems.append(f"machine_policy.{connector}.effective_lock is {entry.get('effective_lock')!r}, want 'enforce'")
    return problems


def describe(document: Dict[str, Any]) -> str:
    return "action={} ok={} noop={} installed={} installed_version={} exit_code={} coverage_complete={} security_complete={}".format(
        document.get("action"),
        document.get("ok"),
        document.get("noop"),
        document.get("installed"),
        document.get("installed_version", ""),
        document.get("exit_code"),
        document.get("coverage_complete"),
        document.get("security_complete"),
    )


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("result", type=Path, help="file holding the lifecycle JSON result")
    parser.add_argument("--label", default="", help="step name to print")
    parser.add_argument("--action", default="", help="required action")
    parser.add_argument("--platform", default="", choices=["", "linux", "darwin", "windows"])
    noop = parser.add_mutually_exclusive_group()
    noop.add_argument("--noop", action="store_true", help="require a no-op")
    noop.add_argument("--changed", action="store_true", help="require a change")
    installed = parser.add_mutually_exclusive_group()
    installed.add_argument("--installed", action="store_true", help="require an installed deployment")
    installed.add_argument("--not-installed", action="store_true", help="require no installed deployment")
    parser.add_argument("--version", default="", help="required installed_version")
    parser.add_argument("--product-version", default="", help="required product_version")
    parser.add_argument("--ready", action="store_true", help="require every readiness check and required service")
    parser.add_argument("--coverage-complete", action="store_true", help="require coverage_complete")
    security = parser.add_mutually_exclusive_group()
    security.add_argument("--complete", action="store_true", help="require coverage_complete and security_complete")
    security.add_argument(
        "--security-incomplete",
        action="store_true",
        help="require security_complete to be false (Windows before the live Claude Code policy proof)",
    )
    parser.add_argument(
        "--expect-error",
        action="append",
        default=[],
        metavar="CODE",
        help="require a failed step (ok false, non-zero exit_code) that reports this error code (repeatable)",
    )
    parser.add_argument(
        "--policy-applied",
        action="store_true",
        help="require the result's policy with an effective_digest, a config_generation and applied true",
    )
    parser.add_argument(
        "--config-generation-above",
        type=int,
        default=None,
        metavar="N",
        help="require policy.config_generation to be greater than N",
    )
    parser.add_argument(
        "--allow-warning",
        action="append",
        default=[],
        metavar="CODE",
        help="accept warnings with this code (repeatable); any other warning fails the step",
    )
    parser.add_argument(
        "--machine-policy",
        action="append",
        default=[],
        metavar="CONNECTOR",
        help="require an owned machine-policy entry for this connector (repeatable)",
    )
    parser.add_argument(
        "--machine-policy-target",
        action="append",
        default=[],
        metavar="CONNECTOR",
        help="require a machine-policy entry, that is an enabled target, for this connector (repeatable)",
    )
    parser.add_argument(
        "--machine-policy-enforced",
        action="append",
        default=[],
        metavar="CONNECTOR",
        help="require this connector's machine policy to report effective_lock 'enforce' (repeatable)",
    )
    args = parser.parse_args(argv)
    label = args.label or args.result.name
    try:
        document = load_result(args.result)
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        print(f"FAIL {label}: cannot read the lifecycle result: {exc}", file=sys.stderr)
        return 2
    problems = check(document, args)
    if not problems:
        print(f"ok   {label}: {describe(document)}")
        return 0
    print(f"FAIL {label}: {describe(document)}", file=sys.stderr)
    for problem in problems:
        print(f"  - {problem}", file=sys.stderr)
    for key in ("errors", "warnings"):
        messages = document.get(key)
        if isinstance(messages, list):
            for message in messages[:20]:
                if isinstance(message, dict):
                    text = str(message.get("message", ""))[:400]
                    print(f"  {key[:-1]}: {message.get('code')}: {text}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
