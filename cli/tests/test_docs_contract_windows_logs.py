# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Pages say Event Log Readers can read only the Windows logs the code lets them read."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs-site/content/docs"
EVENT_LOG_READERS = "S-1-5-32-573"
LIFECYCLE_DIR = "%WINDIR%\\Logs\\DefenseClaw"
WINDOWS_PATH = re.compile(r"(?:[A-Z]:\\|%[A-Z]+%\\)[^`|\s]*")


def _readable_by_event_log_readers():
    """Which Windows log folders grant Event Log Readers read, from the code."""
    lifecycle = re.search(
        r'windowsEnterpriseLogSDDL = "([^"]+)"',
        (ROOT / "internal/cli/windows_enterprise_registration.go").read_text(encoding="utf-8"),
    ).group(1)
    wrapper = re.search(
        r"Initialize-WrapperLog \{.*?SetSecurityDescriptorSddlForm\('([^']+)'\)",
        (ROOT / "packaging/mdm/windows/Invoke-DefenseClawEnterprise.ps1").read_text(encoding="utf-8"),
        re.S,
    ).group(1)
    sensor_helper = re.search(
        r'standaloneSensorHelperLogSDDL = "([^"]+)"',
        (ROOT / "cmd/defenseclaw-sensor-helper/log_standalone_windows.go").read_text(encoding="utf-8"),
    ).group(1)
    module = (ROOT / "packaging/windows/DefenseClawEnterprise.psm1").read_text(encoding="utf-8")
    acl = module[module.index("function New-DefenseClawCanonicalPathAcl") :]
    acl = acl[: acl.index("\nfunction ", 1)]
    # Setup sets the service log folders from the canonical ACL table.
    assert re.search(r"Set-DefenseClawPathAcl -Path \$Layout\.GatewayLogDirectory -Kind", module)
    return {
        LIFECYCLE_DIR: EVENT_LOG_READERS in lifecycle and EVENT_LOG_READERS in wrapper,
        "C:\\ProgramData\\Cisco\\DefenseClaw\\logs": EVENT_LOG_READERS in sensor_helper
        or EVENT_LOG_READERS in acl
        or "Event Log Readers" in acl,
    }


def test_code_grants_event_log_readers_only_the_lifecycle_folder():
    assert _readable_by_event_log_readers() == {
        LIFECYCLE_DIR: True,
        "C:\\ProgramData\\Cisco\\DefenseClaw\\logs": False,
    }


def _blocks(text):
    """Paragraphs and table rows, each with the table just before it (if any)."""
    previous_table = ""
    for block in re.split(r"\n\s*\n", text):
        lines = block.strip().splitlines()
        if lines and all(line.lstrip().startswith("|") for line in lines):
            for row in lines:
                yield row, ""
            previous_table = block
            continue
        yield " ".join(block.split()), previous_table
        previous_table = ""


def test_event_log_readers_claims_name_only_readable_logs():
    # GAP-0588: operations.mdx listed the gateway, guardian and sensor helper
    # logs and then said every log file was readable by Event Log Readers.
    readable = _readable_by_event_log_readers()
    wrong = []
    for page in sorted(DOCS.rglob("*.mdx")):
        for block, table in _blocks(page.read_text(encoding="utf-8").replace("\r\n", "\n")):
            for sentence in re.split(r"(?<=\.)\s+", block):
                if "Event Log Readers" not in sentence:
                    continue
                paths = WINDOWS_PATH.findall(sentence) or WINDOWS_PATH.findall(table)
                for path in paths:
                    folder = next((f for f in readable if path.startswith(f)), path)
                    if not readable.get(folder):
                        wrong.append(f"{page.relative_to(DOCS)}: {path}: {sentence}")
    assert not wrong, wrong


def test_operations_page_says_who_reads_the_service_logs():
    text = " ".join((DOCS / "enterprise/operate/operations.mdx").read_text(encoding="utf-8").split())
    assert (
        "The gateway, guardian and sensor helper logs under `C:\\ProgramData\\Cisco\\DefenseClaw\\logs` are for "
        "SYSTEM and Administrators only"
    ) in text
