# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Pin the enterprise removal, exit-code and detection claims in the docs."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "docs-site/content/docs"


def page(name: str) -> str:
    return " ".join((ROOT / name).read_text(encoding="utf-8").split())


def test_cli_uninstall_row_keeps_sandboxes() -> None:
    text = page("reference/commands/cli.mdx")
    assert "Each account keeps `~/.defenseclaw` and its sandboxes." in text


def test_dnf_row_explains_kept_sandbox_state() -> None:
    text = page("enterprise/install/linux.mdx")
    start = text.index("| `dnf remove defenseclaw-enterprise` |")
    dnf = text[start : start + 600]
    assert "sandbox store and key that an account's kept sandboxes leave behind" in dnf


def test_linux_removal_keeps_administrator_policies() -> None:
    assert "Your policies in `/etc/defenseclaw/policies` stay; `--purge` removes them." in page(
        "enterprise/mdm/index.mdx"
    )


def test_restore_notice_lifetime_is_explained() -> None:
    text = page("troubleshooting/enterprise/index.mdx")
    assert "The warning clears at the next successful guardian refresh." in text
    assert "`settings_lost`" in text


def test_rpm_architecture_is_checked_before_install() -> None:
    text = page("troubleshooting/enterprise/index.mdx")
    assert "`.deb` and for an RPM, before installation" in text
    assert "reaches `rpm -U`" not in text


def test_standalone_setup_refusals_are_1639() -> None:
    mdm = page("enterprise/mdm/index.mdx")
    assert "`invalid_arguments` and exit `1639`" in mdm
    assert "`/ensure BOGUS=1 JSON=1` still returns the JSON refusal" in mdm
    assert "Setup stops reading arguments at the first unknown one" not in mdm
    for name in ("enterprise/mdm/configmgr.mdx", "enterprise/mdm/workspace-one.mdx"):
        text = page(name)
        assert "Setup stops with exit `1639` and names the file" in text


def test_macos_detection_documents_busy_and_unknown() -> None:
    mdm = page("enterprise/mdm/index.mdx")
    assert "`unknown` (not run as root) or `busy`" in mdm
    assert "`busy`" in page("enterprise/mdm/jamf.mdx")
    assert "about 92 KB" in page("enterprise/mdm/intune/macos.mdx")


def test_configmgr_config_change_checks_the_config_hash() -> None:
    text = page("enterprise/mdm/configmgr.mdx")
    assert "### Change the config" in text
    assert "config_sha256" in text


def test_group_names_match_without_regard_to_case() -> None:
    text = page("enterprise/identity/reference.mdx")
    assert "without regard to case" in text
    assert "exactly, including case" not in text
