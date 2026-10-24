# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Operator configuration recipes name the actual layout, scope and result."""

import json
import re
from pathlib import Path

import pytest

DOCS = Path(__file__).resolve().parents[2] / 'docs-site/content/docs'


def flat(name):
    return ' '.join((DOCS / name).read_text().split())


@pytest.mark.parametrize('name', ['reference/configuration/index.mdx', 'reference/configuration/paths.mdx'])
def test_windows_layout_distinguishes_setup_from_powershell_install(name):
    text = flat(name)
    assert 'install.ps1' in text and '`.venv`' in text
    assert 'Setup package' in text and 'embedded runtime' in text


def test_status_json_modes_distinguish_user_and_enterprise_shapes():
    text = flat('reference/configuration/fail-modes.mdx')
    assert '`connectors[].fail_mode.effective`' in text
    assert '`name`' in text
    assert '`connectors.<id>.effective_hook_fail_mode`' in text
    assert 'standalone enterprise' in text


def test_ancestor_strictness_has_no_windows_only_qualifier():
    text = flat('enterprise/plan/threat-model.mdx')
    assert '`DEFENSECLAW_MANAGED_TRUST_STRICT_ANCESTORS` (Windows)' not in text
    assert 'strict ancestor checks on Linux, macOS and Windows' in text


@pytest.mark.parametrize('name', ['enterprise/identity/authentication.mdx', 'enterprise/identity/reference.mdx'])
def test_managed_windows_validation_names_the_machine_config(name):
    text = flat(name)
    assert 'config validate --config' in text
    assert 'C:\\ProgramData\\Cisco\\DefenseClaw\\etc\\config.yaml' in text
    assert 'ensure' in text


@pytest.mark.parametrize('name', ['enterprise/configure/reference.mdx', 'enterprise/configure/ai-defense-key.mdx'])
def test_disabled_ai_defense_reference_allows_key_removal(name):
    text = flat(name).split('Remove the key', 1)[1]
    assert 'enabled AI Defense inspection' in text
    assert 'disabled inspection does not prevent removal' in text


def test_manual_downgrade_regenerates_connectors_before_start():
    text = flat('appendix/migrate-v9.mdx').split('go back by hand', 1)[1].split('If you do not have a matching', 1)[0]
    regenerate = text.index('Regenerate every connector')
    start = text.index('Start the 0.8.x gateway')
    assert regenerate < start
    assert "matching pre-upgrade `.env`" in text
    assert 'defenseclaw agent discover --refresh' in text[regenerate:start]
    assert 'contract lock' in text[start:]
    assert 'fail mode' in text[start:]


def test_manual_downgrade_keeps_the_restored_config():
    # 0.8.x quickstart and init keep only the named connector and reset the
    # scanner mode and the judge, so they must not run on a restored config.
    raw = (DOCS / 'appendix/migrate-v9.mdx').read_text()
    section = raw.split('go back by hand', 1)[1].split('If you do not have a matching', 1)[0]
    commands = ' '.join(re.findall(r'```(?:bash|sh|powershell)?\n(.*?)```', section, re.S))
    assert 'agent discover --refresh' in commands
    assert 'quickstart' not in commands and 'defenseclaw init' not in commands
    text = ' '.join(section.split())
    assert 'Do not run `quickstart` or `init` here' in text
    assert 'scanner mode' in text and 'judge' in text
    assert 'does not change it' in text
    assert 'still the restored file' in text


def test_manual_downgrade_sends_windows_codex_to_rollback():
    text = flat('appendix/migrate-v9.mdx').split('go back by hand', 1)[1][:600]
    assert 'Windows with the Codex connector' in text and '`defenseclaw rollback`' in text


def test_windows_enrollment_wait_starts_after_agent_first_start():
    text = flat("enterprise/configure/enrollment.mdx")
    assert "account is signed in and the agent is installed" in text
    assert "Claude Code must also start once" in text
    assert "five-minute wait starts then" in text


def test_windows_setup_result_lists_changes_only_when_it_wrote_something():
    # GAP-0536: a hot config apply, a migration and other writes add a
    # Windows `changes` list; a run that wrote nothing has none.
    text = flat("enterprise/operate/reference.mdx")
    assert "On Linux and macOS the result's `changes` list" in text
    assert "a `changes` list when the run wrote something" in text
    assert "A run that wrote nothing has no `changes` key" in text


ENTERPRISE = DOCS / 'enterprise'
CONTENT = DOCS.parent
# A step, row or heading that tells an administrator how to change the config.
CONFIG_CHANGE_RECIPE = re.compile(
    r'^#{2,4} [^\n]*[Cc]hange the config'
    r'|\*\*(?:Upgrade or |Upgrade, )?[Cc]hange the config'
    r'|^\| Change the config'
    r'|config-only change'
    r'|change the config only through',
    re.MULTILINE,
)
# Words that name signed policy bundles or their deployment. Public docs keep
# only the bundle-mode refusal guidance until the sync service ships: no page,
# navigation entry, heading or link that sends readers to deploy bundles.
BUNDLE_DEPLOYMENT = re.compile(
    r'\b(?:signed|policy|trust)[ -](?:policy )?bundles?\b|\bbundle[ -]mode\b'
    r'|\b(?:a|the|new|next|each) (?:signed )?bundles?\b|dcbundle',
    re.IGNORECASE,
)
LINK = re.compile(r'\[([^\]]*)\]\(([^)\s]*)\)|href=["\']([^"\']*)')


def _config_change_pages():
    for page in sorted(ENTERPRISE.rglob('*.mdx')):
        rel = page.relative_to(DOCS).as_posix()
        # Secure Client computers do not take signed bundles.
        if 'secure-client' in rel:
            continue
        if CONFIG_CHANGE_RECIPE.search(page.read_text()):
            yield rel


def test_no_docs_page_or_navigation_entry_for_signed_bundles():
    files = [p.relative_to(CONTENT).as_posix() for p in CONTENT.rglob('*')
             if p.is_file() and 'bundle' in p.name.lower()]
    assert not files
    for meta in sorted(CONTENT.rglob('meta.json')):
        entries = json.loads(meta.read_text()).get('pages', [])
        assert not [e for e in entries if 'bundle' in e.lower()], meta.relative_to(CONTENT)
    for page in sorted(CONTENT.rglob('*.mdx')):
        text = page.read_text()
        front = text.split('\n---', 1)[0] if text.startswith('---') else ''
        assert not BUNDLE_DEPLOYMENT.search(front), page.relative_to(CONTENT)


def test_no_docs_heading_or_link_sends_readers_to_deploy_bundles():
    offenders = []
    for page in sorted(CONTENT.rglob('*.mdx')):
        rel = page.relative_to(CONTENT).as_posix()
        text = page.read_text()
        offenders += [f'{rel}: {line}' for line in text.splitlines()
                      if re.match(r'#{1,6} ', line) and BUNDLE_DEPLOYMENT.search(line)]
        for match in LINK.finditer(text):
            label, target = match.group(1) or '', match.group(2) or match.group(3) or ''
            internal = not re.match(r'[a-z]+://', target)
            if BUNDLE_DEPLOYMENT.search(label) or (internal and 'bundle' in target.lower()):
                offenders.append(f'{rel}: {" ".join(match.group(0).split())}')
    assert not offenders, '\n'.join(offenders)


def test_config_change_recipes_are_found():
    found = set(_config_change_pages())
    for name in ('enterprise/mdm/intune/windows.mdx', 'enterprise/mdm/intune/linux.mdx',
                 'enterprise/mdm/intune/macos.mdx', 'enterprise/mdm/reference.mdx',
                 'enterprise/operate/lifecycle.mdx', 'enterprise/mdm/configmgr.mdx',
                 'enterprise/mdm/jamf.mdx', 'enterprise/mdm/kandji.mdx'):
        assert name in found


@pytest.mark.parametrize('name', sorted(set(_config_change_pages()) | {
    'enterprise/configure/configuration.mdx',
    'enterprise/operate/reference.mdx',
}))
def test_config_change_recipes_are_qualified_for_bundle_mode(name):
    # Bundle mode refuses a plain config (`bundle_required`) or reverts an edit
    # of the installed file; every config-change recipe says which.
    text = flat(name)
    assert 'bundle mode' in text.lower(), name
    assert '`bundle_required`' in text or 'reverted' in text, name


def test_windows_bundle_mode_upgrade_leaves_the_config_out():
    text = flat('enterprise/mdm/intune/windows.mdx').split('**Upgrade.**', 1)[1].split('**Roll back.**', 1)[0]
    assert 'without `-ConfigPath`' in text
    row = next(line for line in (DOCS / 'enterprise/mdm/intune/windows-reference.mdx').read_text().splitlines()
               if line.startswith('| `-ConfigPath`'))
    assert 'bundle_required' in row


WRAPPERS = ('packaging/mdm/linux/defenseclaw-enterprise.sh', 'packaging/mdm/macos/defenseclaw-enterprise.sh')
# Words that promise a refused run left the device as it was.
NO_CHANGE_CLAIM = re.compile(
    r'nothing (?:else )?(?:changes|changed|is changed|was changed|is installed|was installed|is applied|was applied|is stored)'
    r'|changes nothing|leaves the device (?:as it was|unchanged)|device is unchanged',
    re.IGNORECASE,
)


def _doc_blocks(text):
    # A paragraph, a list item or a table row.
    return re.split(r'\n\s*\n|\n(?=\s*(?:[-*]|\d+\.|\|) )', text)


@pytest.mark.parametrize('wrapper', WRAPPERS)
def test_unix_wrapper_runs_package_and_credential_before_the_bundle_mode_check(wrapper):
    # The MDM reference discloses this order; if the wrapper ever refuses
    # first, the disclosure must change with it.
    main = (DOCS.parents[2] / wrapper).read_text().split('\ndc_main() {', 1)[1]
    package = main.index('dc_install_package')
    secret = main.index('dc_store_secret "$gateway"')
    ensure = main.index('"--config=$ensure_config"')
    assert package < ensure and secret < ensure


def test_bundle_required_refusal_discloses_the_wrapper_steps_that_already_ran():
    text = (DOCS / 'enterprise/mdm/reference.mdx').read_text()
    section = ' '.join(text.split('**Change the config.**', 1)[1].split('\n## ', 1)[0].split())
    assert 'bundle_required' in section
    assert 'the config is not applied' in section
    assert 'deb, rpm or pkg package (`--source`) is installed' in section
    assert 'a credential (`--secret-name`) is stored' in section


def test_no_page_promises_a_bundle_required_refusal_changes_nothing():
    offenders = []
    for page in sorted(DOCS.rglob('*.mdx')):
        for block in _doc_blocks(page.read_text()):
            if 'bundle_required' in block and NO_CHANGE_CLAIM.search(block):
                offenders.append(f'{page.relative_to(DOCS)}: {" ".join(block.split())[:160]}')
    assert not offenders, '\n'.join(offenders)


# An edit of the installed config in bundle mode: Linux and macOS revert it
# (the apply trigger runs ensure with the current bundle's config); Windows
# does not watch config.yaml, so the edit stays until a later Setup /ensure or
# /repair without CONFIG= puts the bundle's config back.
BUNDLE_MODE_CONTEXT = re.compile(r'bundle mode|bundle trust anchors|trust anchors installed', re.IGNORECASE)
EDIT_PUT_BACK = re.compile(
    r'\bedit(?:s|ed)?\b[^.|]*?\b(?:revert\w*|put back|restor\w*|undone|discarded|overwritten)'
    r'|\b(?:revert\w*|put back|restor\w*|undoes|discards|overwrites)\b[^.|]*?\bedit(?:s|ed)?\b',
    re.IGNORECASE,
)
UNIX_SCOPE = re.compile(r'Linux and macOS|Linux, macOS\b(?! and Windows)|Linux or macOS')
WINDOWS_NOT_WATCHED = re.compile(r'Windows (?:does not|doesn\'t) watch|[Nn]othing watches|not watched', re.IGNORECASE)
# Pages that are about Linux or macOS only; their sentences need no OS scope.
UNIX_ONLY_PAGE = re.compile(r'(?:^|/)(?:linux|macos|jamf|kandji)(?:-[a-z]+)?\.mdx$')
SENTENCE_END = re.compile(r'(?<=[.!?])\s+(?=[A-Z*`])')
WINDOWS_RESTORE = DOCS.parents[2] / 'internal/cli/windows_enterprise_bundle_restore.go'


def _bundle_edit_blocks():
    for page in sorted(DOCS.rglob('*.mdx')):
        rel = page.relative_to(DOCS).as_posix()
        for block in _doc_blocks(page.read_text()):
            flat_block = ' '.join(block.split())
            if BUNDLE_MODE_CONTEXT.search(flat_block) and EDIT_PUT_BACK.search(flat_block):
                yield rel, flat_block


def test_bundle_mode_edit_reversion_is_found():
    found = {rel for rel, _ in _bundle_edit_blocks()}
    for name in ('enterprise/operate/reference.mdx', 'enterprise/operate/lifecycle.mdx',
                 'enterprise/configure/configuration.mdx', 'enterprise/mdm/reference.mdx'):
        assert name in found, name


def test_no_page_promises_windows_reverts_a_bundle_mode_edit():
    # The scope must sit in the sentence that promises the reversion, not
    # elsewhere in the paragraph.
    offenders = []
    for rel, block in _bundle_edit_blocks():
        if UNIX_ONLY_PAGE.search(rel):
            continue
        for sentence in SENTENCE_END.split(block):
            if not EDIT_PUT_BACK.search(sentence):
                continue
            if not UNIX_SCOPE.search(sentence):
                offenders.append(f'{rel}: not scoped to Linux and macOS: {sentence[:200]}')
            elif re.search(r'\bWindows\b', sentence) and not WINDOWS_NOT_WATCHED.search(sentence):
                offenders.append(f'{rel}: names Windows without saying nothing watches the file: {sentence[:200]}')
    assert not offenders, '\n'.join(offenders)


def test_windows_bundle_mode_edit_is_restored_by_a_later_ensure_or_repair():
    # The code: Setup /ensure or /repair without CONFIG= (or BUNDLE=,
    # TRUSTANCHORS=, MODE=) on an installed device restores the confirmed
    # bundle config over an edited config.yaml.
    src = WINDOWS_RESTORE.read_text()
    body = src.split('func windowsBundleRestoreRequested(', 1)[1].split('\n}\n', 1)[0]
    assert '(action == "ensure" || action == "repair")' in body
    assert 'strings.TrimSpace(opts.configPath) == ""' in body
    assert 'opts.installedBeforeRun' in body
    blocks = [b for rel, b in _bundle_edit_blocks() if rel == 'enterprise/operate/reference.mdx']
    assert any(WINDOWS_NOT_WATCHED.search(b) and 'Setup `/ensure` or `/repair` without `CONFIG=`' in b
               for b in blocks), blocks


def test_observability_reference_header_version_is_explained(monkeypatch):
    # GAP-0540 with GAP-0617 (w24-setup-perf): the header names the current
    # config_version; the page says which schema family covers it.
    from click.testing import CliRunner
    from defenseclaw.commands import cmd_config
    from defenseclaw.config import CURRENT_CONFIG_VERSION

    root = DOCS.parents[2]
    embedded = (root / 'schemas/config/v8/reference/observability.yaml').read_text()
    monkeypatch.setattr(cmd_config, 'config_v8_reference', lambda fmt, section: embedded)
    res = CliRunner().invoke(cmd_config.config_reference, ['observability'])
    assert res.exit_code == 0, res.output
    family = re.match(r'# (DEFENSECLAW CONFIGURATION v(\d+))', res.output)
    assert family, res.output.splitlines()[0]
    assert int(family[2]) == CURRENT_CONFIG_VERSION
    schema = json.loads((root / 'schemas/config/v8/defenseclaw-config.schema.json').read_text())
    versions = schema['properties']['config_version']['enum']
    assert CURRENT_CONFIG_VERSION in versions
    text = flat('reference/observability/index.mdx')
    assert f'`{family[1]}`' in text
    covers = ' and '.join(str(v) for v in versions)
    assert f'schema family `v8`, which covers `config_version` {covers}' in text
