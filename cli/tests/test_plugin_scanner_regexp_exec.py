# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""SRC-EXEC reports command execution, not RegExp.prototype.exec (GAP-0610)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from defenseclaw.scanner.plugin_scanner.scanner import scan_plugin
from defenseclaw.scanner.plugin_scanner.types import PluginScanOptions

from tests.environment import requires_symlink_privilege

PROFILES = ("default", "permissive", "strict")

# The matching code of the OpenClaw Amazon Bedrock provider, as published.
PROVIDER_SOURCE = """\
const BEDROCK_REGION_RE = /bedrock-runtime\\.([a-z0-9-]+)\\.amazonaws\\.com/;
const bedrockRegionRe = new RegExp("^[a-z]{2}-[a-z]+-\\\\d$");
export function family(normalized) {
  return /(?:opus-(?:5|4-6))(?:$|-)/.exec(normalized)?.[0];
}
export function arnId(profile) {
  return /foundation-model\\/(.+)$/.exec(profile.models?.[0]?.modelArn ?? "")?.[1];
}
export function region(url) {
  bedrockRegionRe.lastIndex = 0;
  return url?.trim() ? BEDROCK_REGION_RE.exec(url)?.[1] : bedrockRegionRe.exec(url)?.[0];
}
"""


def _plugin(root, source: str, version: str = "2026.11.2") -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text(json.dumps({
        "name": "@openclaw/amazon-bedrock-provider", "version": version,
        "type": "module", "main": "index.js",
    }), encoding="utf-8")
    (root / "index.js").write_text(source, encoding="utf-8")


def _high(root, profile: str) -> set[str]:
    return {
        f.rule_id for f in scan_plugin(str(root), PluginScanOptions(policy=profile)).findings
        if f.severity in ("HIGH", "CRITICAL")
    }


@pytest.mark.parametrize("profile", PROFILES)
def test_r109_g610_pattern_matching_is_not_command_execution(tmp_path, profile) -> None:
    """Benign twin: a provider release no local pin lists is admitted by its own code."""

    _plugin(tmp_path / "provider", PROVIDER_SOURCE)
    assert _high(tmp_path / "provider", profile) == set()


@requires_symlink_privilege
@pytest.mark.parametrize("profile", PROFILES)
def test_r109_g610_provider_with_peer_link_is_admitted_for_any_release(tmp_path, profile) -> None:
    """The installer layout (hoisted dependencies, linked host package) is not a finding."""

    peer = tmp_path / "host" / "node_modules" / "openclaw"
    peer.mkdir(parents=True)
    (peer / "package.json").write_text(json.dumps({"name": "openclaw"}), encoding="utf-8")
    for version in ("2026.10.9", "2026.10.10", "2026.11.1", "2026.11.2", "2027.1.1"):
        root = tmp_path / version
        _plugin(root, PROVIDER_SOURCE, version)
        (root / "node_modules" / "dep").mkdir(parents=True)
        (root / "node_modules" / "dep" / "index.js").write_text("module.exports = 1;\n", encoding="utf-8")
        (root / "node_modules" / "openclaw").symlink_to(peer, target_is_directory=True)
        assert _high(root, profile) == set(), version


BENIGN = {
    "parenthesized-literal": "(/x/).exec(text);\n",
    "construction": "RegExp(\"x\").exec(text);\nnew RegExp(\"x\", \"g\").exec(text);\n",
    "parenthesized-construction": "(new RegExp(\"x\")).exec(text);\n",
    "name-used-by-a-logger": "const RE = /x/;\nconsole.log(\"pattern\", RE);\nlogger.debug(RE);\nRE.exec(text);\n",
    "name-from-construction": "const RE = RegExp(\"x\");\nRE.test(text);\nRE.exec(text);\n",
    "optional-call": "const RE = /x/;\nRE?.exec(text);\n",
    "literal-in-expression": "return (a, /x/g).exec(text) ?? (/y/).exec(text);\n",
    "unrelated-string-reading-exec": "const message = \"exec\";\n/x/.exec(text);\n",
    "unrelated-key-and-quoted-key-named-exec": "const names = { exec: 1, \"exec\": 2 };\n/x/.exec(text);\n",
    "instanceof-regexp": "if (value instanceof RegExp) { value.test(text); }\n/x/.exec(text);\n",
    "own-prototype-methods": (
        "function Parser() {}\nParser.prototype.parse = function (t) { return /x/.exec(t); };\n"
    ),
}


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize("case", sorted(BENIGN))
def test_r109_g610_ordinary_pattern_matching_spellings_are_not_findings(tmp_path, profile, case) -> None:
    _plugin(tmp_path / "provider", BENIGN[case])
    assert _high(tmp_path / "provider", profile) == set(), case


HOSTILE = {
    "bare-call": "exec(command);\n",
    "shell-receiver": "const shell = require(`node:child_process`);\nshell.exec(command);\n",
    "module-call": "require(`child_process`).exec(command);\n",
    "unknown-property-receiver": "options.pattern.exec(command);\n",
    "call-result-receiver": "load().exec(command);\n",
    "literal-and-real-call-on-one-line": "const m = /a/.exec(x); exec(command);\n",
    "regexp-name-rebound": "let RE = /a/;\nRE = require(`child_process`);\nRE.exec(command);\n",
    "regexp-name-shadowed-by-parameter": (
        "const RE = /a/;\nfunction run(RE) { RE.exec(command); }\n"
        "run(require(`child_process`));\n"
    ),
    "regexp-name-declared-twice": (
        "const RE = /a/;\n{ const RE = require(`child_process`); RE.exec(command); }\n"
    ),
    "regexp-name-passed-on": "const RE = /a/;\nuse(RE);\nRE.exec(command);\n",
    "division-not-a-literal": "const q = total /count/g.exec(command);\n",
    "name-without-regexp-binding": "const RE = load();\nRE.exec(command);\n",
    "instance-exec-replaced": (
        "const RE = /a/;\nRE.exec = require(`node:child_process`).exec;\nRE.exec(command);\n"
    ),
    "prototype-exec-replaced": (
        "RegExp.prototype.exec = require(`node:child_process`).exec;\n/a/.exec(command);\n"
    ),
    "exec-replaced-by-index": (
        "const RE = /a/;\nRE[`exec`] = require(`node:child_process`).exec;\nRE.exec(command);\n"
    ),
    "exec-replaced-by-define": (
        "const cp = require(`node:child_process`);\n"
        "Object.defineProperty(RegExp.prototype, `exec`, { value: cp.exec });\n/a/.exec(command);\n"
    ),
    "exec-copied-onto-the-name": (
        "const RE = /a/;\nObject.assign(RE, { exec: require(`node:child_process`).exec });\n"
        "RE.exec(command);\n"
    ),
    "prototype-replaced-through-an-index": (
        "const key = [`ex`, `ec`].join(``);\nRegExp.prototype[key] = require(`node:child_process`).exec;\n"
        "/a/.exec(command);\n"
    ),
    "regexp-rebound": (
        "const RegExp = require(`node:child_process`);\nRegExp(`a`).exec(command);\n"
    ),
    "call-result-of-a-construction": "make(RegExp(`a`)).exec(command);\n",
    "parenthesized-module": "(require(`node:child_process`)).exec(command);\n",
    "parenthesized-name": "const cp = require(`node:child_process`);\n(cp).exec(command);\n",
    "regexp-shadowed-by-a-parameter-and-called": (
        "function run(RegExp) { return RegExp(`a`).exec(command); }\n"
        "run(() => require(`node:child_process`));\n"
    ),
    "prototype-merged-by-a-computed-key": (
        "const cp = require(`node:child_process`);\nconst key = [`ex`, `ec`].join(``);\n"
        "Object.assign(RegExp.prototype, { [key]: cp.exec });\n/a/.exec(command);\n"
    ),
    "prototype-reached-through-the-constructor": (
        "const cp = require(`node:child_process`);\nconst key = [`ex`, `ec`].join(``);\n"
        "Object.assign(/b/.constructor.prototype, { [key]: cp.exec });\n/a/.exec(command);\n"
    ),
    "prototype-kept-in-a-name": (
        "const cp = require(`node:child_process`);\nconst proto = Object.getPrototypeOf(/b/);\n"
        "proto.exec = cp.exec;\n/a/.exec(command);\n"
    ),
    "regexp-kept-in-an-object": (
        "const cp = require(`node:child_process`);\nconst holder = { kind: RegExp };\n"
        "Object.assign(holder.kind.prototype, { exec: cp.exec });\n/a/.exec(command);\n"
    ),
}


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize("case", sorted(HOSTILE))
def test_r109_g610_command_execution_stays_reported(tmp_path, profile, case) -> None:
    _plugin(tmp_path / "provider", PROVIDER_SOURCE + HOSTILE[case])
    assert "SRC-EXEC" in _high(tmp_path / "provider", profile), case


@pytest.mark.parametrize("profile", PROFILES)
def test_r109_g610_a_regexp_name_is_judged_per_file(tmp_path, profile) -> None:
    _plugin(tmp_path / "provider", PROVIDER_SOURCE)
    (tmp_path / "provider" / "other.js").write_text("BEDROCK_REGION_RE.exec(command);\n", encoding="utf-8")
    assert "SRC-EXEC" in _high(tmp_path / "provider", profile)


@pytest.mark.parametrize("profile", PROFILES)
def test_r109_g610_another_file_can_change_what_a_pattern_reaches(tmp_path, profile) -> None:
    """One file that changes the built-in object voids the proof in every file."""

    root = tmp_path / "provider"
    _plugin(root, PROVIDER_SOURCE + "/a/.exec(command);\n")
    assert _high(root, profile) == set()
    (root / "mutator.js").write_text(
        "RegExp.prototype.exec = require(`node:child_process`).exec;\n", encoding="utf-8",
    )
    assert "SRC-EXEC" in _high(root, profile)


@pytest.mark.parametrize("profile", PROFILES)
def test_r109_g610_typescript_uses_of_the_regexp_type_are_not_findings(tmp_path, profile) -> None:
    root = tmp_path / "provider"
    root.mkdir()
    (root / "package.json").write_text(json.dumps({
        "name": "ordinary-plugin", "version": "1.0.0", "main": "index.ts",
    }), encoding="utf-8")
    (root / "index.ts").write_text(
        "const BODY: RegExp = /a(b)/;\n"
        "export function pick(rules: RegExp[], map: Map<string, RegExp>, text: string) {\n"
        "  return BODY.exec(text)?.[1] ?? /c/.exec(text);\n}\n",
        encoding="utf-8",
    )
    assert _high(root, profile) == set()
    (root / "index.ts").write_text(
        "const cp = require(`node:child_process`);\nconst holder = { kind: RegExp };\n"
        "Object.assign(holder.kind.prototype, { exec: cp.exec });\n/a/.exec(command);\n",
        encoding="utf-8",
    )
    assert "SRC-EXEC" in _high(root, profile)


def _peer(tmp_path, destination) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "package.json").write_text(json.dumps({"name": "openclaw"}), encoding="utf-8")
    root = tmp_path / "provider"
    _plugin(root, PROVIDER_SOURCE)
    (root / "node_modules").mkdir()
    return root


@requires_symlink_privilege
@pytest.mark.parametrize("profile", PROFILES)
def test_r109_g610_a_peer_link_into_protected_state_is_blocked(tmp_path, profile) -> None:
    """Direct, aliased and nested links are judged where they resolve; an ordinary peer is not."""

    protected = tmp_path / "home" / ".ssh" / "openclaw"
    root = _peer(tmp_path, protected)
    (root / "node_modules" / "openclaw").symlink_to(protected, target_is_directory=True)
    assert "STRUCT-SYMLINK-ESCAPE" in _high(root, profile)

    alias = tmp_path / "alias"
    alias.symlink_to(protected.parent, target_is_directory=True)
    (root / "node_modules" / "openclaw").unlink()
    (root / "node_modules" / "openclaw").symlink_to(alias / "openclaw", target_is_directory=True)
    assert "STRUCT-SYMLINK-ESCAPE" in _high(root, profile)

    (root / "node_modules" / "openclaw").unlink()
    (root / "node_modules" / "dep" / "node_modules").mkdir(parents=True)
    (root / "node_modules" / "dep" / "node_modules" / "openclaw").symlink_to(
        protected, target_is_directory=True,
    )
    assert "STRUCT-SYMLINK-ESCAPE" in _high(root, profile)

    ordinary = tmp_path / "host" / "node_modules" / "openclaw"
    ordinary.mkdir(parents=True)
    (ordinary / "package.json").write_text(json.dumps({"name": "openclaw"}), encoding="utf-8")
    (root / "node_modules" / "dep" / "node_modules" / "openclaw").unlink()
    (root / "node_modules" / "openclaw").symlink_to(ordinary, target_is_directory=True)
    assert _high(root, profile) == set()


@requires_symlink_privilege
def test_r109_g610_a_peer_link_into_the_state_folder_is_blocked(tmp_path) -> None:
    state = tmp_path / "state"
    root = _peer(tmp_path, state / "openclaw")
    (root / "node_modules" / "openclaw").symlink_to(state / "openclaw", target_is_directory=True)
    findings = scan_plugin(str(root), PluginScanOptions(data_dir=str(state))).findings
    assert "STRUCT-SYMLINK-ESCAPE" in {f.rule_id for f in findings if f.severity == "HIGH"}


@pytest.mark.parametrize("profile", PROFILES)
def test_r109_g610_a_local_source_in_protected_state_is_blocked(tmp_path, profile) -> None:
    root = tmp_path / "provider"
    _plugin(root, PROVIDER_SOURCE)
    manifest = json.loads((root / "package.json").read_text(encoding="utf-8"))
    manifest["dependencies"] = {"helper": "file:../home/.ssh/helper"}
    (root / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
    assert "DEP-LOCAL-FILE" in _high(root, profile)

    manifest["dependencies"] = {"helper": "file:../sibling"}
    (root / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
    assert "DEP-LOCAL-FILE" not in _high(root, profile)


@pytest.mark.parametrize("profile", PROFILES)
def test_r109_g610_a_local_source_in_the_configured_state_folder_is_blocked(tmp_path, profile) -> None:
    state = tmp_path / "state"
    (state / "private").mkdir(parents=True)
    root = tmp_path / "provider"
    _plugin(root, PROVIDER_SOURCE)
    manifest = json.loads((root / "package.json").read_text(encoding="utf-8"))
    manifest["dependencies"] = {"helper": "file:../state/private"}
    (root / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
    findings = scan_plugin(str(root), PluginScanOptions(policy=profile, data_dir=str(state))).findings
    assert "DEP-LOCAL-FILE" in {f.rule_id for f in findings if f.severity == "HIGH"}
    findings = scan_plugin(str(root), PluginScanOptions(policy=profile)).findings
    assert "DEP-LOCAL-FILE" not in {f.rule_id for f in findings if f.severity == "HIGH"}


@requires_symlink_privilege
@pytest.mark.parametrize("profile", PROFILES)
def test_r109_g610_a_dependency_folder_that_is_itself_a_link_is_judged_inside(tmp_path, profile) -> None:
    """An ordinary link to a dependency folder is fine; a protected link inside it is not."""

    protected = tmp_path / "home" / ".ssh" / "secret"
    protected.mkdir(parents=True)
    shared = tmp_path / "shared-dependencies"
    (shared / "dep").mkdir(parents=True)
    root = tmp_path / "provider"
    _plugin(root, PROVIDER_SOURCE)
    (root / "node_modules").symlink_to(shared, target_is_directory=True)
    assert _high(root, profile) == set()
    (shared / "dep").rmdir()
    (shared / "dep").symlink_to(protected, target_is_directory=True)
    assert "STRUCT-SYMLINK-ESCAPE" in _high(root, profile)


@requires_symlink_privilege
def test_r109_g610_secure_client_keeps_its_ordinary_scan(tmp_path) -> None:
    """Secure Client options (vendor identity off) see neither the pattern proof nor the new links."""

    options = PluginScanOptions(disable_vendor_identity=True)
    root = tmp_path / "pattern"
    _plugin(root, PROVIDER_SOURCE)
    assert "SRC-EXEC" in {f.rule_id for f in scan_plugin(str(root), options).findings if f.severity == "HIGH"}

    protected = tmp_path / "home" / ".ssh" / "openclaw"
    linked = _peer(tmp_path, protected)
    (linked / "node_modules" / "openclaw").symlink_to(protected, target_is_directory=True)
    (linked / "index.js").write_text("export const one = 1;\n", encoding="utf-8")
    assert "STRUCT-SYMLINK-ESCAPE" not in {f.rule_id for f in scan_plugin(str(linked), options).findings}
