# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""The provider identity needs the install to come from the registry.

Published bytes are not enough: an install record that names a file, a link or
another address is judged by the ordinary scan. A release the registry cannot
confirm because it is unreachable is admitted by the ordinary profiles on its
install record, with a visible warning, and never by strict.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import shutil
import urllib.error

import pytest
from defenseclaw.scanner.plugin_scanner import vendor_identity
from defenseclaw.scanner.plugin_scanner.scanner import scan_plugin
from defenseclaw.scanner.plugin_scanner.types import PluginScanOptions

from tests.environment import requires_symlink_privilege
from tests.test_openclaw_provider_install_shape import (
    PROVIDER,
    VERSION,
    _archive,
    _installed_by_openclaw,
    _new_release_install,
    _published_provider,
    _serve_release,
    _write,
)
from tests.test_openclaw_vendor_provider import _openclaw_peer

PACKAGE_KEY = "node_modules/" + PROVIDER
INTEGRITY = "sha512-" + base64.b64encode(hashlib.sha512(b"archive").digest()).decode()


def _archive_address(version: str) -> str:
    return f"https://registry.npmjs.org/{PROVIDER}/-/amazon-bedrock-provider-{version}.tgz"


def _high(path, profile: str) -> set[str]:
    findings = scan_plugin(str(path), PluginScanOptions(policy=profile)).findings
    return {f.rule_id for f in findings if f.severity in ("HIGH", "CRITICAL")}


def _rules(path, profile: str) -> set[str]:
    return {f.rule_id for f in scan_plugin(str(path), PluginScanOptions(policy=profile)).findings}


def _pinned_npm_install(tmp_path, monkeypatch):
    """A pinned release installed into an npm project: (project, package folder)."""

    published = tmp_path / "published"
    _published_provider(published)
    monkeypatch.setitem(
        vendor_identity.VENDOR_DIGESTS, (PROVIDER, VERSION),
        vendor_identity._package_digest(str(published)),
    )
    project = tmp_path / "project"
    installed = project / PACKAGE_KEY
    _installed_by_openclaw(published, installed, _openclaw_peer(tmp_path))
    return project, installed


def _edit_manifest(folder, change) -> None:
    manifest = json.loads((folder / "package.json").read_text(encoding="utf-8"))
    change(manifest)
    _write(folder / "package.json", json.dumps(manifest))


def _lock(path, entry, *, key: str = PACKAGE_KEY) -> None:
    _write(path, json.dumps({"lockfileVersion": 3, "packages": {key: entry}}))


PROTECTED_AND_OTHER_SOURCES = {
    "file-in-private-folder": {"version": VERSION, "resolved": "file:/home/user/.ssh/provider.tgz"},
    "file-relative": {"version": VERSION, "resolved": "file:../provider.tgz"},
    "linked-folder": {"version": VERSION, "resolved": "../provider", "link": True},
    "other-address": {"version": VERSION, "resolved": "https://example.invalid/provider.tgz"},
    "plain-http": {"version": VERSION, "resolved": _archive_address(VERSION).replace("https", "http")},
    "address-with-credentials": {
        "version": VERSION,
        "resolved": _archive_address(VERSION).replace("https://", "https://user:key@"),
    },
    "other-package-archive": {
        "version": VERSION,
        "resolved": "https://registry.npmjs.org/other/-/other-" + VERSION + ".tgz",
    },
    "version-is-a-source": {"version": "file:../provider"},
    "git-source": {"version": VERSION, "resolved": "git+ssh://example.invalid/provider.git#abc"},
}

LOCK_PLACES = {
    "parent-lock": lambda project, folder: project / "package-lock.json",
    "parent-hidden-lock": lambda project, folder: project / "node_modules" / ".package-lock.json",
    "parent-shrinkwrap": lambda project, folder: project / "npm-shrinkwrap.json",
    "own-hidden-lock": lambda project, folder: folder / "node_modules" / ".package-lock.json",
}


@requires_symlink_privilege
def test_install_record_that_names_another_source_gives_no_identity(tmp_path, monkeypatch) -> None:
    project, installed = _pinned_npm_install(tmp_path, monkeypatch)
    assert vendor_identity.inspect_official_provider_tree(str(installed)) is not None

    for source_name, entry in PROTECTED_AND_OTHER_SOURCES.items():
        for place_name, place in LOCK_PLACES.items():
            label = f"{source_name} in {place_name}"
            root = tmp_path / "case" / source_name / place_name
            shutil.copytree(project, root, symlinks=True)
            target = root / PACKAGE_KEY
            _lock(place(root, target), entry)
            assert vendor_identity.inspect_official_provider_tree(str(target)) is None, label
            for profile in ("default", "permissive", "strict"):
                assert "SRC-EXEC" in _high(target, profile), f"{label} {profile}"


@requires_symlink_privilege
def test_manifest_install_metadata_that_names_another_source_gives_no_identity(
    tmp_path, monkeypatch,
) -> None:
    project, installed = _pinned_npm_install(tmp_path, monkeypatch)
    cases = {
        "resolved-file": {"_resolved": "file:/home/user/.ssh/provider.tgz"},
        "resolved-address": {"_resolved": "https://example.invalid/provider.tgz"},
        "from-address": {"_from": "https://example.invalid/provider.tgz"},
        "from-file": {"_from": PROVIDER + "@file:../provider"},
        "from-alias": {"_from": PROVIDER + "@npm:other@1.0.0"},
        "requested-git": {"_requested": {"type": "git"}},
        "requested-directory": {"_requested": {"type": "directory"}},
        "requested-not-a-record": {"_requested": "git"},
        "requested-version-with-file-raw": {"_requested": {
            "type": "version", "raw": "file:/home/user/.ssh/provider.tgz",
        }},
        "requested-version-with-file-fetch": {"_requested": {
            "type": "version", "fetchSpec": "file:/home/user/.ssh/provider.tgz",
        }},
        "requested-range-with-path-save": {"_requested": {
            "type": "range", "saveSpec": "../provider", "registry": True,
        }},
        "requested-tag-with-address": {"_requested": {
            "type": "tag", "rawSpec": "https://example.invalid/provider.tgz",
        }},
    }
    for name, fields in cases.items():
        root = tmp_path / "case" / name
        shutil.copytree(project, root, symlinks=True)
        _edit_manifest(root / PACKAGE_KEY, lambda m, fields=fields: m.update(fields))
        assert vendor_identity.inspect_official_provider_tree(str(root / PACKAGE_KEY)) is None, name
        assert "SRC-EXEC" in _high(root / PACKAGE_KEY, "default"), name


@requires_symlink_privilege
def test_install_records_that_name_the_registry_keep_the_identity(tmp_path, monkeypatch) -> None:
    project, installed = _pinned_npm_install(tmp_path, monkeypatch)
    registry = {"version": VERSION, "resolved": _archive_address(VERSION), "integrity": INTEGRITY}
    cases = {
        "registry-archive": registry,
        "archive-with-hash": {**registry, "resolved": _archive_address(VERSION) + "#" + "a" * 40},
        "mirror-archive": {
            **registry,
            "resolved": f"https://mirror.example/api/npm/team/{PROVIDER}/-/amazon-bedrock-provider-{VERSION}.tgz",
        },
        "no-address-recorded": {"version": VERSION},
    }
    for name, entry in cases.items():
        for place_name, place in LOCK_PLACES.items():
            root = tmp_path / "case" / name / place_name
            shutil.copytree(project, root, symlinks=True)
            target = root / PACKAGE_KEY
            _lock(place(root, target), entry)
            label = f"{name} in {place_name}"
            assert vendor_identity.inspect_official_provider_tree(str(target)) is not None, label
            for profile in ("default", "permissive"):
                assert _high(target, profile) == set(), f"{label} {profile}"
            assert "SRC-EXEC" in _high(target, "strict"), label

    # A record about another package is not about this one.
    root = tmp_path / "case" / "other-package"
    shutil.copytree(project, root, symlinks=True)
    _lock(root / "package-lock.json", {"version": "1.0.0", "resolved": "file:../other"},
          key="node_modules/other")
    assert vendor_identity.inspect_official_provider_tree(str(root / PACKAGE_KEY)) is not None

    root = tmp_path / "case" / "manifest-metadata"
    shutil.copytree(project, root, symlinks=True)
    _edit_manifest(root / PACKAGE_KEY, lambda m: m.update(
        _resolved=_archive_address(VERSION), _from=PROVIDER + "@" + VERSION,
        _requested={"type": "version"},
    ))
    assert vendor_identity.inspect_official_provider_tree(str(root / PACKAGE_KEY)) is not None

    # The whole npm 6 record of an ordinary registry install.
    root = tmp_path / "case" / "manifest-metadata-full"
    shutil.copytree(project, root, symlinks=True)
    _edit_manifest(root / PACKAGE_KEY, lambda m: m.update(
        _resolved=_archive_address(VERSION), _from=PROVIDER + "@" + VERSION,
        _requested={
            "type": "version", "registry": True, "where": "/home/user/project",
            "raw": PROVIDER + "@" + VERSION, "name": PROVIDER,
            "escapedName": "@openclaw%2famazon-bedrock-provider",
            "rawSpec": VERSION, "saveSpec": None, "fetchSpec": VERSION,
        },
    ))
    assert vendor_identity.inspect_official_provider_tree(str(root / PACKAGE_KEY)) is not None


REGISTRY_RECORD = {"version": VERSION, "resolved": _archive_address(VERSION), "integrity": INTEGRITY}


def _root_lock(project, root_entry, **others) -> None:
    _write(project / "package-lock.json", json.dumps({
        "lockfileVersion": 3,
        "packages": {"": root_entry, PACKAGE_KEY: REGISTRY_RECORD, **others},
    }))


@requires_symlink_privilege
def test_dependency_spec_that_asks_for_another_source_gives_no_identity(
    tmp_path, monkeypatch,
) -> None:
    """The root of the project can ask for a file while the entry claims the registry."""

    project, installed = _pinned_npm_install(tmp_path, monkeypatch)
    cases = {
        "file": "file:/home/user/.ssh/provider.tgz",
        "link": "link:../provider",
        "path": "../provider",
        "address": "https://example.invalid/provider.tgz",
        "git": "git+ssh://example.invalid/provider.git",
        "workspace": "workspace:*",
        "alias-of-another-package": "npm:other@1.0.0",
    }
    for field in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        for label, spec in cases.items():
            root = tmp_path / "case" / field / label
            shutil.copytree(project, root, symlinks=True)
            _root_lock(root, {field: {PROVIDER: spec}})
            target = root / PACKAGE_KEY
            assert vendor_identity.inspect_official_provider_tree(str(target)) is None, f"{field} {label}"
            for profile in ("default", "permissive", "strict"):
                assert "SRC-EXEC" in _high(target, profile), f"{field} {label} {profile}"


@requires_symlink_privilege
def test_dependency_spec_that_asks_the_registry_keeps_the_identity(tmp_path, monkeypatch) -> None:
    project, installed = _pinned_npm_install(tmp_path, monkeypatch)
    for label, spec in {
        "range": "^2026.10.0", "exact": VERSION, "tag": "latest", "any": "*", "empty": "",
        "same-package-alias": f"npm:{PROVIDER}@{VERSION}",
    }.items():
        root = tmp_path / "case" / label
        shutil.copytree(project, root, symlinks=True)
        _root_lock(root, {"dependencies": {PROVIDER: spec}})
        target = root / PACKAGE_KEY
        assert vendor_identity.inspect_official_provider_tree(str(target)) is not None, label
        for profile in ("default", "permissive"):
            assert _high(target, profile) == set(), f"{label} {profile}"


@requires_symlink_privilege
def test_another_copy_of_the_package_elsewhere_in_the_project_is_another_install(
    tmp_path, monkeypatch,
) -> None:
    """A sibling that carries its own local copy does not change the top-level install."""

    project, installed = _pinned_npm_install(tmp_path, monkeypatch)
    nested = "node_modules/sibling/node_modules/" + PROVIDER
    _write(project / "package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {
        "": {"dependencies": {PROVIDER: VERSION, "sibling": "1.0.0"}},
        PACKAGE_KEY: REGISTRY_RECORD,
        "node_modules/sibling": {
            "version": "1.0.0", "dependencies": {PROVIDER: "file:../local-provider.tgz"},
        },
        nested: {"version": VERSION, "resolved": "file:../local-provider.tgz"},
    }}))
    assert vendor_identity.inspect_official_provider_tree(str(installed)) is not None
    for profile in ("default", "permissive"):
        assert _high(installed, profile) == set(), profile
    assert "SRC-EXEC" in _high(installed, "strict")

    # The same record is decisive for the copy it describes.
    moved = project / nested
    moved.parent.mkdir(parents=True)
    shutil.copytree(installed, moved, symlinks=True)
    assert vendor_identity.inspect_official_provider_tree(str(moved)) is None
    for profile in ("default", "permissive", "strict"):
        assert "SRC-EXEC" in _high(moved, profile), profile

    # A v1 lock is read by the same path: the nested copy is the sibling's.
    _write(project / "package-lock.json", json.dumps({"lockfileVersion": 1, "dependencies": {
        PROVIDER: {"version": VERSION, "resolved": _archive_address(VERSION)},
        "sibling": {"version": "1.0.0", "dependencies": {
            PROVIDER: {"version": VERSION, "resolved": "file:../local-provider.tgz"},
        }},
    }}))
    assert vendor_identity.inspect_official_provider_tree(str(installed)) is not None
    assert vendor_identity.inspect_official_provider_tree(str(moved)) is None


@requires_symlink_privilege
def test_release_with_its_own_development_dependencies_is_identified(tmp_path, monkeypatch) -> None:
    """The installer line is removed on both sides; the release own entries stay in the digest."""

    published = tmp_path / "published"
    _published_provider(published)
    _edit_manifest(published, lambda m: m.update(devDependencies={"typescript": "5.0.0"}))
    monkeypatch.setitem(
        vendor_identity.VENDOR_DIGESTS, (PROVIDER, VERSION),
        vendor_identity._package_digest(str(published)),
    )
    peer = _openclaw_peer(tmp_path)
    installed = tmp_path / "installed"
    _installed_by_openclaw(published, installed, peer)
    installer_line = {"typescript": "5.0.0", "@openclaw/plugin-sdk": "workspace:*"}
    _edit_manifest(installed, lambda m: m.update(devDependencies=installer_line))
    assert vendor_identity.inspect_official_provider_tree(str(installed)) is not None
    assert _high(installed, "default") == set()

    cases = {
        "other-version": {"typescript": "6.0.0", "@openclaw/plugin-sdk": "workspace:*"},
        "added-entry": {**installer_line, "helper": "1.0.0"},
        "added-source": {**installer_line, "helper": "file:../../.ssh"},
        "removed-entry": {"@openclaw/plugin-sdk": "workspace:*"},
        "other-installer-value": {"typescript": "5.0.0", "@openclaw/plugin-sdk": "file:../sdk"},
    }
    for name, development in cases.items():
        root = tmp_path / name
        shutil.copytree(installed, root, symlinks=True)
        _edit_manifest(root, lambda m, development=development: m.update(devDependencies=development))
        assert vendor_identity.inspect_official_provider_tree(str(root)) is None, name

    # The same release installed without the installer line is the same package.
    plain = tmp_path / "plain"
    shutil.copytree(installed, plain, symlinks=True)
    _edit_manifest(plain, lambda m: m.update(devDependencies={"typescript": "5.0.0"}))
    assert vendor_identity.inspect_official_provider_tree(str(plain)) is not None


@requires_symlink_privilege
def test_unpublished_development_dependencies_do_not_block_an_unpinned_release(
    tmp_path, monkeypatch,
) -> None:
    version = "2026.99.3"
    published, installed = _new_release_install(tmp_path, version)
    _edit_manifest(published, lambda m: m.update(devDependencies={"typescript": "5.0.0"}))
    _edit_manifest(installed, lambda m: m.update(devDependencies={
        "typescript": "5.0.0", "@openclaw/plugin-sdk": "workspace:*",
    }))
    _serve_release(monkeypatch, version, _archive(published))
    assert vendor_identity.inspect_official_provider_tree(str(installed)) is not None
    for profile in ("default", "permissive"):
        assert _high(installed, profile) == set(), profile
    assert "SRC-EXEC" in _high(installed, "strict")


def _unpinned_npm_install(tmp_path, version: str, entry):
    """An unpinned release in an npm project that records ``entry`` for it."""

    published, installed = _new_release_install(tmp_path, version)
    project = tmp_path / "project"
    target = project / PACKAGE_KEY
    shutil.copytree(installed, target, symlinks=True)
    if entry is not None:
        _lock(project / "package-lock.json", entry)
    return published, target


def _registry_outage(error):
    def get(url, limit):
        raise error

    return get


REGISTRY_ENTRY = {
    "version": "2026.99.4", "resolved": _archive_address("2026.99.4"), "integrity": INTEGRITY,
}
OUTAGES = {
    "unreachable": OSError("network is unreachable"),
    "timeout": TimeoutError("timed out"),
    "dns": urllib.error.URLError("name resolution failed"),
    "server-error": urllib.error.HTTPError("https://registry.npmjs.org/x", 503, "unavailable", {}, None),
    "rate-limited": urllib.error.HTTPError("https://registry.npmjs.org/x", 429, "slow down", {}, None),
    "cut-off": http.client.IncompleteRead(b""),
}


@requires_symlink_privilege
@pytest.mark.parametrize("outage", sorted(OUTAGES))
def test_registry_outage_admits_a_recorded_release_with_a_warning(
    tmp_path, monkeypatch, outage,
) -> None:
    version = "2026.99.4"
    _, target = _unpinned_npm_install(tmp_path, version, REGISTRY_ENTRY)
    monkeypatch.setattr(vendor_identity, "_registry_get", _registry_outage(OUTAGES[outage]))

    identity = vendor_identity.inspect_official_provider_tree(str(target))
    assert identity is not None and identity.unverified
    for profile in ("default", "permissive"):
        assert _high(target, profile) == set(), profile
        warning = [
            f for f in scan_plugin(str(target), PluginScanOptions(policy=profile)).findings
            if f.rule_id == "VENDOR-REGISTRY-UNVERIFIED"
        ]
        assert [f.severity for f in warning] == ["MEDIUM"], profile
    # Strict does not rely on the record: the ordinary scan applies.
    assert "SRC-EXEC" in _high(target, "strict")
    assert "VENDOR-REGISTRY-UNVERIFIED" not in _rules(target, "strict")


PROTECTED_READS = {
    "named-directly": "require('node:fs').readFileSync('/home/user/.codex/auth.json');",
    "through-a-known-value": (
        "const protectedFile = '/home/user/.codex/auth.json'; "
        "require('node:fs').readFileSync(protectedFile);"
    ),
}


@requires_symlink_privilege
@pytest.mark.parametrize("read", sorted(PROTECTED_READS))
@pytest.mark.parametrize("record", ["recorded", "any-well-formed-integrity"])
def test_registry_outage_does_not_admit_edited_code_that_names_a_protected_file(
    tmp_path, monkeypatch, read, record,
) -> None:
    """The record is a claim of the install; protected-file rules outrank it in every profile."""

    version = "2026.99.4"
    entry = REGISTRY_ENTRY if record == "recorded" else {
        **REGISTRY_ENTRY,
        "integrity": "sha512-" + base64.b64encode(hashlib.sha512(b"other").digest()).decode(),
    }
    _, target = _unpinned_npm_install(tmp_path, version, entry)
    monkeypatch.setattr(vendor_identity, "_registry_get", _registry_outage(OSError("offline")))

    # Unmodified, the same tree is admitted with the warning.
    assert vendor_identity.inspect_official_provider_tree(str(target)).unverified
    assert _high(target, "default") == set()
    assert "VENDOR-REGISTRY-UNVERIFIED" in _rules(target, "default")

    with open(target / "dist" / "index.js", "a", encoding="utf-8") as stream:
        stream.write("\n" + PROTECTED_READS[read] + "\n")
    for profile in ("default", "permissive", "strict"):
        assert "CRED-CODEX-AUTH" in _high(target, profile), profile
        assert "VENDOR-REGISTRY-UNVERIFIED" not in _rules(target, profile), profile


@requires_symlink_privilege
def test_registry_outage_does_not_admit_a_release_the_record_does_not_support(
    tmp_path, monkeypatch,
) -> None:
    version = "2026.99.4"
    cases = {
        "no-record": None,
        "record-of-another-version": {**REGISTRY_ENTRY, "version": "2026.99.3"},
        "archive-of-another-version": {**REGISTRY_ENTRY, "resolved": _archive_address("2026.99.3")},
        "no-integrity": {k: v for k, v in REGISTRY_ENTRY.items() if k != "integrity"},
        "weak-integrity": {**REGISTRY_ENTRY, "integrity": "sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAA="},
        "short-integrity": {**REGISTRY_ENTRY, "integrity": "sha512-AAAA"},
        "no-address": {k: v for k, v in REGISTRY_ENTRY.items() if k != "resolved"},
        "file-source": {**REGISTRY_ENTRY, "resolved": "file:/home/user/.ssh/provider.tgz"},
        "linked-source": {**REGISTRY_ENTRY, "link": True},
    }
    for name, entry in cases.items():
        root = tmp_path / name
        root.mkdir()
        _, target = _unpinned_npm_install(root, version, entry)
        monkeypatch.setattr(vendor_identity, "_registry_get", _registry_outage(OSError("offline")))
        vendor_identity._registry_digests.clear()
        assert vendor_identity.inspect_official_provider_tree(str(target)) is None, name
        for profile in ("default", "permissive", "strict"):
            assert "SRC-EXEC" in _high(target, profile), f"{name} {profile}"


@requires_symlink_privilege
def test_registry_answer_that_is_wrong_is_not_an_outage(tmp_path, monkeypatch) -> None:
    """Only an outage falls back to the record; an answer that refutes the tree does not."""

    version = "2026.99.4"
    published, target = _unpinned_npm_install(tmp_path, version, REGISTRY_ENTRY)

    not_found = urllib.error.HTTPError("https://registry.npmjs.org/x", 404, "no", {}, None)
    monkeypatch.setattr(vendor_identity, "_registry_get", _registry_outage(not_found))
    assert vendor_identity.inspect_official_provider_tree(str(target)) is None

    # The registry archive differs from the installed tree (the tree was edited).
    vendor_identity._registry_digests.clear()
    _serve_release(monkeypatch, version, _archive(published, extra={"dist/extra.js": b"1"}))
    assert vendor_identity.inspect_official_provider_tree(str(target)) is None
    assert "SRC-EXEC" in _high(target, "default")

    # The same tree is identified when the registry confirms it.
    vendor_identity._registry_digests.clear()
    _serve_release(monkeypatch, version, _archive(published))
    identity = vendor_identity.inspect_official_provider_tree(str(target))
    assert identity is not None and not identity.unverified


@requires_symlink_privilege
def test_pinned_release_is_verified_without_the_registry(tmp_path, monkeypatch) -> None:
    project, installed = _pinned_npm_install(tmp_path, monkeypatch)
    monkeypatch.setattr(vendor_identity, "_registry_get", _registry_outage(OSError("offline")))
    identity = vendor_identity.inspect_official_provider_tree(str(installed))
    assert identity is not None and not identity.unverified
    assert "VENDOR-REGISTRY-UNVERIFIED" not in _rules(installed, "default")
