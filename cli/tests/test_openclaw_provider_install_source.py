# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""The provider identity needs the install to come from the registry.

Published bytes are not enough: every place an install names its source (the
manifest fields, the lock entry, the spec its owner gives it) must say the
registry. A source of any other kind (a file, a link, a path, a git address, a
URL alias, a list or an object) gives no identity and the ordinary scan applies;
no spec or address is ever read as a file name. A release the registry cannot
confirm because it is unreachable is admitted by the ordinary profiles on its
install record, with a visible warning, and never by strict.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
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


REGISTRY_RECORD = {"version": VERSION, "resolved": _archive_address(VERSION), "integrity": INTEGRITY}


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


@requires_symlink_privilege
def test_manifest_install_metadata_is_not_an_install_record(tmp_path, monkeypatch) -> None:
    """The lock entry of the package is the record. Manifest fields that say the
    registry change nothing on a pinned tree and cannot stand in for the entry
    on an outage; fields that say another source give no identity."""

    project, installed = _pinned_npm_install(tmp_path, monkeypatch)
    spellings = {
        "registry-looking": {
            "_resolved": _archive_address(VERSION), "_from": PROVIDER + "@" + VERSION,
            "_requested": {"type": "version", "scope": "@openclaw", "rawSpec": VERSION},
        },
        "source-looking": {
            "_resolved": "file:../provider", "_from": PROVIDER + "@file:../provider",
            "_requested": {"type": "directory", "raw": "../provider"},
        },
    }
    for name, fields in spellings.items():
        root = tmp_path / "case" / name
        shutil.copytree(project, root, symlinks=True)
        target = root / PACKAGE_KEY
        _edit_manifest(target, lambda m, fields=fields: m.update(fields))
        identity = vendor_identity.inspect_official_provider_tree(str(target))
        assert (identity is not None) == (name == "registry-looking"), name
        if name == "source-looking":
            for profile in ("default", "permissive", "strict"):
                assert "SRC-EXEC" in _high(target, profile), f"{name} {profile}"

        # Nor can they stand in for the entry when the registry cannot be asked.
        outage = tmp_path / "outage" / name
        outage.mkdir(parents=True)
        _, target = _unpinned_npm_install(outage, "2026.99.4", None)
        monkeypatch.setattr(vendor_identity, "_registry_get", _registry_outage(OSError("offline")))
        _edit_manifest(target, lambda m, fields=fields: m.update(fields))
        assert vendor_identity.inspect_official_provider_tree(str(target)) is None, name
        for profile in ("default", "permissive", "strict"):
            assert "SRC-EXEC" in _high(target, profile), f"{name} {profile}"


PROTECTED_SOURCE = "file:/home/user/.ssh/provider.tgz"
MIRROR_ARCHIVE = f"https://mirror.example/api/npm/team/{PROVIDER}/-/amazon-bedrock-provider-{VERSION}.tgz"

# Sources that say the registry, as a spec (a version, a range, a tag, the name
# with one of them, an archive address) ...
REGISTRY_SOURCES = {
    "version": VERSION,
    "range": "^2026.10.0",
    "tag": "latest",
    "name-and-version": PROVIDER + "@" + VERSION,
    "registry-archive": _archive_address(VERSION),
    "mirror-archive": MIRROR_ARCHIVE,
}
# ... and the ones that are an address of an archive of the package.
ARCHIVE_SOURCES = ("registry-archive", "mirror-archive")
# Every other kind of source gets no identity bonus.
OTHER_SOURCES = {
    "file-protected": PROTECTED_SOURCE,
    "file-ordinary": "file:../provider",
    "file-home": "file:~/.ssh/provider.tgz",
    "file-multi-dot-folder": "file:C:/ordinary/.ssh../provider.tgz",
    "file-percent-encoded": "file:/home/user/%2Essh/provider.tgz",
    "link": "link:../provider",
    "relative": "../provider",
    "relative-dot": ".",
    "bare-archive-name": "provider.tgz",
    "absolute": "/home/user/provider.tgz",
    "windows-path": "C:\\Users\\user\\provider.tgz",
    "git": "git+https://example.invalid/provider.git#abc",
    "github-shorthand": "example/provider",
    "url-alias": "https://example.invalid/provider.tgz",
    "plain-http-archive": _archive_address(VERSION).replace("https", "http"),
    "npm-alias-other-package": "npm:other@1.0.0",
    "npm-alias-same-package": f"npm:{PROVIDER}@{VERSION}",
    "named-file": PROVIDER + "@file:../provider",
}
# A dependency whose spec is not a string at all.
STRUCTURED_SOURCES = {
    "object": {"rawSpec": PROTECTED_SOURCE},
    "object-registry-looking": {"rawSpec": VERSION},
    "list": [VERSION, PROTECTED_SOURCE],
    "list-registry-looking": [VERSION],
    "number": 1,
}


def _case(project, tmp_path, label):
    root = tmp_path / "case" / label
    shutil.copytree(project, root, symlinks=True)
    return root, root / PACKAGE_KEY


def _v1_lock(root, entry) -> None:
    _write(root / "package-lock.json", json.dumps({
        "lockfileVersion": 1, "dependencies": {PROVIDER: entry},
    }))


def _v3_root_spec(root, field, spec, *, entry) -> None:
    packages = {"": {field: {PROVIDER: spec}}}
    if entry:
        packages[PACKAGE_KEY] = REGISTRY_RECORD
    _write(root / "package-lock.json", json.dumps({"lockfileVersion": 3, "packages": packages}))


def _v3_nested_owner(root, spec) -> None:
    _write(root / "package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {
        "node_modules/sibling": {"version": "1.0.0", "dependencies": {PROVIDER: spec}},
    }}))


# Where an install names its source. ``archive_only`` places hold an address.
PLACES = {
    "manifest-resolved": (True, lambda t, r, v: _edit_manifest(t, lambda m: m.update(_resolved=v))),
    "manifest-from": (False, lambda t, r, v: _edit_manifest(t, lambda m: m.update(_from=v))),
    "manifest-requested-text": (
        False, lambda t, r, v: _edit_manifest(t, lambda m: m.update(_requested=v))),
    "manifest-requested-object": (False, lambda t, r, v: _edit_manifest(
        t, lambda m: m.update(_requested={"type": "version", "rawSpec": v}))),
    "v1-resolved": (True, lambda t, r, v: _v1_lock(r, {"version": VERSION, "resolved": v})),
    "v1-from": (False, lambda t, r, v: _v1_lock(r, {
        "version": VERSION, "resolved": _archive_address(VERSION), "from": v})),
    "v3-entry-resolved": (True, lambda t, r, v: _lock(
        r / "package-lock.json", {"version": VERSION, "resolved": v})),
    "v3-root-dependency": (False, lambda t, r, v: _v3_root_spec(
        r, "dependencies", v, entry=True)),
    "v3-root-dev-dependency-without-entry": (False, lambda t, r, v: _v3_root_spec(
        r, "devDependencies", v, entry=False)),
}


@requires_symlink_privilege
@pytest.mark.parametrize("place", sorted(PLACES))
def test_only_a_source_that_says_the_registry_gives_an_identity(tmp_path, monkeypatch, place) -> None:
    """One cell per kind of source: the registry is identified, any other kind
    gets exactly the verdict of the ordinary scan."""

    only_addresses, edit = PLACES[place]
    project, installed = _pinned_npm_install(tmp_path, monkeypatch)
    sources = {**{f"registry/{k}": v for k, v in REGISTRY_SOURCES.items()},
               **{f"other/{k}": v for k, v in OTHER_SOURCES.items()}}
    for label, value in sources.items():
        # A registry address and a plain spec are both registry sources, but a
        # field that holds an address holds nothing else.
        registry = label.startswith("registry/") and (
            not only_addresses or label.split("/", 1)[1] in ARCHIVE_SOURCES
        )
        root, target = _case(project, tmp_path, f"{place}-{label.replace('/', '-')}")
        edit(target, root, value)
        identity = vendor_identity.inspect_official_provider_tree(str(target))
        assert (identity is not None) == registry, f"{place} {label}"
        for profile in ("default", "permissive", "strict"):
            high = _high(target, profile)
            if registry and profile != "strict":
                assert high == set(), f"{place} {label} {profile}"
            elif not registry:
                ordinary = scan_plugin(
                    str(target), PluginScanOptions(policy=profile, disable_vendor_identity=True),
                )
                assert "SRC-EXEC" in high, f"{place} {label} {profile}"
                assert sorted((f.rule_id, f.severity) for f in ordinary.findings) == sorted(
                    (f.rule_id, f.severity)
                    for f in scan_plugin(str(target), PluginScanOptions(policy=profile)).findings
                ), f"{place} {label} {profile}"


@requires_symlink_privilege
@pytest.mark.parametrize("kind", sorted(STRUCTURED_SOURCES))
def test_dependency_spec_that_is_not_text_gives_no_identity(tmp_path, monkeypatch, kind) -> None:
    """An object or a list is not a registry request, whatever it holds."""

    project, installed = _pinned_npm_install(tmp_path, monkeypatch)
    value = STRUCTURED_SOURCES[kind]
    nested_key = "node_modules/sibling/" + PACKAGE_KEY
    cases = {
        "root-dependency": lambda t, r: _v3_root_spec(r, "dependencies", value, entry=True),
        "root-dev-dependency": lambda t, r: _v3_root_spec(r, "devDependencies", value, entry=False),
        "v1-from": lambda t, r: _v1_lock(r, {
            "version": VERSION, "resolved": _archive_address(VERSION), "from": value}),
        "manifest-from": lambda t, r: _edit_manifest(t, lambda m: m.update(_from=value)),
        "manifest-requested-member": lambda t, r: _edit_manifest(
            t, lambda m: m.update(_requested={"type": "version", "rawSpec": value})),
    }
    for place, edit in cases.items():
        root, target = _case(project, tmp_path, f"{kind}-{place}")
        edit(target, root)
        assert vendor_identity.inspect_official_provider_tree(str(target)) is None, place
        for profile in ("default", "permissive", "strict"):
            assert "SRC-EXEC" in _high(target, profile), f"{place} {profile}"

    # The package that owns a nested copy gives it its spec.
    root = tmp_path / "case" / f"{kind}-nested-owner"
    nested = root / nested_key
    nested.parent.mkdir(parents=True)
    shutil.copytree(installed, nested, symlinks=True)
    _write(root / "package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {
        "node_modules/sibling": {"version": "1.0.0", "dependencies": {PROVIDER: value}},
        nested_key: {"version": VERSION, "resolved": _archive_address(VERSION)},
    }}))
    assert vendor_identity.inspect_official_provider_tree(str(nested)) is None
    for profile in ("default", "permissive", "strict"):
        assert "SRC-EXEC" in _high(nested, profile), profile


def _link_to(root, folder: str, alias: str = "alias") -> None:
    (root / folder).mkdir(parents=True)
    (root / folder / "provider.tgz").write_bytes(b"fixture")
    (root / alias).symlink_to(root / folder, target_is_directory=True)


@requires_symlink_privilege
@pytest.mark.parametrize("folder", [".ssh", "vendor"])
def test_relative_source_is_a_path_and_gets_no_identity_whatever_a_link_leads_to(
    tmp_path, monkeypatch, folder,
) -> None:
    """A relative source is not judged by where a link leads: it is not the
    registry. The verdict is the ordinary one, as for the absolute spelling."""

    project, installed = _pinned_npm_install(tmp_path, monkeypatch)
    for place, edit in {
        "manifest-resolved": lambda t, r: _edit_manifest(
            t, lambda m: m.update(_resolved="file:../../../alias/provider.tgz")),
        "manifest-from": lambda t, r: _edit_manifest(
            t, lambda m: m.update(_from="file:../../../alias/provider.tgz")),
        "v3-root-spec": lambda t, r: _v3_root_spec(
            r, "dependencies", "file:./alias/provider.tgz", entry=True),
        "v1-from": lambda t, r: _v1_lock(r, {
            "version": VERSION, "resolved": _archive_address(VERSION),
            "from": "file:./alias/provider.tgz"}),
    }.items():
        root, target = _case(project, tmp_path, f"{folder}-{place}")
        _link_to(root, folder)
        edit(target, root)
        assert vendor_identity.inspect_official_provider_tree(str(target)) is None, place
        for profile in ("default", "permissive", "strict"):
            assert "SRC-EXEC" in _high(target, profile), f"{place} {profile}"


@requires_symlink_privilege
def test_install_below_protected_state_is_judged_by_its_source_only(tmp_path, monkeypatch) -> None:
    """The place of the project says nothing: a registry install keeps the
    identity wherever the project sits, and a relative alias or a direct
    spelling of a file there gives none."""

    published = tmp_path / "published"
    _published_provider(published)
    monkeypatch.setitem(
        vendor_identity.VENDOR_DIGESTS, (PROVIDER, VERSION),
        vendor_identity._package_digest(str(published)),
    )
    cases = {
        "registry": (True, lambda m: m.update(_resolved=_archive_address(VERSION))),
        "alias": (False, lambda m: m.update(_resolved="file:../../../alias/provider.tgz")),
        "direct": (False, lambda m: m.update(_resolved="file:../../../.ssh/provider.tgz")),
    }
    for label, (admitted, change) in cases.items():
        project = tmp_path / label / ".ssh" / "project"
        installed = project / PACKAGE_KEY
        _installed_by_openclaw(published, installed, _openclaw_peer(tmp_path / label))
        (project.parent / "provider.tgz").write_bytes(b"fixture")
        (project / "alias").symlink_to(project.parent, target_is_directory=True)
        _edit_manifest(installed, change)
        assert (vendor_identity.inspect_official_provider_tree(str(installed)) is not None) == admitted
        for profile in ("default", "permissive", "strict"):
            assert ("SRC-EXEC" in _high(installed, profile)) == (
                not admitted or profile == "strict"
            ), f"{label} {profile}"


@pytest.mark.skipif(os.name == "nt", reason="a file name cannot hold a colon on Windows, so the link this test needs cannot exist there")
@requires_symlink_privilege
def test_registry_address_is_identity_data_and_never_a_path(tmp_path, monkeypatch) -> None:
    """A local link named like the scheme of an address changes nothing."""

    project, installed = _pinned_npm_install(tmp_path, monkeypatch)
    root, target = _case(project, tmp_path, "scheme-link")
    (root / ".ssh").mkdir()
    (root / "https:").symlink_to(root / ".ssh", target_is_directory=True)
    _edit_manifest(target, lambda m: m.update(
        _from=_archive_address(VERSION), _resolved=_archive_address(VERSION),
    ))
    assert vendor_identity.inspect_official_provider_tree(str(target)) is not None
    for profile in ("default", "permissive"):
        assert _high(target, profile) == set(), profile


@requires_symlink_privilege
def test_protected_source_of_another_copy_does_not_decide_this_install(tmp_path, monkeypatch) -> None:
    """A sibling that requires this package from a protected file names another copy."""

    project, installed = _pinned_npm_install(tmp_path, monkeypatch)
    _write(project / "package-lock.json", json.dumps({"lockfileVersion": 1, "dependencies": {
        PROVIDER: {"version": VERSION, "resolved": _archive_address(VERSION)},
        "sibling": {"version": "1.0.0", "requires": {PROVIDER: PROTECTED_SOURCE}},
    }}))
    assert vendor_identity.inspect_official_provider_tree(str(installed)) is not None
    _write(project / "package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {
        "": {"dependencies": {"sibling": "1.0.0"}},
        PACKAGE_KEY: REGISTRY_RECORD,
        "node_modules/sibling": {"version": "1.0.0", "dependencies": {PROVIDER: PROTECTED_SOURCE}},
    }}))
    assert vendor_identity.inspect_official_provider_tree(str(installed)) is not None
    for profile in ("default", "permissive"):
        assert _high(installed, profile) == set(), profile


@requires_symlink_privilege
def test_dependency_specs_of_other_packages_do_not_decide_this_install(
    tmp_path, monkeypatch,
) -> None:
    """Only the lock entry at the installed path describes this copy.

    A sibling that carries its own copy, whether or not the lock lists that
    copy, is another install; the top-level package stays identified.
    """

    project, installed = _pinned_npm_install(tmp_path, monkeypatch)
    local = "file:../local-provider.tgz"
    nested_key = "node_modules/sibling/node_modules/" + PROVIDER
    _write(project / "package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {
        "": {"dependencies": {PROVIDER: VERSION, "sibling": "1.0.0"}},
        PACKAGE_KEY: REGISTRY_RECORD,
        "node_modules/sibling": {"version": "1.0.0", "dependencies": {PROVIDER: local}},
        nested_key: {"version": VERSION, "resolved": local},
    }}))
    assert vendor_identity.inspect_official_provider_tree(str(installed)) is not None
    for profile in ("default", "permissive"):
        assert _high(installed, profile) == set(), profile
    assert "SRC-EXEC" in _high(installed, "strict")

    # The nested copy is judged by its own entry.
    moved = project / nested_key
    moved.parent.mkdir(parents=True)
    shutil.copytree(installed, moved, symlinks=True)
    assert vendor_identity.inspect_official_provider_tree(str(moved)) is None
    for profile in ("default", "permissive", "strict"):
        assert "SRC-EXEC" in _high(moved, profile), profile

    # A partial lock that omits the nested copy (and an npm 6 lock, which has
    # no package entries) leaves the top-level copy as it was.
    for lock in (
        {"lockfileVersion": 3, "packages": {
            "": {"dependencies": {"sibling": "1.0.0"}},
            "node_modules/sibling": {"version": "1.0.0", "dependencies": {PROVIDER: local}},
        }},
        {"lockfileVersion": 1, "dependencies": {
            PROVIDER: {"version": VERSION, "resolved": _archive_address(VERSION)},
            "sibling": {"version": "1.0.0", "requires": {PROVIDER: local}},
        }},
    ):
        _write(project / "package-lock.json", json.dumps(lock))
        assert vendor_identity.inspect_official_provider_tree(str(installed)) is not None
        for profile in ("default", "permissive"):
            assert _high(installed, profile) == set(), profile


@requires_symlink_privilege
def test_dependency_spec_of_the_owning_package_decides_a_nested_copy(tmp_path, monkeypatch) -> None:
    """A copy below ``node_modules/a`` is the one ``a`` asks for: its spec must
    say the registry, as the root spec must for a top-level copy."""

    project, installed = _pinned_npm_install(tmp_path, monkeypatch)
    nested_key = "node_modules/sibling/" + PACKAGE_KEY
    registry = {"version": VERSION, "resolved": _archive_address(VERSION)}
    owners = {
        "v3-dependencies": lambda spec: {"lockfileVersion": 3, "packages": {
            "node_modules/sibling": {"version": "1.0.0", "dependencies": {PROVIDER: spec}},
            nested_key: registry,
        }},
        "v3-optional-dependencies": lambda spec: {"lockfileVersion": 3, "packages": {
            "": {"dependencies": {"sibling": "1.0.0"}},
            "node_modules/sibling": {"optionalDependencies": {PROVIDER: spec}},
        }},
        "v1-requires": lambda spec: {"lockfileVersion": 1, "dependencies": {"sibling": {
            "version": "1.0.0", "requires": {PROVIDER: spec}, "dependencies": {PROVIDER: registry},
        }}},
    }
    specs = {
        "registry": (VERSION, True),
        "registry-range": ("^2026.10.0", True),
        "protected": (PROTECTED_SOURCE, False),
        "unprotected-local": ("file:../provider", False),
        "git": ("git+https://example.invalid/provider.git", False),
    }
    for label, (spec, admitted) in specs.items():
        for owner, make in owners.items():
            root = tmp_path / "nested" / f"{label}-{owner}"
            nested = root / nested_key
            nested.parent.mkdir(parents=True)
            shutil.copytree(installed, nested, symlinks=True)
            _write(root / "package-lock.json", json.dumps(make(spec)))
            identity = vendor_identity.inspect_official_provider_tree(str(nested))
            assert (identity is not None) == admitted, f"{label} {owner}"
            for profile in ("default", "permissive"):
                assert ("SRC-EXEC" in _high(nested, profile)) == (not admitted), (
                    f"{label} {owner} {profile}"
                )
            if not admitted:
                assert "SRC-EXEC" in _high(nested, "strict"), f"{label} {owner}"


MANIFEST_EDITS = {
    "install-script-reading-a-protected-file": {"scripts": {
        "postinstall": "node -e \"require(fs).readFileSync(/home/user/.codex/auth.json)\"",
    }},
    "protected-local-dependency": {"dependencies": {"helper": "file:/home/user/.codex/provider.tgz"}},
    "dependency-over-http": {"dependencies": {"helper": "http://example.invalid/helper.tgz"}},
    "git-dependency": {"dependencies": {"helper": "git+https://example.invalid/helper.git"}},
    "dangerous-permission": {"permissions": ["fs:*"]},
}


@requires_symlink_privilege
@pytest.mark.parametrize("edit", sorted(MANIFEST_EDITS))
def test_registry_outage_does_not_admit_an_edited_manifest(tmp_path, monkeypatch, edit) -> None:
    """The record is a claim, so the manifest rules read the tree like any other plugin."""

    _, target = _unpinned_npm_install(tmp_path, "2026.99.4", REGISTRY_ENTRY)
    monkeypatch.setattr(vendor_identity, "_registry_get", _registry_outage(OSError("offline")))

    # Benign twin: a dependency from the registry changes nothing.
    _edit_manifest(target, lambda m: m.update(dependencies={"helper": "^1.2.3"}))
    assert vendor_identity.inspect_official_provider_tree(str(target)).unverified
    for profile in ("default", "permissive"):
        assert _high(target, profile) == set(), profile
        assert "VENDOR-REGISTRY-UNVERIFIED" in _rules(target, profile), profile

    _edit_manifest(target, lambda m: m.update(MANIFEST_EDITS[edit]))
    for profile in ("default", "permissive", "strict"):
        ordinary = scan_plugin(
            str(target), PluginScanOptions(policy=profile, disable_vendor_identity=True),
        )
        assert "SRC-EXEC" in _high(target, profile), f"{edit} {profile}"
        assert "VENDOR-REGISTRY-UNVERIFIED" not in _rules(target, profile), f"{edit} {profile}"
        # Exactly the ordinary verdict.
        assert sorted((f.rule_id, f.severity) for f in ordinary.findings) == sorted(
            (f.rule_id, f.severity)
            for f in scan_plugin(str(target), PluginScanOptions(policy=profile)).findings
        ), f"{edit} {profile}"


@requires_symlink_privilege
@pytest.mark.parametrize("read", sorted(PROTECTED_READS))
def test_registry_outage_does_not_admit_edited_extensionless_entrypoint_that_names_a_protected_file(
    tmp_path, monkeypatch, read,
) -> None:
    """The manifest declares the file that runs; the check reads it whatever its name."""

    version = "2026.99.4"
    _, target = _unpinned_npm_install(tmp_path, version, REGISTRY_ENTRY)
    monkeypatch.setattr(vendor_identity, "_registry_get", _registry_outage(OSError("offline")))
    _edit_manifest(target, lambda m: m.update(main="bin/runner"))
    runner = target / "bin" / "runner"

    # Benign twin: an ordinary launcher is admitted with the warning.
    _write(runner, "module.exports = 1;\n")
    assert vendor_identity.inspect_official_provider_tree(str(target)).unverified
    for profile in ("default", "permissive"):
        assert _high(target, profile) == set(), profile
        assert "VENDOR-REGISTRY-UNVERIFIED" in _rules(target, profile), profile

    _write(runner, PROTECTED_READS[read] + "\n")
    for profile in ("default", "permissive", "strict"):
        assert "CRED-CODEX-AUTH" in _high(target, profile), profile
        assert "VENDOR-REGISTRY-UNVERIFIED" not in _rules(target, profile), profile


def _installed_under(project, tmp_path, label: str, key: str):
    """A copy of the pinned install placed at ``key`` below a fresh project."""

    root = tmp_path / "placed" / label
    target = root / key
    target.parent.mkdir(parents=True)
    shutil.copytree(project / PACKAGE_KEY, target, symlinks=True)
    return root, target


def _alias_lock(root, key: str, owner: str, dependencies: dict, *, field: str = "dependencies") -> None:
    packages = {
        owner: {field: dependencies},
        key: {"name": PROVIDER, "version": VERSION, "resolved": _archive_address(VERSION)},
    }
    _write(root / "package-lock.json", json.dumps({"lockfileVersion": 3, "packages": packages}))


@requires_symlink_privilege
def test_copy_installed_under_another_name_gets_the_ordinary_verdict(tmp_path, monkeypatch) -> None:
    """An alias is another name for a source: the entry at the alias path
    names the provider and the registry, but the spec its owner files under
    the alias decides the source, and an alias is never the registry."""

    project, _ = _pinned_npm_install(tmp_path, monkeypatch)
    alias_specs = {
        "npm-alias": f"npm:{PROVIDER}@{VERSION}",
        "protected-file": PROTECTED_SOURCE,
        "ordinary-spec": VERSION,
        "no-spec": None,
    }
    places = {
        "root": ("node_modules/bedrock-alias", "", "node_modules/bedrock-alias"),
        "nested": (
            "node_modules/sibling/node_modules/bedrock-alias", "node_modules/sibling",
            "node_modules/sibling/node_modules/bedrock-alias",
        ),
    }
    for place, (key, owner, _) in places.items():
        for label, spec in alias_specs.items():
            root, target = _installed_under(project, tmp_path, f"{place}-{label}", key)
            _alias_lock(root, key, owner, {} if spec is None else {"bedrock-alias": spec})
            name = f"{place} {label}"
            assert vendor_identity.inspect_official_provider_tree(str(target)) is None, name
            for profile in ("default", "permissive", "strict"):
                assert "SRC-EXEC" in _high(target, profile), f"{name} {profile}"

    # Benign twin: the same layout under the package's own name is identified.
    for place, key, owner in (
        ("root", PACKAGE_KEY, ""),
        ("nested", "node_modules/sibling/" + PACKAGE_KEY, "node_modules/sibling"),
    ):
        root, target = _installed_under(project, tmp_path, f"own-name-{place}", key)
        _alias_lock(root, key, owner, {PROVIDER: VERSION})
        assert vendor_identity.inspect_official_provider_tree(str(target)) is not None, place
        assert _high(target, "default") == set(), place


REQUESTED_MEMBERS_THAT_SAY_ANOTHER_SOURCE = {
    "path-only": {"type": "version", "path": PROTECTED_SOURCE},
    "path-beside-request": {"type": "version", "rawSpec": VERSION, "path": PROTECTED_SOURCE},
    "resolved": {"type": "version", "rawSpec": VERSION, "resolved": PROTECTED_SOURCE},
    "from": {"type": "version", "rawSpec": VERSION, "from": "file:../provider"},
    "where": {"type": "version", "rawSpec": VERSION, "where": PROTECTED_SOURCE},
    "unknown-member": {"type": "version", "rawSpec": VERSION, "anything": "x"},
    "fetch-spec": {"type": "version", "rawSpec": VERSION, "fetchSpec": PROTECTED_SOURCE},
    "other-name": {"type": "version", "rawSpec": VERSION, "name": "other"},
    "other-scope": {"type": "version", "rawSpec": VERSION, "scope": "@other"},
    "no-type": {"rawSpec": VERSION},
    "empty": {},
    "directory": {"type": "directory", "rawSpec": VERSION},
}


@requires_symlink_privilege
def test_requested_object_names_only_registry_members(tmp_path, monkeypatch) -> None:
    """Every member of the npm 6 request object is judged; one that is not part
    of a registry request gives no identity whatever it holds, and the manifest
    spec field is judged like the others."""

    project, _ = _pinned_npm_install(tmp_path, monkeypatch)
    real = {
        "type": "version", "registry": True, "raw": f"{PROVIDER}@{VERSION}", "name": PROVIDER,
        "escapedName": "@openclaw%2famazon-bedrock-provider", "scope": "@openclaw",
        "rawSpec": VERSION, "saveSpec": None, "fetchSpec": VERSION,
    }
    cases = {
        **{f"requested/{k}": ({"_requested": v}, False) for k, v in REQUESTED_MEMBERS_THAT_SAY_ANOTHER_SOURCE.items()},
        "requested/real-npm6-shape": ({"_requested": real}, True),
        "requested/range": ({"_requested": {**real, "type": "range", "rawSpec": "^2026.10.0", "fetchSpec": "^2026.10.0"}}, True),
        "spec/registry": ({"_spec": f"{PROVIDER}@{VERSION}"}, True),
        "spec/protected-file": ({"_spec": PROTECTED_SOURCE}, False),
        "spec/relative-file": ({"_spec": "file:../provider"}, False),
        "spec/not-text": ({"_spec": {"path": PROTECTED_SOURCE}}, False),
    }
    for label, (fields, admitted) in cases.items():
        root, target = _case(project, tmp_path, label.replace("/", "-"))
        _edit_manifest(target, lambda m, fields=fields: m.update(fields))
        assert (vendor_identity.inspect_official_provider_tree(str(target)) is not None) == admitted, label
        for profile in ("default", "permissive", "strict"):
            high = _high(target, profile)
            if admitted:
                assert (profile == "strict") == ("SRC-EXEC" in high), f"{label} {profile}"
            else:
                assert "SRC-EXEC" in high, f"{label} {profile}"


@requires_symlink_privilege
def test_lock_that_is_present_and_cannot_be_read_gives_no_identity(tmp_path, monkeypatch) -> None:
    """A lock file in the places the install record is read from that does not
    parse into a lock gives the ordinary verdict; a missing lock, or one that
    simply has no entry for the package, does not hold the install against."""

    project, _ = _pinned_npm_install(tmp_path, monkeypatch)
    unreadable = {
        "invalid-json": b"{",
        "empty-file": b"",
        "not-an-object": b"[]",
        "null": b"null",
        "invalid-utf8": b"\xff\xfe{\x80",
        "too-deep": b"[" * 100000,
    }
    readable = {
        "no-entry": json.dumps({"lockfileVersion": 3, "packages": {}}).encode(),
        "registry-entry": json.dumps({"lockfileVersion": 3, "packages": {
            PACKAGE_KEY: {"version": VERSION, "resolved": _archive_address(VERSION)},
        }}).encode(),
    }
    for place, locate in LOCK_PLACES.items():
        for label, payload in {**unreadable, **readable, "absent": None}.items():
            root, target = _case(project, tmp_path, f"{place}-{label}")
            if payload is not None:
                path = locate(root, target)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(payload)
            name = f"{place} {label}"
            admitted = label not in unreadable
            assert (vendor_identity.inspect_official_provider_tree(str(target)) is not None) == admitted, name
            for profile in ("default", "permissive"):
                assert ("SRC-EXEC" in _high(target, profile)) == (not admitted), f"{name} {profile}"
            assert "SRC-EXEC" in _high(target, "strict"), f"{name} strict"


MALFORMED_LOCKS = {
    "packages-is-a-list": {"lockfileVersion": 3, "packages": []},
    "packages-is-text": {"lockfileVersion": 3, "packages": "file:../.ssh/provider.tgz"},
    "entry-at-path-is-text": {"lockfileVersion": 3, "packages": {PACKAGE_KEY: "file:../.ssh/provider.tgz"}},
    "entry-at-path-is-a-list": {"lockfileVersion": 3, "packages": {PACKAGE_KEY: ["file:../.ssh/provider.tgz"]}},
    "entry-of-another-package-is-text": {"lockfileVersion": 3, "packages": {
        "node_modules/other": "file:../.ssh/other.tgz",
        PACKAGE_KEY: {"version": VERSION, "resolved": _archive_address(VERSION)},
    }},
    "version-is-a-number": {"lockfileVersion": 3, "packages": {PACKAGE_KEY: {"version": 1}}},
    "resolved-is-a-list": {"lockfileVersion": 3, "packages": {
        PACKAGE_KEY: {"version": VERSION, "resolved": ["file:../.ssh/provider.tgz"]},
    }},
    "integrity-is-an-object": {"lockfileVersion": 3, "packages": {
        PACKAGE_KEY: {"version": VERSION, "integrity": {"value": INTEGRITY}},
    }},
    "link-is-text": {"lockfileVersion": 3, "packages": {PACKAGE_KEY: {"version": VERSION, "link": "yes"}}},
    "spec-table-is-text": {"lockfileVersion": 3, "packages": {
        "": {"dependencies": "file:../.ssh/provider.tgz"},
        PACKAGE_KEY: {"version": VERSION, "resolved": _archive_address(VERSION)},
    }},
    "spec-is-an-object": {"lockfileVersion": 3, "packages": {
        "": {"dependencies": {PROVIDER: {"path": "../.ssh/provider"}}},
        PACKAGE_KEY: {"version": VERSION, "resolved": _archive_address(VERSION)},
    }},
    "dependencies-is-a-list": {"lockfileVersion": 1, "dependencies": []},
    "dependency-entry-is-text": {"lockfileVersion": 1, "dependencies": {PROVIDER: "file:../.ssh/provider.tgz"}},
    "dependency-entry-is-a-list": {"lockfileVersion": 1, "dependencies": {PROVIDER: ["file:../.ssh/provider.tgz"]}},
    "nested-dependency-entry-is-text": {"lockfileVersion": 1, "dependencies": {
        PROVIDER: {"version": VERSION, "resolved": _archive_address(VERSION), "dependencies": {"x": "file:../.ssh/x"}},
    }},
    "requires-is-text": {"lockfileVersion": 1, "dependencies": {
        PROVIDER: {"version": VERSION, "resolved": _archive_address(VERSION), "requires": "file:../.ssh/x"},
    }},
    "v1-version-is-a-list": {"lockfileVersion": 1, "dependencies": {PROVIDER: {"version": [VERSION]}}},
    "packages-is-null": {"lockfileVersion": 3, "packages": None},
    "dependencies-is-null": {"lockfileVersion": 1, "dependencies": None},
    "nested-dependencies-is-null": {"lockfileVersion": 1, "dependencies": {
        PROVIDER: {"version": VERSION, "resolved": _archive_address(VERSION), "dependencies": None},
    }},
    "lockfile-version-is-null": {"lockfileVersion": None, "packages": {}},
    "lockfile-version-is-text": {"lockfileVersion": "3", "packages": {}},
    "entry-dependencies-is-null": {"lockfileVersion": 3, "packages": {
        PACKAGE_KEY: {"version": VERSION, "resolved": _archive_address(VERSION), "dependencies": None},
    }},
    "entry-link-is-null": {"lockfileVersion": 3, "packages": {
        PACKAGE_KEY: {"version": VERSION, "resolved": _archive_address(VERSION), "link": None},
    }},
    "v2-valid-packages-malformed-dependencies": {
        "lockfileVersion": 2,
        "packages": {PACKAGE_KEY: {"version": VERSION, "resolved": _archive_address(VERSION)}},
        "dependencies": {PROVIDER: "file:../.ssh/provider.tgz"},
    },
}
WELL_FORMED_LOCKS = {
    "no-entry": {"lockfileVersion": 3, "packages": {}},
    "registry-entry-with-npm-extras": {"lockfileVersion": 3, "packages": {
        "": {"name": "project", "version": "1.0.0", "dependencies": {PROVIDER: "^" + VERSION}},
        PACKAGE_KEY: {
            "version": VERSION, "resolved": _archive_address(VERSION), "integrity": INTEGRITY,
            "dev": True, "license": ["MIT"], "engines": {"node": ">=20"}, "peerDependencies": {"openclaw": "*"},
        },
        "node_modules/other": {"version": "1.0.0", "link": False, "bin": {"other": "cli.js"}},
    }},
    "v1-registry-entry": {"lockfileVersion": 1, "dependencies": {PROVIDER: {
        "version": VERSION, "resolved": _archive_address(VERSION), "integrity": INTEGRITY,
        "requires": {"left-pad": "^1.0.0"}, "dependencies": {"left-pad": {"version": "1.3.0"}},
    }}},
}


@requires_symlink_privilege
def test_lock_that_has_any_malformed_part_is_not_an_install_record(tmp_path, monkeypatch) -> None:
    """The whole lock is trusted or none of it: a malformed package table, an
    entry of a wrong type (at this install's path or elsewhere in the file) or a
    wrong-typed field gives the ordinary verdict in every profile, where a lock
    of the npm shape keeps the identity."""

    project, _ = _pinned_npm_install(tmp_path, monkeypatch)
    for place, locate in LOCK_PLACES.items():
        for label, lock in {**MALFORMED_LOCKS, **WELL_FORMED_LOCKS}.items():
            root, target = _case(project, tmp_path, f"{place}-{label}")
            path = locate(root, target)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(lock), encoding="utf-8")
            name = f"{place} {label}"
            admitted = label in WELL_FORMED_LOCKS
            assert (vendor_identity.inspect_official_provider_tree(str(target)) is not None) == admitted, name
            for profile in ("default", "permissive"):
                assert ("SRC-EXEC" in _high(target, profile)) == (not admitted), f"{name} {profile}"
            assert "SRC-EXEC" in _high(target, "strict"), f"{name} strict"
