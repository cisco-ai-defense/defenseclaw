# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Exact published OpenClaw provider identities for plugin admission."""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import io
import json
import os
import re
import stat
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path, PureWindowsPath
from typing import NamedTuple

from defenseclaw.hermes_skills import (
    _SKILL_FILE_MAX_BYTES,
    _SKILL_TREE_MAX_BYTES,
    _filesystem_identity,
    _hash_regular_file,
    _is_link_or_junction,
    _is_real_directory,
    _is_regular_file,
    _read_regular_file,
)

# Digests of the published package own files, see ``_package_digest``. The
# installed dependency tree is not part of the identity: npm resolves it from
# the registry when the plugin is installed, so it differs between installs of
# the same provider version. These pins let a host with no registry access
# identify the releases below; any other release is confirmed against the npm
# registry (``_registry_digest``), so a new release needs no change here.
# ``scripts/openclaw_provider_digests.py`` prints the rows for a release.
VENDOR_DIGESTS = {
    ("@openclaw/amazon-bedrock-provider", "2026.9.33"):
        "227f9139d20266784b1a8f736bc57c7a8c015c66a210fb9b0ed2d3c53f8a3c5c",
    ("@openclaw/amazon-bedrock-provider", "2026.9.34"):
        "cb06f530edaa3c1c21a3daf19de2d3feec3ba19c127ecaeb39cc1e45405c67dc",
    ("@openclaw/amazon-bedrock-provider", "2026.9.35"):
        "d35b540fb7ba1e34de31b1a49331f8d081865524aa4b5f44972b9e3732648e82",
    ("@openclaw/amazon-bedrock-provider", "2026.9.36"):
        "f093f56e06772aa423b59e4ba2ea8651d30cdf4f1da9f3067c37401c3cd864bf",
    ("@openclaw/amazon-bedrock-provider", "2026.10.1"):
        "82a8271d9502ef9e17590cea67f3fd894077829fd21a457680d0b19315f7bcff",
    ("@openclaw/amazon-bedrock-provider", "2026.10.2"):
        "60de8fadf40ec6fbe2da249312b4bc8aa71a397ea9ab5f3b60fb0c2a40005721",
    ("@openclaw/amazon-bedrock-provider", "2026.10.3"):
        "44c5f821816b129fafe47f02807a95d745acb9d28f1fd85033eb01092af28752",
    ("@openclaw/amazon-bedrock-provider", "2026.10.4"):
        "8eb455002ce747ad4d9b005fdc17e7345725f7a9cdcf96cb51d200053f236924",
    ("@openclaw/amazon-bedrock-provider", "2026.10.5"):
        "d46d1d71159e309841d2776df87dc42640d5e17b417d0eac2d7f89816a07e8b9",
    ("@openclaw/amazon-bedrock-provider", "2026.10.6"):
        "e27d05f4124ca33cd0d625f3caa3fe0a0766198e2a9dc1df08d018bf16f8aff0",
    ("@openclaw/amazon-bedrock-provider", "2026.10.7"):
        "00beac565275b2d387311b88f962100fc950ddc3bd38441868929416089e734f",
    ("@openclaw/amazon-bedrock-provider", "2026.10.8"):
        "a7a398c64326b8bd083ce20f5a043e839b3f44fe7702a5f71f08327a696d9f99",
    ("@openclaw/amazon-bedrock-provider", "2026.10.9"):
        "1a932902454e24eaa8406106d417cd54c29c615fc5a23136704939b997645bf2",
    ("@openclaw/amazon-bedrock-provider", "2026.10.10"):
        "31167f79f18e916248d1bcb4b7be2e6bd5d5ec878aa7660c0344d44988b829e3",
    ("@openclaw/amazon-bedrock-provider", "2026.11.1"):
        "a059007a42818a11cbf8be2f04cf24897ac9aa99130a141b920aad503e651cbc",
}

# Packages whose identity is checked: the pinned releases above, and any other
# release the npm registry publishes under the same name.
_OFFICIAL_PACKAGES = frozenset(name for name, _ in VENDOR_DIGESTS)

_PRIVATE_INSTALL_COMPONENTS = frozenset({
    ".ssh", ".aws", ".gnupg", ".kube", ".azure", ".docker", ".defenseclaw",
})


class ProviderIdentity(NamedTuple):
    name: str
    possible_peer: bool
    # True when the registry could not be reached and the release was admitted
    # on the install record alone (see ``_recorded_registry_release``).
    unverified: bool = False


def inspect_official_provider_tree(plugin_dir: str, *, data_dir: str = "") -> ProviderIdentity | None:
    """Identify published bytes plus validated installer-created peer links."""

    manifest = _read_regular_file(
        os.path.join(plugin_dir, "package.json"), max_bytes=64 * 1024,
    )
    if manifest is None:
        return None
    try:
        package = json.loads(manifest)
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(package, dict):
        return None
    name, version = package.get("name"), package.get("version")
    if not isinstance(name, str) or not isinstance(version, str):
        return None
    if name not in _OFFICIAL_PACKAGES:
        return None
    # Every place the install names its source must say the registry: any other
    # source gives no identity, whatever the bytes are (see ``_install_records``).
    try:
        records = _install_records(plugin_dir, package, name)
    except (OSError, ValueError):
        return None
    if records is None:
        return None
    # A release without a pinned digest is confirmed against the npm registry
    # below, once the local tree has passed the cheap checks.
    want = VENDOR_DIGESTS.get((name, version))
    unverified = False

    peers = package.get("peerDependencies", {})
    if not isinstance(peers, dict):
        return None
    root = os.path.abspath(plugin_dir)
    tolerated: set[str] = set()
    links: dict[str, tuple[str, tuple]] = {}
    for peer in peers:
        if not isinstance(peer, str) or not re.fullmatch(
            r"(?:@[a-z0-9._-]+/)?[a-z0-9._-]+", peer,
        ) or any(part in (".", "..") for part in peer.split("/")):
            return None
        relative = "node_modules/" + peer
        link = os.path.join(plugin_dir, *relative.split("/"))
        tolerated.add(relative)
        try:
            links[peer] = (link, _validated_peer_link(link, root, peer, data_dir))
        except (OSError, ValueError, TypeError, AttributeError):
            return None

    before_tree = _tree_entry_state(root)
    if before_tree is None:
        return None
    # A same-size edit can retain its mtime, and Windows ctime is creation
    # time. Recheck the package files and links before admitting.
    for _ in range(2):
        found = _package_digest(plugin_dir, tolerated_links=frozenset(tolerated))
        if found is None:
            return None
        if not want and not unverified:
            try:
                want = _registry_digest(name, version)
            except _RegistryUnavailableError:
                # An outage proves nothing about the bytes. The ordinary
                # profiles still admit a release whose install record names
                # the registry archive; strict never reaches this check.
                unverified = _recorded_registry_release(records, name, version)
        if not unverified and (not want or not hmac.compare_digest(found, want)):
            return None
        for peer, (link, before) in links.items():
            try:
                if before != _validated_peer_link(link, root, peer, data_dir):
                    return None
            except (OSError, ValueError, TypeError, AttributeError):
                return None
        if before_tree != _tree_entry_state(root):
            return None
    return ProviderIdentity(
        name=name,
        possible_peer=any(state[1] is not None for _, state in links.values()),
        unverified=unverified,
    )


# Fields an installer adds to or removes from the published manifest.
# bundledDependencies names what npm packs, never a source, and is dropped
# once the dependencies are installed. OpenClaw adds one development-only
# line for its plugin SDK; development dependencies are never installed. That
# one line is removed from the manifest on both sides of the comparison and
# every other development dependency keeps its value in the digest, so a
# manifest source (a URL, a local path) that the dependency checks judge is
# never hidden by the identity, and a release that already has development
# dependencies of its own is identified the same way as one that has none.
_BUNDLED_FIELDS = frozenset({"bundledDependencies", "bundleDependencies"})
_INSTALLER_DEV_DEPENDENCY = ("@openclaw/plugin-sdk", "workspace:*")
_MANIFEST_MAX_BYTES = 1024 * 1024
_DEPENDENCY_DIR = "node_modules"
_DEPENDENCY_ENTRY_LIMIT = 500_000


def _published_manifest_bytes(payload: bytes) -> bytes | None:
    """The manifest as published: installer fields and npm metadata removed."""

    try:
        manifest = json.loads(payload)
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(manifest, dict):
        return None
    kept = {
        key: value for key, value in manifest.items()
        if key not in _BUNDLED_FIELDS and not key.startswith("_")
    }
    development = kept.get("devDependencies")
    if isinstance(development, dict):
        development = {
            key: value for key, value in development.items()
            if (key, value) != _INSTALLER_DEV_DEPENDENCY
        }
        if development:
            kept["devDependencies"] = development
        else:
            del kept["devDependencies"]
    return json.dumps(kept, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _package_digest(
    plugin_dir: str, *, tolerated_links: frozenset[str] = frozenset(),
) -> str | None:
    """Digest of the package own files, whichever way it was installed.

    Every entry outside the top-level ``node_modules`` is part of the digest:
    its relative path and a digest of its bytes, with the manifest reduced to
    its published form. Any link, device or other non-regular entry there makes
    the tree unidentified. ``node_modules`` holds what npm resolved for this
    install, so it is not hashed, but it must hold only directories and regular
    files; the one link allowed is a tolerated installer peer link, which the
    caller validates and which is never followed.
    """

    root = os.path.abspath(plugin_dir)
    try:
        root_before = os.stat(root, follow_symlinks=False)
    except OSError:
        return None
    if not _is_real_directory(root_before):
        return None

    files: list[tuple[str, str, int]] = []
    own_bytes = 0
    dependency_entries = 0
    try:
        for current, dirs, names in os.walk(root, topdown=True, followlinks=False):
            if not _is_real_directory(os.stat(current, follow_symlinks=False)):
                return None
            safe_dirs: list[str] = []
            for name in dirs:
                child = os.path.join(current, name)
                info = os.stat(child, follow_symlinks=False)
                relative = os.path.relpath(child, root).replace("\\", "/")
                if _is_link_or_junction(info) and relative in tolerated_links:
                    continue
                if not _is_real_directory(info):
                    return None
                safe_dirs.append(name)
            dirs[:] = safe_dirs
            for name in names:
                full = os.path.join(current, name)
                info = os.stat(full, follow_symlinks=False)
                relative = os.path.relpath(full, root).replace("\\", "/")
                if _is_link_or_junction(info) and relative in tolerated_links:
                    continue
                if not _is_regular_file(info):
                    return None
                if relative.startswith(_DEPENDENCY_DIR + "/"):
                    dependency_entries += 1
                    if dependency_entries > _DEPENDENCY_ENTRY_LIMIT:
                        return None
                    continue
                if info.st_size > _SKILL_FILE_MAX_BYTES:
                    return None
                own_bytes += info.st_size
                if own_bytes > _SKILL_TREE_MAX_BYTES:
                    return None
                files.append((relative, full, info.st_size))
    except OSError:
        return None

    outer = hashlib.sha256()
    for relative, full, size in sorted(files, key=lambda item: item[0]):
        inner = hashlib.sha256()
        if relative == "package.json":
            payload = _read_regular_file(full, max_bytes=_MANIFEST_MAX_BYTES)
            published = None if payload is None else _published_manifest_bytes(payload)
            if published is None:
                return None
            inner.update(published)
        elif not _hash_regular_file(full, size, inner):
            return None
        outer.update(relative.encode("utf-8") + b"\0" + inner.digest())
    try:
        root_after = os.stat(root, follow_symlinks=False)
    except OSError:
        return None
    if _filesystem_identity(root_before) != _filesystem_identity(root_after):
        return None
    return outer.hexdigest()


_REGISTRY = "https://registry.npmjs.org"
_REGISTRY_TIMEOUT_SECONDS = 20
_REGISTRY_METADATA_MAX_BYTES = 4 * 1024 * 1024
_REGISTRY_TARBALL_MAX_BYTES = 64 * 1024 * 1024
_REGISTRY_MEMBER_LIMIT = 100_000
_VERSION = re.compile(r"\d{1,4}\.\d{1,3}\.\d{1,3}(?:-[0-9A-Za-z.]{1,32})?")
_registry_digests: dict[tuple[str, str], str] = {}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """The registry serves its tarballs itself; a redirect is not followed."""

    def redirect_request(self, *_args, **_kwargs):
        return None


def _registry_get(url: str, limit: int) -> bytes:
    if not url.startswith(_REGISTRY + "/"):
        raise ValueError("not a registry address")
    opener = urllib.request.build_opener(_NoRedirect)
    with opener.open(url, timeout=_REGISTRY_TIMEOUT_SECONDS) as response:
        if response.status != 200:
            raise ValueError("registry did not answer 200")
        payload = response.read(limit + 1)
    if len(payload) > limit:
        raise ValueError("registry answer too large")
    return payload


class _RegistryUnavailableError(Exception):
    """The registry could not be reached or failed to answer: nothing was learned."""


def _registry_fetch(url: str, limit: int) -> bytes:
    """One registry request. An outage is told apart from an answer that is wrong."""

    try:
        return _registry_get(url, limit)
    except urllib.error.HTTPError as exc:
        if exc.code < 500 and exc.code != 429:
            raise ValueError("registry refused the request") from exc
        raise _RegistryUnavailableError from exc
    except (OSError, http.client.HTTPException) as exc:
        raise _RegistryUnavailableError from exc


def _registry_digest(name: str, version: str) -> str | None:
    """The package-own-files digest of a release as the npm registry publishes it.

    The registry states the integrity of the release archive; the archive is
    fetched from the registry address that names it, checked against that
    integrity, and its own files are digested exactly as an installed tree is.
    Any wrong answer (another address, another integrity, an unreadable
    archive) gives no identity, so the plugin gets the ordinary scan. When the
    registry cannot be reached at all, ``_RegistryUnavailableError`` is raised and
    the caller decides.
    """

    key = (name, version)
    if key in _registry_digests:
        return _registry_digests[key]
    if name not in _OFFICIAL_PACKAGES or not _VERSION.fullmatch(version):
        return None
    package = name.split("/", 1)[1]
    try:
        quoted = urllib.parse.quote(name, safe="@")
        metadata = json.loads(_registry_fetch(
            f"{_REGISTRY}/{quoted}/{version}", _REGISTRY_METADATA_MAX_BYTES,
        ))
        dist = metadata["dist"]
        integrity = dist["integrity"]
        if (
            metadata["name"] != name or metadata["version"] != version
            or dist["tarball"] != f"{_REGISTRY}/{name}/-/{package}-{version}.tgz"
            or not isinstance(integrity, str) or not integrity.startswith("sha512-")
        ):
            return None
        archive = _registry_fetch(dist["tarball"], _REGISTRY_TARBALL_MAX_BYTES)
        expected = base64.b64decode(integrity[len("sha512-"):], validate=True)
        if not hmac.compare_digest(hashlib.sha512(archive).digest(), expected):
            return None
        digest = _archive_package_digest(archive)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, tarfile.TarError):
        return None
    if digest:
        _registry_digests[key] = digest
    return digest


def _archive_package_digest(archive: bytes) -> str | None:
    """Digest the package own files of a release archive; dependencies are not unpacked."""

    with tempfile.TemporaryDirectory(prefix="dc-provider-") as scratch:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
            members = []
            for member in bundle:
                if len(members) >= _REGISTRY_MEMBER_LIMIT:
                    return None
                if not member.name.startswith("package/"):
                    return None
                if member.name.startswith("package/" + _DEPENDENCY_DIR + "/"):
                    continue
                members.append(member)
            bundle.extractall(scratch, members=members, filter="data")
        return _package_digest(os.path.join(scratch, "package"))


# Where an install came from. npm writes the lock entry of every package it
# installs into the lock of the project that holds it, with the ``resolved``
# address and the ``integrity`` of the archive. That entry is the install
# record: the bytes can match a published release while the entry says the
# package was taken from a file, a link or another address, and such an install
# is judged by the ordinary scan. An entry that is absent is not evidence of a
# source, so an install that left none (OpenClaw copies the package) is not held
# against; only an outage needs one (see ``_recorded_registry_release``).
#
# Every place the install names its source (the manifest fields ``_resolved``,
# ``_from`` and ``_requested``, the lock entry, and the spec that the package
# owning this copy gives it) must say, in so many words, that the source is the
# registry. That is the whole rule: an address is read as an address and a spec
# as a spec, never as a file name, so no folder name, link or platform naming
# rule decides anything. A source of any other kind (a file, a link, a path, a
# git address, a URL alias, a list or an object) gives no identity, and the
# plugin gets exactly the verdict of the ordinary scan. Specs of other packages
# are not read: they describe other copies.
_LOCK_FILES = ("package-lock.json", "npm-shrinkwrap.json", "node_modules/.package-lock.json")
_LOCK_MAX_BYTES = 32 * 1024 * 1024
_RECORDED_VERSION = re.compile(r"[0-9][0-9A-Za-z.+-]*")
_DEPENDENCY_FIELDS = (
    "dependencies", "devDependencies", "optionalDependencies", "peerDependencies",
)
_METADATA_FIELDS = ("_resolved", "_from", "_requested", "_spec")
# A version, a range or a tag: letters, digits and range operators, with at
# least one letter, digit or ``*``. A path separator, a colon or an ``@`` make a
# different kind of spec, and a name that ends like an archive is a file.
_REGISTRY_SPEC = re.compile(r"(?=.*[0-9A-Za-z*])[0-9A-Za-z.^~*<>=| +-]{0,128}")
_ARCHIVE_NAME = re.compile(r"\.(?:tgz|tar|tar\.gz)$", re.IGNORECASE)
_REQUEST_FIELDS = ("raw", "rawSpec", "saveSpec", "fetchSpec")
_REQUESTED_MEMBERS = frozenset(("type", "registry", "name", "escapedName", "scope") + _REQUEST_FIELDS)


def _registry_request(value: object, name: str) -> bool:
    """Whether ``value`` is a plain registry request for the package ``name``.

    The request is a registry archive address of the package, a version, range
    or tag, or the name followed by one of these.
    """

    if not isinstance(value, str):
        return False
    if _registry_archive(value, name):
        return True
    spec = value[len(name) + 1:] if value.startswith(name + "@") else value
    return _REGISTRY_SPEC.fullmatch(spec) is not None and not _ARCHIVE_NAME.search(spec)


def _registry_metadata(field: str, value: object, name: str) -> bool:
    """Whether a manifest install field (``_resolved``, ``_from``, ``_requested``, ``_spec``) is the registry."""

    if field == "_resolved":
        return _registry_archive(value, name)
    if field != "_requested" or not isinstance(value, dict):
        return _registry_request(value, name)
    # npm 6 records the request as an object. Every member is named and
    # judged; a member this rule does not know (a path, a resolved address, a
    # source of any kind under any spelling) gives no identity, so no member
    # can carry a source past the rule.
    if set(value) - _REQUESTED_MEMBERS or value.get("type") not in ("version", "range", "tag"):
        return False
    escaped = name.replace("/", "%2f")
    return (
        value.get("registry", True) is True
        and value.get("name", name) == name
        and value.get("scope") in (None, name.split("/", 1)[0] if name.startswith("@") else None)
        and str(value.get("escapedName", escaped)).lower() == escaped
        and all(value.get(key) is None or _registry_request(value[key], name) for key in _REQUEST_FIELDS)
    )


def _registry_archive(address: object, name: str, version: str | None = None) -> bool:
    """Whether ``address`` is an https address of a registry archive of ``name``.

    Any registry host (a mirror) is accepted: the bytes are proven against the
    npm registry, not against this address, which only has to be a registry
    address and not a file, a link or another kind of source.
    """

    if not isinstance(address, str):
        return False
    try:
        parsed = urllib.parse.urlsplit(address)
        host = parsed.hostname
        parsed.port
    except ValueError:
        return False
    if parsed.scheme != "https" or not host or parsed.username is not None or (
        parsed.password is not None
    ):
        return False
    release = re.escape(version) if version else r"[0-9][0-9A-Za-z.+-]*"
    package = re.escape(name.split("/", 1)[1])
    return re.fullmatch(
        r"(?:/[^/]+)*/" + re.escape(name) + "/-/" + package + "-" + release + r"\.tgz",
        parsed.path,
    ) is not None


def _lock_folders(plugin_dir: str) -> list[str]:
    """The package folder and each folder that owns a ``node_modules`` above it."""

    root = os.path.abspath(plugin_dir)
    parts = Path(root).parts
    return [root] + [
        os.path.join(*parts[:index]) for index, part in enumerate(parts)
        if index and part.casefold() == _DEPENDENCY_DIR
    ]


def _fold(path: str) -> str:
    return path.casefold() if os.name == "nt" else path


def _flat_v1(tree: object) -> dict[str, dict]:
    """The nested ``dependencies`` tree of an npm 6 lock as lock paths.

    ``a`` with a nested ``b`` becomes ``node_modules/a`` and
    ``node_modules/a/node_modules/b``, the form later locks use, so one reading
    serves every lock version. ``requires`` is a spec of another package and is
    not part of the entry.
    """

    flat: dict[str, dict] = {}
    pending: list[tuple[str, object]] = [("", tree)]
    while pending:
        base, dependencies = pending.pop()
        if not isinstance(dependencies, dict):
            continue
        for dependency, entry in dependencies.items():
            if not isinstance(dependency, str) or not isinstance(entry, dict):
                continue
            path = (base + "/" if base else "") + _DEPENDENCY_DIR + "/" + dependency
            flat[path] = entry
            pending.append((path, entry.get("dependencies")))
    return flat


def _specs_are_text(specs: object) -> bool:
    return isinstance(specs, dict) and all(
        isinstance(key, str) and isinstance(value, str) for key, value in specs.items()
    )


def _lock_entry_is_valid(entry: object, spec_fields: tuple[str, ...]) -> bool:
    """Whether one lock entry has the shape npm writes for the fields read here."""

    return isinstance(entry, dict) and all(
        isinstance(entry[field], str)
        for field in ("name", "version", "resolved", "integrity", "from") if field in entry
    ) and isinstance(entry.get("link", False), bool) and all(
        _specs_are_text(entry[field]) for field in spec_fields if field in entry
    )


def _is_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _lock_is_valid(lock: dict) -> bool:
    """Whether the whole lock has the npm lock shape: every package table and every entry.

    The lock is trusted all or nothing. A table or an entry of a type npm never
    writes, at this install path or anywhere else in the file, means the file
    is not read as an install record at all.
    """

    # A key that is present must hold the type npm writes: a JSON null is a
    # malformed value, not an absent table.
    if "lockfileVersion" in lock and not _is_integer(lock["lockfileVersion"]):
        return False
    if "packages" in lock:
        packages = lock["packages"]
        if not (
            isinstance(packages, dict)
            and all(_lock_entry_is_valid(entry, _DEPENDENCY_FIELDS) for entry in packages.values())
        ):
            return False
    pending = [lock["dependencies"]] if "dependencies" in lock else []
    while pending:
        tree = pending.pop()
        if not isinstance(tree, dict):
            return False
        for entry in tree.values():
            if not _lock_entry_is_valid(entry, ("requires",)):
                return False
            if "dependencies" in entry:
                pending.append(entry["dependencies"])
    return True


def _lock_records(lock: dict, name: str, key: str | None) -> list[dict]:
    """The entries of an npm lock that record this package.

    ``key`` is the path of the package below the folder of the lock: only the
    entry at that path describes this install. A lock that sits in the package
    folder itself has no key, and every entry that names the package counts.
    Both the ``packages`` table and the nested ``dependencies`` tree are read.
    """

    wanted = None if key is None else _fold(key)
    tables = [
        table for table in (lock.get("packages"), _flat_v1(lock.get("dependencies")))
        if isinstance(table, dict)
    ]
    return [
        entry for table in tables for path, entry in table.items()
        if isinstance(path, str) and isinstance(entry, dict) and path and (
            _fold(path) == wanted if wanted is not None else (
                path == f"{_DEPENDENCY_DIR}/{name}"
                or path.endswith(f"/{_DEPENDENCY_DIR}/{name}")
                or entry.get("name") == name
            )
        )
    ]


def _installed_as(key: str | None) -> tuple[str, str] | None:
    """The owner path and the dependency name of a copy at ``.../node_modules/<dep>``.

    The dependency name is the folder name the owner's spec is filed under: it
    is the package name for an ordinary install and the alias for an aliased
    one. ``None`` when the copy is not in a ``node_modules`` folder.
    """

    if key is None:
        return None
    parts = key.split("/")
    size = 2 if len(parts) > 2 and parts[-2].startswith("@") else 1
    if len(parts) <= size or parts[-size - 1] != _DEPENDENCY_DIR:
        return None
    return "/".join(parts[:-size - 1]), "/".join(parts[-size:])


def _owner_specs(lock: dict, key: str | None) -> list[object]:
    """The specs that the package owning this install gives it.

    A copy at ``node_modules/<dep>`` is the one the root of the project asks
    for (the lock entry with an empty path) under the name ``<dep>``; a copy at
    ``node_modules/a/node_modules/<dep>`` is the one ``a`` asks for. The spec
    describes this install only when it is that copy, and the copy is a copy
    whether or not the lock lists it. A lock of npm 6 gives the same spec in
    ``requires``.
    """

    placed = _installed_as(key)
    if placed is None:
        return []
    owner, dependency = _fold(placed[0]), placed[1]
    # The ``dependencies`` of an npm 6 entry are the nested packages, not specs.
    tables = [
        (lock.get("packages"), _DEPENDENCY_FIELDS),
        (_flat_v1(lock.get("dependencies")), ("requires",)),
    ]
    return [
        specs[dependency] for table, fields in tables if isinstance(table, dict)
        for path, entry in table.items()
        if isinstance(path, str) and isinstance(entry, dict) and _fold(path) == owner
        for field in fields
        if isinstance(specs := entry.get(field), dict) and dependency in specs
    ]


def _install_records(plugin_dir: str, manifest: dict, name: str) -> list[dict] | None:
    """The lock entries that record this install, or None if any place the
    install names its source does not say the registry, the copy is installed
    under another name than the package's (an alias), or a lock that is present
    cannot be read as an install record (the whole lock is checked)."""

    if not all(
        field not in manifest or _registry_metadata(field, manifest[field], name)
        for field in _METADATA_FIELDS
    ):
        return None
    records: list[dict] = []
    root = os.path.abspath(plugin_dir)
    for position, folder in enumerate(_lock_folders(plugin_dir)):
        key = None if position == 0 else os.path.relpath(root, folder).replace(os.sep, "/")
        placed = _installed_as(key)
        if placed is not None and _fold(placed[1]) != _fold(name):
            return None
        for relative in _LOCK_FILES:
            path = os.path.join(folder, *relative.split("/"))
            try:
                info = os.lstat(path)
            except FileNotFoundError:
                continue
            if not _is_regular_file(info) or info.st_size > _LOCK_MAX_BYTES:
                return None
            payload = _read_regular_file(path, max_bytes=_LOCK_MAX_BYTES)
            if payload is None:
                return None
            try:
                lock = json.loads(payload)
            except (UnicodeDecodeError, ValueError, RecursionError):
                return None
            if not isinstance(lock, dict) or not _lock_is_valid(lock):
                return None
            if not all(_registry_request(spec, name) for spec in _owner_specs(lock, key)):
                return None
            for entry in _lock_records(lock, name, key):
                version = entry.get("version")
                if entry.get("link") or (
                    version is not None
                    and not (isinstance(version, str) and _RECORDED_VERSION.fullmatch(version))
                ) or ("resolved" in entry and not _registry_archive(entry["resolved"], name)) or (
                    "from" in entry and not _registry_request(entry["from"], name)
                ):
                    return None
                records.append(entry)
    return records


def _recorded_registry_release(records: list[dict], name: str, version: str) -> bool:
    """Whether an install record names the registry archive of this release.

    The record carries the sha512 integrity of the archive, which is what the
    registry would confirm. It is a claim made by the install, not a check of
    these bytes, so it is used only when the registry cannot be reached.
    """

    for entry in records:
        integrity = entry.get("integrity")
        if (
            entry.get("version") == version
            and _registry_archive(entry.get("resolved"), name, version)
            and isinstance(integrity, str) and integrity.startswith("sha512-")
        ):
            try:
                if len(base64.b64decode(integrity[len("sha512-"):], validate=True)) == 64:
                    return True
            except ValueError:
                continue
    return False


def _tree_entry_state(root: str) -> tuple | None:
    """Record every in-root entry so the digest describes the final tree.

    Each entry is read with ``os.stat`` on its own path, never with the
    ``DirEntry`` the listing hands out. On Windows that is directory-listing
    data: it carries no volume or file ID, and it shows the modification time
    of a subdirectory only after NTFS has flushed it to the parent index, so
    two listings of an unchanged tree can differ.
    """

    try:
        root_info = os.stat(root, follow_symlinks=False)
        if not _is_real_directory(root_info):
            return None
        entries = [(".", root_info.st_mode, _filesystem_identity(root_info), None)]
        pending = [(root, "")]
        while pending:
            current, parent = pending.pop()
            with os.scandir(current) as children:
                for child in children:
                    info = os.stat(child.path, follow_symlinks=False)
                    relative = os.path.join(parent, child.name).replace("\\", "/")
                    target = os.readlink(child.path) if _is_link_or_junction(info) else None
                    entries.append((relative, info.st_mode, _filesystem_identity(info), target))
                    if _is_real_directory(info):
                        pending.append((child.path, relative))
        return tuple(sorted(entries))
    except (OSError, ValueError):
        return None


def _validated_peer_link(link: str, root: str, peer: str, data_dir: str) -> tuple:
    """Record the complete in-root path to an optional installer peer link."""

    relative = os.path.relpath(link, root)
    parts = relative.split(os.sep)
    ancestors = []
    current = root
    for part in ("", *parts[:-1]):
        if part:
            current = os.path.join(current, part)
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            ancestors.append(None)
            return tuple(ancestors), None
        if not _is_real_directory(info):
            raise ValueError("peer path contains a non-directory entry")
        ancestors.append(_filesystem_identity(info))

    try:
        info = os.lstat(link)
    except FileNotFoundError:
        return tuple(ancestors), None
    if not _is_link_or_junction(info):
        raise ValueError("peer entry is not a link or junction")
    if _peer_path_uses_private_state(link, data_dir):
        raise ValueError("peer link points into private state")
    destination = os.path.realpath(link)
    if _path_within(os.path.realpath(root), destination):
        raise ValueError("peer link points inside the package")
    if peer != "openclaw":
        raise ValueError("peer link is not the OpenClaw package")
    target = os.stat(destination, follow_symlinks=False)
    if not stat.S_ISDIR(target.st_mode):
        raise ValueError("peer link target is not a directory")
    manifest = _read_regular_file(
        os.path.join(destination, "package.json"), max_bytes=1024 * 1024,
    )
    if manifest is None or json.loads(manifest).get("name") != peer:
        raise ValueError("peer link target has another package identity")
    # The validated target is bound by its volume and file ID, not only by
    # its path and manifest, so a different directory at the same path is
    # judged again.
    return tuple(ancestors), (
        _filesystem_identity(info), os.readlink(link), destination,
        (target.st_dev, target.st_ino), manifest,
    )


def _peer_path_uses_private_state(link: str, data_dir: str) -> bool:
    """Check every named and every resolved location on the way to the peer.

    A protected name can appear in a link or junction target, where a later
    alias could hide it, or only after resolution, behind an alias with an
    ordinary name. Both are checked at every hop, so an alias kind this walk
    does not expand is still judged by where it resolves. Every location is
    judged as a whole path, from its anchor (a UNC server and share are names
    too) to its last name, and the final destination is judged again.
    """

    from defenseclaw.config import default_data_path

    roots = {os.path.realpath(str(default_data_path()))}
    if data_dir:
        roots.add(os.path.realpath(data_dir))

    def private(location: str) -> bool:
        resolved = os.path.realpath(location)
        return (
            _names_private_state(location)
            or _names_private_state(resolved)
            or any(_path_within(root, resolved) for root in roots)
        )

    target = _on_link_drive(os.readlink(link), link)
    path = target if os.path.isabs(target) else os.path.join(os.path.dirname(link), target)
    if not os.path.isabs(path):
        path = os.path.join(os.getcwd(), path)
    parts = Path(path).parts
    current = _path_anchor(path)
    if private(_exact_location(current, last=False)):
        return True
    pending = list(parts[1:])
    # Whether a separator follows the last name of the complete path.
    trailing = _ends_with_separator(path)
    links = 0
    steps = 0
    while pending:
        steps += 1
        if steps > 256:
            raise ValueError("peer path is too deep")
        part = pending.pop(0)
        if part == "..":
            current = os.path.dirname(current)
            continue
        current = os.path.join(current, part)
        # A location is the one this name selects within the complete path,
        # not the one a shorter path ending at the same name would select.
        location = _exact_location(current, last=not pending and not trailing)
        if private(location):
            return True
        try:
            alias = _is_link_or_junction(os.lstat(location))
        except FileNotFoundError:
            alias = False
        if alias:
            links += 1
            if links > 40:
                raise ValueError("peer path has too many links")
            next_target = _on_link_drive(os.readlink(location), location)
            if not pending:
                trailing = _ends_with_separator(next_target)
            target_parts = Path(next_target).parts
            if os.path.isabs(next_target):
                current = _path_anchor(next_target)
                if private(current):
                    return True
                pending = list(target_parts[1:]) + pending
            else:
                current = os.path.dirname(current)
                pending = list(target_parts) + pending
    destination = os.path.realpath(link)
    return _names_private_state(destination) or any(
        _path_within(root, destination) for root in roots
    )


def _names_private_state(path: str) -> bool:
    """Check every name that selects a location, UNC server and share included."""

    return any(
        name.casefold() in _PRIVATE_INSTALL_COMPONENTS for name in _location_names(path)
    )


def _path_within(root: str, path: str) -> bool:
    """Containment for resolved absolute paths; another drive or share is outside.

    Whole names are compared as the filesystem sees them, so a share root names
    the same location with or without its trailing separator, and a device or
    extended-length spelling names the same location as the ordinary one.
    """

    windows = isinstance(Path(root), PureWindowsPath)

    def key(value: str) -> tuple[str, ...]:
        names = _location_names(value)
        return tuple(name.casefold() for name in names) if windows else names

    root_names, path_names = key(root), key(path)
    return bool(root_names) and path_names[:len(root_names)] == root_names


# Windows passes a path that starts exactly with one of these to the filesystem
# without normalizing its names.
_WINDOWS_VERBATIM_PREFIXES = ("\\\\?\\", "\\??\\")
_WINDOWS_DEVICE_PREFIX = re.compile(r"^(?:[\\/]{2}[.?][\\/]|\\\?\?\\)(?:UNC[\\/])?", re.I)


def _path_anchor(path: str) -> str:
    """The first part of a path, in the namespace the path spells.

    The parsed anchor of a device path written with forward slashes is spelled
    with backslashes, which would read as extended-length; Windows normalizes
    such a path, so its anchor stays a device path.
    """

    anchor = Path(path).parts[0]
    if anchor.startswith(_WINDOWS_VERBATIM_PREFIXES) and not path.startswith(
        _WINDOWS_VERBATIM_PREFIXES,
    ):
        return "\\\\.\\" + anchor[4:]
    return anchor


def _location_names(path: str) -> tuple[str, ...]:
    """The names that select a location: anchor names first, then each name.

    A UNC server and share are names too. A device or extended-length prefix
    only selects the namespace, so it is not a name. Windows normalizes an
    ordinary path as a whole: a name before a separator drops one trailing dot
    (a name that ends in two or more dots is kept as written), and the last
    name, unless a separator follows it, drops all its trailing dots and
    spaces. The names of an extended-length path are used as written.
    """

    text = str(path)
    pure = Path(text)
    if not isinstance(pure, PureWindowsPath):
        return pure.parts
    verbatim = text.startswith(_WINDOWS_VERBATIM_PREFIXES)
    prefix = _WINDOWS_DEVICE_PREFIX.match(text)
    if prefix:
        unc = prefix.group(0)[4:].casefold().startswith("unc")
        pure = PureWindowsPath(("\\\\" if unc else "") + text[prefix.end():])
    names = [name for name in re.split(r"[\\/]+", pure.drive) if name]
    names += [pure.root] if pure.root else []
    names += pure.parts[1:] if pure.anchor else pure.parts
    if not verbatim:
        last = len(names) - 1 if not _ends_with_separator(text) else -1
        names = [
            _normalized_name(name, final=index == last) for index, name in enumerate(names)
        ]
    return tuple(names)


def _normalized_name(name: str, *, final: bool) -> str:
    """One name of an ordinary Windows path after the filesystem trimming.

    The last name of a path drops every trailing dot and space. A name before
    a separator drops a single trailing dot only; a longer run of dots is a
    distinct name and trailing spaces stay.
    """

    if final:
        return name.rstrip(". ") or name
    if name.endswith(".") and not name.endswith(".."):
        return name[:-1] or name
    return name


def _on_link_drive(target: str, link: str) -> str:
    """Give a link target that starts with one separator the drive of its link.

    Windows resolves such a target on the volume that holds the link, so every
    name of it is judged on that drive, as a drive-qualified path would be.
    """

    if not isinstance(Path(target), PureWindowsPath):
        return target
    pure = PureWindowsPath(target)
    if pure.drive or not pure.root:
        return target
    prefix = _WINDOWS_DEVICE_PREFIX.match(link)
    unc = bool(prefix) and prefix.group(0)[4:].casefold().startswith("unc")
    rest = link[prefix.end():] if prefix else link
    return PureWindowsPath(("\\\\" if unc else "") + rest).drive + target


def _ends_with_separator(path: str) -> bool:
    return isinstance(Path(path), PureWindowsPath) and path[-1:] in ("\\", "/")


def _exact_location(path: str, *, last: bool) -> str:
    """Spell a location so that Windows selects exactly the entry it names.

    Windows normalizes an ordinary path as a whole, so a name selects another
    entry at the end of the path than before a separator. The extended-length
    spelling of the names the complete path selects is used as written, so
    every check reads the entry the complete path reaches. Other paths are
    returned unchanged.
    """

    text = str(path)
    if not isinstance(Path(text), PureWindowsPath) or text.startswith(
        _WINDOWS_VERBATIM_PREFIXES,
    ):
        return text
    prefix = _WINDOWS_DEVICE_PREFIX.match(text)
    unc = bool(prefix) and prefix.group(0)[4:].casefold().startswith("unc")
    pure = PureWindowsPath(("\\\\" if unc else "") + text[prefix.end():] if prefix else text)
    unc = unc or pure.drive.startswith(("\\\\", "//"))
    if not pure.drive or not pure.root:
        return text
    names = _location_names(text if last else text + "\\")
    drive = [name for name in re.split(r"[\\/]+", pure.drive) if name]
    tail = names[len(drive) + 1:]
    head = "\\\\?\\UNC\\" if unc else "\\\\?\\"
    return head + "\\".join(names[:len(drive)]) + "\\" + "\\".join(tail)
