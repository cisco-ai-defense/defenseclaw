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

"""Registry utilities — fetch plugins from npm, clawhub://, or HTTP URLs.

Provides source detection and download/extract helpers reusable by both
``plugin install`` and any future registry-aware commands.
"""

from __future__ import annotations

import os
import subprocess
import tarfile
import zipfile
from enum import Enum
from urllib.parse import quote as urlquote
from urllib.parse import urljoin

import requests

from defenseclaw.registries.adapters._base import _PinnedConnect
from defenseclaw.registries.ssrf import (
    Resolver,
    SSRFError,
    guard_url,
    resolve_and_pin,
)

MAX_DOWNLOAD_BYTES = 100 * 1024 * 1024  # 100 MB safety cap
DEFAULT_NPM_REGISTRY = "https://registry.npmjs.org"
DOWNLOAD_TIMEOUT = 120
METADATA_TIMEOUT = 30


class SourceType(Enum):
    LOCAL = "local"
    NPM = "npm"
    CLAWHUB = "clawhub"
    HTTP = "http"


class RegistryError(Exception):
    """Raised when a registry fetch fails."""


def detect_source(name_or_path: str) -> SourceType:
    """Determine the install source from user input."""
    if name_or_path.startswith("clawhub://"):
        return SourceType.CLAWHUB
    if name_or_path.startswith(("http://", "https://")):
        return SourceType.HTTP
    if os.path.isdir(name_or_path) or name_or_path.startswith(("/", "./")):
        return SourceType.LOCAL
    return SourceType.NPM


def parse_clawhub_uri(uri: str) -> tuple[str, str | None]:
    """Parse ``clawhub://name[@version]`` into (name, version_or_None)."""
    path = uri.removeprefix("clawhub://")
    if not path:
        return ("", None)
    if "@" in path:
        name, version = path.split("@", 1)
        return (name, version)
    return (path, None)


def _npm_metadata_url(package_name: str, version: str | None, registry_url: str) -> str:
    """Build the npm registry metadata URL, handling scoped packages."""
    tag = version or "latest"
    if package_name.startswith("@"):
        encoded = urlquote(package_name, safe="")
        return f"{registry_url}/{encoded}/{tag}"
    return f"{registry_url}/{package_name}/{tag}"


def _stream_download(
    url: str,
    dest_path: str,
    *,
    allow_private: bool = False,
    resolver: Resolver | None = None,
) -> None:
    """Download a URL to *dest_path* with streaming, a size cap, and SSRF guards.

    F-0347: the legacy archive download used a bare
    ``requests.get(url, stream=True)`` with neither an SSRF check nor
    redirect control, so a hostile registry or package publisher could
    point the download (directly or via a 30x ``Location``) at loopback,
    private, link-local, or RFC 6598 CGNAT hosts — exactly the SSRF
    pattern the central guard exists to stop. We now:

    * validate + pin every hop through
      :func:`defenseclaw.registries.ssrf.resolve_and_pin`;
    * pin the TCP connect to the vetted IP (``_PinnedConnect``) so a
      low-TTL DNS rebind cannot swap in an internal address between the
      check and the connect;
    * follow redirects manually with ``allow_redirects=False`` so each
      hop is re-validated instead of trusting :mod:`requests` to follow
      an attacker-chosen ``Location``.

    ``allow_private`` mirrors the operator opt-in used elsewhere;
    ``resolver`` is plumbed to the guard so tests can stub DNS without
    network access.
    """
    try:
        ip, host, port = resolve_and_pin(
            url, allow_private=allow_private, resolver=resolver
        )
    except SSRFError as exc:
        raise RegistryError(
            f"refusing to download from unsafe URL: {exc}"
        ) from exc

    pin = _PinnedConnect(host, port, ip)
    current_url = url
    with pin:
        resp = requests.get(
            current_url, timeout=DOWNLOAD_TIMEOUT, stream=True, allow_redirects=False,
        )
        try:
            hops = 0
            while getattr(resp, "is_redirect", False) and hops < 5:
                location = resp.headers.get("Location")
                if not location:
                    raise RegistryError(
                        f"redirect with empty Location header from {current_url}"
                    )
                if not location.lower().startswith(("http://", "https://")):
                    location = urljoin(current_url, location)
                try:
                    next_ip, next_host, next_port = resolve_and_pin(
                        location, allow_private=allow_private, resolver=resolver,
                    )
                except SSRFError as exc:
                    raise RegistryError(
                        f"redirect blocked by SSRF guard: {exc}"
                    ) from exc
                resp.close()
                pin.repin(next_host, next_port, next_ip)
                resp = requests.get(
                    location, timeout=DOWNLOAD_TIMEOUT, stream=True,
                    allow_redirects=False,
                )
                current_url = location
                hops += 1
            if getattr(resp, "is_redirect", False):
                raise RegistryError(
                    f"too many redirects starting from {url}"
                )
            resp.raise_for_status()
            total = 0
            with open(dest_path, "wb") as f:
                for chunk in resp.iter_content(chunk_size=65536):
                    total += len(chunk)
                    if total > MAX_DOWNLOAD_BYTES:
                        raise RegistryError(
                            f"download exceeds {MAX_DOWNLOAD_BYTES // (1024 * 1024)} MB limit"
                        )
                    f.write(chunk)
        finally:
            resp.close()


def _extract_archive(archive_path: str, dest_dir: str, *, prefix: str = "") -> None:
    """Extract a tar.gz or zip archive into *dest_dir*.

    If *prefix* is given (e.g. ``package/plugins/foo/``), only entries under
    that prefix are extracted (tar only) with the prefix stripped.

    Zip extraction includes path-traversal protection.
    """
    if tarfile.is_tarfile(archive_path):
        if prefix:
            strip = prefix.count("/")
            result = subprocess.run(
                [
                    "tar", "xzf", archive_path,
                    "-C", dest_dir,
                    f"--strip-components={strip}",
                    prefix,
                ],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                raise RegistryError(
                    f"tar extraction failed (exit {result.returncode}): "
                    f"{result.stderr.strip()[:200]}"
                )
        else:
            with tarfile.open(archive_path) as tf:
                try:
                    tf.extractall(dest_dir, filter="data")
                except TypeError:
                    # Python <3.12 lacks the `filter`
                    # parameter. The legacy fallback called
                    # tf.extractall(dest_dir) WITHOUT any path-
                    # traversal validation, so a malicious tar with
                    # `../escape`, absolute-path members, symlinks
                    # pointing outside the dest, hardlinks, or
                    # special device files could write outside
                    # dest_dir before the plugin was scanned. We
                    # reproduce the Python 3.12 "data" filter
                    # contract by hand: regular files and dirs only,
                    # all paths must resolve under dest_dir, and
                    # anything that looks like traversal is fatal.
                    safe_root = os.path.realpath(dest_dir)
                    members: list[tarfile.TarInfo] = []
                    for m in tf.getmembers():
                        # Reject anything that isn't a plain file or
                        # directory. The 3.12+ data filter does the
                        # same — symlinks/hardlinks/devices/FIFOs
                        # have no place inside a plugin tarball.
                        if not (m.isfile() or m.isdir()):
                            raise RegistryError(
                                f"tar contains non-regular member: {m.name!r} "
                                f"(type={m.type!r}, )"
                            )
                        # Tar members are POSIX paths regardless of
                        # the host OS; split on `/` and `\\` so we
                        # catch traversal attempts on Windows hosts
                        # too.
                        normalized = m.name.replace("\\", "/")
                        if normalized.startswith("/") or normalized.startswith("\\"):
                            raise RegistryError(
                                f"tar contains absolute-path entry: {m.name!r}"
                            )
                        parts = os.path.normpath(normalized).split("/")
                        if ".." in parts:
                            raise RegistryError(
                                f"tar contains path-traversal entry: {m.name!r}"
                            )
                        member_path = os.path.realpath(
                            os.path.join(dest_dir, normalized)
                        )
                        if (member_path != safe_root
                                and not member_path.startswith(safe_root + os.sep)):
                            raise RegistryError(
                                f"tar contains path-traversal entry: {m.name!r}"
                            )
                        members.append(m)
                    tf.extractall(dest_dir, members=members)
    elif zipfile.is_zipfile(archive_path):
        safe_root = os.path.realpath(dest_dir)
        with zipfile.ZipFile(archive_path) as zf:
            for member in zf.infolist():
                member_path = os.path.realpath(
                    os.path.join(dest_dir, member.filename),
                )
                if not member_path.startswith(safe_root + os.sep) and member_path != safe_root:
                    raise RegistryError(
                        f"zip contains path-traversal entry: {member.filename}"
                    )
            zf.extractall(dest_dir)
    else:
        raise RegistryError("unsupported archive format (expected .tar.gz or .zip)")


def _normalize_extracted(dest_dir: str) -> str:
    """If the archive contained a single top-level directory, return it."""
    entries = os.listdir(dest_dir)
    if len(entries) == 1:
        single = os.path.join(dest_dir, entries[0])
        if os.path.isdir(single):
            return single
    return dest_dir


def fetch_npm_package(
    package_name: str,
    dest_dir: str,
    registry_url: str = DEFAULT_NPM_REGISTRY,
    version: str | None = None,
    *,
    allow_private: bool = False,
    resolver: Resolver | None = None,
) -> str:
    """Fetch a package from the npm registry and extract it into *dest_dir*.

    Returns the path to the extracted plugin root directory.
    """
    meta_url = _npm_metadata_url(package_name, version, registry_url)
    # F-0347: the metadata GET also crosses the registry trust boundary,
    # so guard it before dialing (the tarball download itself is guarded
    # inside _stream_download).
    try:
        guard_url(meta_url, allow_private=allow_private, resolver=resolver)
    except SSRFError as exc:
        raise RegistryError(
            f"refusing npm registry lookup for unsafe URL: {exc}"
        ) from exc
    try:
        meta_resp = requests.get(meta_url, timeout=METADATA_TIMEOUT)
        meta_resp.raise_for_status()
        meta = meta_resp.json()
    except requests.RequestException as exc:
        raise RegistryError(f"npm registry lookup failed: {exc}") from exc

    tarball_url = meta.get("dist", {}).get("tarball")
    if not tarball_url:
        raise RegistryError(
            f"could not resolve tarball URL for {package_name!r} from npm"
        )

    archive_path = os.path.join(dest_dir, "package.tgz")
    try:
        _stream_download(
            tarball_url, archive_path,
            allow_private=allow_private, resolver=resolver,
        )
    except requests.RequestException as exc:
        raise RegistryError(f"tarball download failed: {exc}") from exc

    extract_dir = os.path.join(dest_dir, "extracted")
    os.makedirs(extract_dir, exist_ok=True)
    _extract_archive(archive_path, extract_dir)
    os.unlink(archive_path)

    return _normalize_extracted(extract_dir)


def fetch_from_clawhub(
    uri: str,
    dest_dir: str,
    plugin_name: str | None = None,
    *,
    allow_private: bool = False,
    resolver: Resolver | None = None,
) -> str:
    """Fetch a plugin from the clawhub registry (npm ``openclaw`` package).

    Returns the path to the extracted plugin directory.
    """
    name, version = parse_clawhub_uri(uri)
    if not name:
        raise RegistryError(f"invalid clawhub URI: {uri}")
    if plugin_name is None:
        plugin_name = name

    meta_url = f"{DEFAULT_NPM_REGISTRY}/openclaw/latest"
    # F-0347: guard the metadata GET before dialing.
    try:
        guard_url(meta_url, allow_private=allow_private, resolver=resolver)
    except SSRFError as exc:
        raise RegistryError(
            f"refusing npm registry lookup for unsafe URL: {exc}"
        ) from exc
    try:
        meta = requests.get(meta_url, timeout=METADATA_TIMEOUT).json()
        tarball_url = meta.get("dist", {}).get("tarball")
    except requests.RequestException as exc:
        raise RegistryError(f"npm registry lookup failed: {exc}") from exc

    if not tarball_url:
        raise RegistryError("could not resolve openclaw tarball URL from npm")

    archive_path = os.path.join(dest_dir, "openclaw.tgz")
    try:
        _stream_download(
            tarball_url, archive_path,
            allow_private=allow_private, resolver=resolver,
        )
    except requests.RequestException as exc:
        raise RegistryError(f"tarball download failed: {exc}") from exc

    plugin_prefix = f"package/plugins/{plugin_name}/"
    extract_dir = os.path.join(dest_dir, "plugin")
    os.makedirs(extract_dir, exist_ok=True)

    try:
        _extract_archive(archive_path, extract_dir, prefix=plugin_prefix)
    except RegistryError:
        raise RegistryError(
            f"plugin {plugin_name!r} not found in openclaw package"
        )

    os.unlink(archive_path)

    if not os.listdir(extract_dir):
        raise RegistryError(
            f"plugin {plugin_name!r} not found in openclaw package"
        )

    return extract_dir


def fetch_from_url(
    url: str,
    dest_dir: str,
    *,
    allow_private: bool = False,
    resolver: Resolver | None = None,
) -> str:
    """Download a plugin archive from a direct HTTP(S) URL and extract it.

    Returns the path to the extracted plugin root directory.
    """
    archive_path = os.path.join(dest_dir, "download")
    try:
        _stream_download(
            url, archive_path, allow_private=allow_private, resolver=resolver,
        )
    except requests.RequestException as exc:
        raise RegistryError(f"download failed: {exc}") from exc

    extract_dir = os.path.join(dest_dir, "plugin")
    os.makedirs(extract_dir, exist_ok=True)
    _extract_archive(archive_path, extract_dir)
    os.unlink(archive_path)

    return _normalize_extracted(extract_dir)
