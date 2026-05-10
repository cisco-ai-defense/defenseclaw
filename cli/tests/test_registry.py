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

"""Tests for defenseclaw.registry — source detection & download helpers."""

from __future__ import annotations

import io
import os
import tarfile
import tempfile
import unittest
import zipfile
from unittest.mock import MagicMock, patch

try:
    import pytest
except ImportError:
    raise unittest.SkipTest("pytest not available")

from defenseclaw.registry import (
    DEFAULT_NPM_REGISTRY,
    MAX_DOWNLOAD_BYTES,
    RegistryError,
    SourceType,
    _extract_archive,
    _normalize_extracted,
    _stream_download,
    detect_source,
    fetch_from_clawhub,
    fetch_from_url,
    fetch_npm_package,
    parse_clawhub_uri,
)


# ---------------------------------------------------------------------------
# detect_source
# ---------------------------------------------------------------------------

class TestDetectSource:
    def test_local_existing_dir(self, tmp_path):
        d = tmp_path / "my-plugin"
        d.mkdir()
        assert detect_source(str(d)) == SourceType.LOCAL

    def test_local_absolute_path(self):
        assert detect_source("/some/path/plugin") == SourceType.LOCAL

    def test_local_relative_path(self):
        assert detect_source("./local-dir") == SourceType.LOCAL

    def test_npm_bare_name(self):
        assert detect_source("my-plugin") == SourceType.NPM

    def test_npm_scoped(self):
        assert detect_source("@openclasw/voice-call") == SourceType.NPM

    def test_clawhub(self):
        assert detect_source("clawhub://voice-call") == SourceType.CLAWHUB

    def test_clawhub_with_version(self):
        assert detect_source("clawhub://voice-call@1.0.0") == SourceType.CLAWHUB

    def test_http(self):
        assert detect_source("https://example.com/plugin.tgz") == SourceType.HTTP

    def test_http_insecure(self):
        assert detect_source("http://example.com/plugin.tgz") == SourceType.HTTP


# ---------------------------------------------------------------------------
# parse_clawhub_uri
# ---------------------------------------------------------------------------

class TestParseClawhubUri:
    def test_name_only(self):
        assert parse_clawhub_uri("clawhub://voice-call") == ("voice-call", None)

    def test_name_with_version(self):
        assert parse_clawhub_uri("clawhub://voice-call@2.1.0") == ("voice-call", "2.1.0")

    def test_empty(self):
        assert parse_clawhub_uri("clawhub://") == ("", None)


# ---------------------------------------------------------------------------
# Helpers for building test archives
# ---------------------------------------------------------------------------

def _make_tgz(members: dict[str, str]) -> bytes:
    """Build a .tar.gz in memory with the given filename->content map."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, content in members.items():
            data = content.encode()
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _make_zip(members: dict[str, str]) -> bytes:
    """Build a .zip in memory with the given filename->content map."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in members.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _mock_response(content: bytes, status_code: int = 200):
    """Build a mock requests.Response with streaming support."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.raise_for_status = MagicMock()
    if status_code >= 400:
        import requests
        resp.raise_for_status.side_effect = requests.HTTPError(
            response=resp
        )
    resp.iter_content = MagicMock(return_value=iter([content]))
    return resp


# ---------------------------------------------------------------------------
# fetch_npm_package
# ---------------------------------------------------------------------------

class TestFetchNpmPackage:
    @patch("defenseclaw.registry.requests")
    def test_success(self, mock_requests, tmp_path):
        tgz = _make_tgz({
            "package/index.js": "module.exports = {};",
            "package/package.json": '{"name":"my-plugin","version":"1.0.0"}',
        })
        meta_resp = MagicMock()
        meta_resp.json.return_value = {"dist": {"tarball": "https://r.npm/my-plugin.tgz"}}
        meta_resp.raise_for_status = MagicMock()

        dl_resp = _mock_response(tgz)

        mock_requests.get.side_effect = [meta_resp, dl_resp]

        dest = str(tmp_path / "work")
        os.makedirs(dest)
        result = fetch_npm_package("my-plugin", dest)

        assert os.path.isdir(result)
        assert mock_requests.get.call_count == 2
        first_url = mock_requests.get.call_args_list[0][0][0]
        assert first_url == f"{DEFAULT_NPM_REGISTRY}/my-plugin/latest"

    @patch("defenseclaw.registry.requests")
    def test_scoped_package_url_encoding(self, mock_requests, tmp_path):
        tgz = _make_tgz({"package/index.js": ""})
        meta_resp = MagicMock()
        meta_resp.json.return_value = {"dist": {"tarball": "https://r.npm/pkg.tgz"}}
        meta_resp.raise_for_status = MagicMock()

        mock_requests.get.side_effect = [meta_resp, _mock_response(tgz)]

        dest = str(tmp_path / "work")
        os.makedirs(dest)
        fetch_npm_package("@openclasw/voice-call", dest)

        first_url = mock_requests.get.call_args_list[0][0][0]
        assert "%40openclasw%2Fvoice-call" in first_url

    @patch("defenseclaw.registry.requests")
    def test_registry_404(self, mock_requests, tmp_path):
        import requests as real_requests
        meta_resp = MagicMock()
        meta_resp.raise_for_status.side_effect = real_requests.HTTPError(
            response=MagicMock(status_code=404)
        )
        mock_requests.get.return_value = meta_resp
        mock_requests.RequestException = real_requests.RequestException

        dest = str(tmp_path / "work")
        os.makedirs(dest)
        with pytest.raises(RegistryError, match="npm registry lookup failed"):
            fetch_npm_package("nonexistent-pkg", dest)

    @patch("defenseclaw.registry.requests")
    def test_no_tarball_in_metadata(self, mock_requests, tmp_path):
        meta_resp = MagicMock()
        meta_resp.json.return_value = {"dist": {}}
        meta_resp.raise_for_status = MagicMock()
        mock_requests.get.return_value = meta_resp

        dest = str(tmp_path / "work")
        os.makedirs(dest)
        with pytest.raises(RegistryError, match="could not resolve tarball URL"):
            fetch_npm_package("bad-pkg", dest)


# ---------------------------------------------------------------------------
# fetch_from_url
# ---------------------------------------------------------------------------

class TestFetchFromUrl:
    @patch("defenseclaw.registry.requests")
    def test_tarball(self, mock_requests, tmp_path):
        tgz = _make_tgz({
            "my-plugin/index.js": "// plugin code",
            "my-plugin/package.json": "{}",
        })
        mock_requests.get.return_value = _mock_response(tgz)

        dest = str(tmp_path / "work")
        os.makedirs(dest)
        result = fetch_from_url("https://example.com/plugin.tgz", dest)

        assert os.path.isdir(result)
        assert "index.js" in os.listdir(result)

    @patch("defenseclaw.registry.requests")
    def test_zip(self, mock_requests, tmp_path):
        z = _make_zip({
            "my-plugin/index.js": "// plugin code",
        })
        mock_requests.get.return_value = _mock_response(z)

        dest = str(tmp_path / "work")
        os.makedirs(dest)
        result = fetch_from_url("https://example.com/plugin.zip", dest)

        assert os.path.isdir(result)

    @patch("defenseclaw.registry.requests")
    def test_zip_path_traversal_blocked(self, mock_requests, tmp_path):
        z = _make_zip({
            "../../etc/passwd": "root:x:0:0",
        })
        mock_requests.get.return_value = _mock_response(z)

        dest = str(tmp_path / "work")
        os.makedirs(dest)
        with pytest.raises(RegistryError, match="path-traversal"):
            fetch_from_url("https://example.com/evil.zip", dest)

    @patch("defenseclaw.registry.requests")
    def test_unsupported_format(self, mock_requests, tmp_path):
        mock_requests.get.return_value = _mock_response(b"this is not an archive")

        dest = str(tmp_path / "work")
        os.makedirs(dest)
        with pytest.raises(RegistryError, match="unsupported archive format"):
            fetch_from_url("https://example.com/plugin.exe", dest)

    @patch("defenseclaw.registry.requests")
    def test_network_error(self, mock_requests, tmp_path):
        import requests as real_requests
        mock_requests.get.side_effect = real_requests.ConnectionError("refused")
        mock_requests.RequestException = real_requests.RequestException

        dest = str(tmp_path / "work")
        os.makedirs(dest)
        with pytest.raises(RegistryError, match="download failed"):
            fetch_from_url("https://example.com/plugin.tgz", dest)


# ---------------------------------------------------------------------------
# fetch_from_clawhub
# ---------------------------------------------------------------------------

class TestFetchFromClawhub:
    @patch("defenseclaw.registry.requests")
    def test_success(self, mock_requests, tmp_path):
        tgz = _make_tgz({
            "package/plugins/voice-call/index.js": "// voice call",
            "package/plugins/voice-call/package.json": "{}",
        })
        meta_resp = MagicMock()
        meta_resp.json.return_value = {"dist": {"tarball": "https://r.npm/openclaw.tgz"}}
        meta_resp.raise_for_status = MagicMock()

        mock_requests.get.side_effect = [meta_resp, _mock_response(tgz)]

        dest = str(tmp_path / "work")
        os.makedirs(dest)
        result = fetch_from_clawhub("clawhub://voice-call", dest)

        assert os.path.isdir(result)

    @patch("defenseclaw.registry.requests")
    def test_invalid_uri(self, mock_requests, tmp_path):
        dest = str(tmp_path / "work")
        os.makedirs(dest)
        with pytest.raises(RegistryError, match="invalid clawhub URI"):
            fetch_from_clawhub("clawhub://", dest)


# ---------------------------------------------------------------------------
# _stream_download — size limit enforcement
# ---------------------------------------------------------------------------

class TestStreamDownloadSizeLimit:
    @patch("defenseclaw.registry.requests")
    def test_exceeds_max_download_bytes(self, mock_requests, tmp_path):
        oversized_chunk = b"x" * (MAX_DOWNLOAD_BYTES + 1)
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.iter_content.return_value = iter([oversized_chunk])
        mock_requests.get.return_value = resp

        dest = str(tmp_path / "download")
        with pytest.raises(RegistryError, match="MB limit"):
            _stream_download("https://example.com/huge.tgz", dest)

    @patch("defenseclaw.registry.requests")
    def test_multiple_chunks_exceed_limit(self, mock_requests, tmp_path):
        half = MAX_DOWNLOAD_BYTES // 2 + 1
        chunk = b"x" * half
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.iter_content.return_value = iter([chunk, chunk])
        mock_requests.get.return_value = resp

        dest = str(tmp_path / "download")
        with pytest.raises(RegistryError, match="MB limit"):
            _stream_download("https://example.com/huge.tgz", dest)

    @patch("defenseclaw.registry.requests")
    def test_within_limit_succeeds(self, mock_requests, tmp_path):
        small_chunk = b"hello"
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.iter_content.return_value = iter([small_chunk])
        mock_requests.get.return_value = resp

        dest = str(tmp_path / "download")
        _stream_download("https://example.com/small.tgz", dest)
        assert os.path.isfile(dest)
        with open(dest, "rb") as f:
            assert f.read() == small_chunk


# ---------------------------------------------------------------------------
# _normalize_extracted — single-directory flattening
# ---------------------------------------------------------------------------

class TestNormalizeExtracted:
    def test_single_subdir_returns_it(self, tmp_path):
        inner = tmp_path / "package"
        inner.mkdir()
        (inner / "index.js").write_text("code")
        assert _normalize_extracted(str(tmp_path)) == str(inner)

    def test_multiple_entries_returns_parent(self, tmp_path):
        (tmp_path / "file_a.txt").write_text("a")
        (tmp_path / "file_b.txt").write_text("b")
        assert _normalize_extracted(str(tmp_path)) == str(tmp_path)

    def test_single_file_returns_parent(self, tmp_path):
        (tmp_path / "only_file.js").write_text("code")
        assert _normalize_extracted(str(tmp_path)) == str(tmp_path)

    def test_empty_dir_returns_parent(self, tmp_path):
        assert _normalize_extracted(str(tmp_path)) == str(tmp_path)


# ---------------------------------------------------------------------------
# _extract_archive — tar with prefix, tar path traversal
# ---------------------------------------------------------------------------

class TestExtractArchive:
    def test_tar_with_prefix_strips_components(self, tmp_path):
        tgz_bytes = _make_tgz({
            "package/plugins/voice-call/index.js": "// voice call plugin",
            "package/plugins/voice-call/package.json": '{"name":"voice-call"}',
            "package/plugins/other/index.js": "// should not appear",
        })
        archive = tmp_path / "test.tgz"
        archive.write_bytes(tgz_bytes)
        dest = tmp_path / "out"
        dest.mkdir()

        _extract_archive(str(archive), str(dest), prefix="package/plugins/voice-call/")
        extracted = os.listdir(str(dest))
        assert "index.js" in extracted
        assert "package.json" in extracted
        assert "other" not in extracted

    def test_tar_no_prefix_extracts_all(self, tmp_path):
        tgz_bytes = _make_tgz({
            "my-plugin/index.js": "code",
            "my-plugin/readme.md": "docs",
        })
        archive = tmp_path / "test.tgz"
        archive.write_bytes(tgz_bytes)
        dest = tmp_path / "out"
        dest.mkdir()

        _extract_archive(str(archive), str(dest))
        assert os.path.isdir(os.path.join(str(dest), "my-plugin"))

    def test_zip_path_traversal_detected(self, tmp_path):
        z_bytes = _make_zip({"../../etc/evil": "payload"})
        archive = tmp_path / "evil.zip"
        archive.write_bytes(z_bytes)
        dest = tmp_path / "out"
        dest.mkdir()

        with pytest.raises(RegistryError, match="path-traversal"):
            _extract_archive(str(archive), str(dest))

    def test_unsupported_format_raises(self, tmp_path):
        archive = tmp_path / "bad.bin"
        archive.write_bytes(b"not an archive at all")
        dest = tmp_path / "out"
        dest.mkdir()

        with pytest.raises(RegistryError, match="unsupported archive format"):
            _extract_archive(str(archive), str(dest))

    def test_tar_with_nonexistent_prefix_raises(self, tmp_path):
        tgz_bytes = _make_tgz({
            "package/plugins/other/index.js": "code",
        })
        archive = tmp_path / "test.tgz"
        archive.write_bytes(tgz_bytes)
        dest = tmp_path / "out"
        dest.mkdir()

        with pytest.raises(RegistryError, match="tar extraction failed"):
            _extract_archive(str(archive), str(dest), prefix="package/plugins/missing/")

    # ----------------------------------------------------------------
    # F-2390 fallback path-traversal validation. We force the legacy
    # fallback by stubbing tarfile.TarFile.extractall to raise
    # TypeError on the modern `filter="data"` keyword argument, the
    # exact shape Python <3.12 produces.
    # ----------------------------------------------------------------

    def test_tar_path_traversal_blocked_in_fallback(self, tmp_path,
                                                     monkeypatch):
        """F-2390: traversal entries must be rejected even when running
        under the legacy fallback that lacks the `filter="data"` arg."""
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            data = b"pwned"
            ti = tarfile.TarInfo(name="../escape.txt")
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
        archive = tmp_path / "evil.tgz"
        archive.write_bytes(buf.getvalue())
        dest = tmp_path / "out"
        dest.mkdir()

        # Force the fallback path by making the modern keyword raise.
        original_extractall = tarfile.TarFile.extractall

        def fake_extractall(self, *args, **kwargs):
            if "filter" in kwargs:
                raise TypeError("simulated <3.12 tarfile")
            return original_extractall(self, *args, **kwargs)

        monkeypatch.setattr(tarfile.TarFile, "extractall", fake_extractall)

        with pytest.raises(RegistryError, match="F-2390"):
            _extract_archive(str(archive), str(dest))
        # Confirm nothing leaked outside the dest dir.
        assert not (tmp_path / "escape.txt").exists()

    def test_tar_symlink_member_blocked_in_fallback(self, tmp_path,
                                                     monkeypatch):
        """F-2390: symlink members must be rejected (the 3.12+ "data"
        filter rejects them automatically; the fallback must too)."""
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            ti = tarfile.TarInfo(name="link-to-secret")
            ti.type = tarfile.SYMTYPE
            ti.linkname = "/etc/passwd"
            tf.addfile(ti)
        archive = tmp_path / "evil.tgz"
        archive.write_bytes(buf.getvalue())
        dest = tmp_path / "out"
        dest.mkdir()

        original_extractall = tarfile.TarFile.extractall

        def fake_extractall(self, *args, **kwargs):
            if "filter" in kwargs:
                raise TypeError("simulated <3.12 tarfile")
            return original_extractall(self, *args, **kwargs)

        monkeypatch.setattr(tarfile.TarFile, "extractall", fake_extractall)

        with pytest.raises(RegistryError, match="F-2390"):
            _extract_archive(str(archive), str(dest))
