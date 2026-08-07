# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""PEP 517 backend adapter for DefenseClaw release metadata."""

from __future__ import annotations

import os
from pathlib import Path

from setuptools import build_meta as _setuptools

build_sdist = _setuptools.build_sdist
build_wheel = _setuptools.build_wheel
get_requires_for_build_sdist = _setuptools.get_requires_for_build_sdist
get_requires_for_build_wheel = _setuptools.get_requires_for_build_wheel
prepare_metadata_for_build_wheel = _setuptools.prepare_metadata_for_build_wheel
get_requires_for_build_editable = _setuptools.get_requires_for_build_editable
prepare_metadata_for_build_editable = _setuptools.prepare_metadata_for_build_editable


def _editable_metadata_parent(metadata_directory: str | os.PathLike[str] | None) -> str | None:
    if metadata_directory is None:
        return None

    supplied = Path(metadata_directory)
    dist_info: Path | None
    if supplied.name.endswith(".dist-info"):
        parent = supplied.parent
        dist_info = supplied
    else:
        parent = supplied
        dist_info = None

    if parent.is_symlink() or not parent.is_dir():
        raise ValueError("editable metadata directory is unavailable")
    if dist_info is None:
        candidates = [path for path in parent.glob("*.dist-info") if path.is_dir() and not path.is_symlink()]
        if len(candidates) != 1:
            raise ValueError("editable metadata directory must contain exactly one .dist-info directory")
        dist_info = candidates[0]

    if dist_info.is_symlink() or not dist_info.is_dir():
        raise ValueError("editable .dist-info directory is unavailable")
    metadata = dist_info / "METADATA"
    if metadata.is_symlink() or not metadata.is_file():
        raise ValueError("editable .dist-info directory lacks METADATA")
    candidates = [path for path in parent.glob("*.dist-info") if path.is_dir() and not path.is_symlink()]
    if candidates != [dist_info]:
        raise ValueError("editable metadata directory does not identify one exact .dist-info directory")
    return os.fspath(parent)


def build_editable(
    wheel_directory: str | os.PathLike[str],
    config_settings: dict[str, object] | None = None,
    metadata_directory: str | os.PathLike[str] | None = None,
) -> str:
    normalized = _editable_metadata_parent(metadata_directory)
    return _setuptools.build_editable(wheel_directory, config_settings, normalized)
