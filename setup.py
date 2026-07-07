# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Build hooks for package-local runtime assets."""

from __future__ import annotations

import shutil
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py


class BuildPyWithRuntimeAssets(build_py):
    """Copy authoritative non-Python runtime assets into every wheel build."""

    def run(self) -> None:
        super().run()
        root = Path(__file__).resolve().parent
        source = root / "bundles" / "local_observability_stack"
        destination = (
            Path(self.build_lib)
            / "defenseclaw"
            / "_data"
            / "local_observability_stack"
        )
        if not source.is_dir():
            raise RuntimeError(f"required local observability bundle is missing: {source}")
        shutil.rmtree(destination, ignore_errors=True)
        shutil.copytree(source, destination)

        registry_source = root / "internal" / "envvars" / "registry.json"
        registry_destination = (
            Path(self.build_lib) / "defenseclaw" / "_data" / "envvars" / "registry.json"
        )
        if not registry_source.is_file():
            raise RuntimeError(f"required environment registry is missing: {registry_source}")
        registry_destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(registry_source, registry_destination)


setup(cmdclass={"build_py": BuildPyWithRuntimeAssets})
