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


class BuildPyWithLocalObservability(build_py):
    """Copy the maintained Compose bundle directly into every wheel build."""

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


setup(cmdclass={"build_py": BuildPyWithLocalObservability})
