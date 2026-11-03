# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Give one module a test platform without changing Python's shared ``os``."""

import os
from types import ModuleType


def os_view(name: str) -> ModuleType:
    view = ModuleType("os")
    view.__dict__.update(vars(os))
    view.name = name
    return view
