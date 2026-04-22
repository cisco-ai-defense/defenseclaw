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

"""Shared Click context types used by command modules."""

from __future__ import annotations

import click


class AppContext:
    """Shared application context passed through Click."""

    def __init__(self) -> None:
        self.cfg = None
        self.store = None
        self.logger = None


pass_ctx = click.make_pass_decorator(AppContext, ensure=True)

# Alias for command modules that import `pass_context`.
pass_context = pass_ctx
