# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0
"""DefenseClaw docs-site generator package.

Emits MDX fragments into AUTOGEN blocks under ``docs-site/``.
See ``docs-site/_meta/AUTOGEN.md`` for the sentinel contract.
"""

from __future__ import annotations

__all__ = ["mdx", "splice", "cli_py", "cli_go", "schemas", "env_vars",
           "exit_codes", "providers", "otel_spec", "rules", "rego_mod"]
