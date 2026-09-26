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

"""defenseclaw upgrade / rollback — Click wrappers around the upgrade shim.

The console entry point (``defenseclaw.entry``) dispatches these commands to
:mod:`defenseclaw.upgrade_shim` before the CLI is imported. These wrappers
keep ``python -m defenseclaw.main upgrade`` and ``--help`` working.
"""

from __future__ import annotations

import click


@click.command("upgrade")
@click.option("--version", "target_version", default=None, metavar="X.Y.Z", help="Install this release.")
@click.option("--yes", "-y", is_flag=True, help="Do not prompt.")
def upgrade(target_version: str | None, yes: bool) -> None:
    """Upgrade to the latest release (or X.Y.Z) using that release's installer."""
    from defenseclaw.upgrade_shim import run

    args = ["upgrade"] + (["--version", target_version] if target_version else []) + (["--yes"] if yes else [])
    raise SystemExit(run(args))


@click.command("rollback")
@click.option("--yes", "-y", is_flag=True, help="Do not prompt.")
def rollback(yes: bool) -> None:
    """Restore the install that the last upgrade replaced."""
    from defenseclaw.upgrade_shim import run

    raise SystemExit(run(["rollback"] + (["--yes"] if yes else [])))
