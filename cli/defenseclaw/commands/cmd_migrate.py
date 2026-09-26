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

"""defenseclaw migrate — bring config and data to this version's schema.

The installer runs this from the version it just installed, with the gateway
stopped. Operators rarely need it directly; it is safe to re-run.

Exit codes: 0 done (or nothing to do), 1 a step failed, 2 the configuration
was written by a newer DefenseClaw than this one.
"""

from __future__ import annotations

import json
import os

import click

from defenseclaw import ux

EXIT_FAILED = 1
EXIT_CONFIG_TOO_NEW = 2


def _default_data_dir() -> str:
    return os.environ.get("DEFENSECLAW_HOME") or os.path.expanduser("~/.defenseclaw")


@click.command("migrate")
@click.option("--check", is_flag=True, help="Report pending steps without changing anything.")
@click.option("--from-version", default=None, metavar="X.Y.Z", help="Version that wrote the data (0.x imports).")
@click.option("--data-dir", default=None, type=click.Path(file_okay=False), help="Data directory to migrate.")
@click.option("--openclaw-home", default=None, type=click.Path(file_okay=False), help="OpenClaw home directory.")
@click.option("--gateway-binary", default=None, type=click.Path(dir_okay=False), help="Gateway used by --check.")
@click.option("--json", "as_json", is_flag=True, help="Print the result as JSON.")
@click.option("--yes", "-y", is_flag=True, hidden=True, help="Accepted for installer compatibility.")
def migrate_cmd(check, from_version, data_dir, openclaw_home, gateway_binary, as_json, yes) -> None:
    """Bring config and data to this version's schema."""
    del yes
    from defenseclaw.migrations import ConfigTooNewError, MigrationError, migrate

    try:
        result = migrate(
            data_dir or _default_data_dir(),
            openclaw_home=openclaw_home,
            from_version=from_version,
            check=check,
            gateway_binary=gateway_binary,
        )
    except ConfigTooNewError as exc:
        ux.err(str(exc))
        raise SystemExit(EXIT_CONFIG_TOO_NEW) from None
    except MigrationError as exc:
        ux.err(str(exc))
        raise SystemExit(EXIT_FAILED) from None

    if as_json:
        click.echo(
            json.dumps(
                {
                    "from_config_version": result.from_config_version,
                    "to_config_version": result.to_config_version,
                    "applied": result.applied,
                    "changed": result.changed,
                    "check": check,
                },
                sort_keys=True,
            )
        )
    elif result.from_config_version is None:
        ux.ok("No configuration yet; nothing to migrate.")
    elif not result.applied:
        ux.ok(f"Configuration is current (config_version {result.to_config_version}).")
    elif check:
        ux.ok(f"{len(result.applied)} migration step(s) pending.")
    else:
        ux.ok(f"Migrated to config_version {result.to_config_version} ({len(result.applied)} step(s)).")
