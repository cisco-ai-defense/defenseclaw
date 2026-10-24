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

import contextlib
import json
import os
import re
import sys

import click

from defenseclaw import ux

EXIT_FAILED = 1
EXIT_CONFIG_TOO_NEW = 2


def _default_data_dir() -> str:
    # The same resolution every other command uses (DEFENSECLAW_HOME, sudo).
    from defenseclaw.config import default_data_path

    return str(default_data_path())


def _validate_from_version(_ctx, _param, value):
    # GAP-1449: any string used to be accepted. Installer values are package
    # versions (0.8.10, 1.0.1.dev3, 0.8.10+local), so only the X.Y.Z prefix
    # is required.
    if value is None or re.match(r"v?\d+\.\d+\.\d+", value.strip()):
        return value
    raise click.BadParameter(
        f"{value!r} is not a release version; use X.Y.Z, for example 0.8.10",
    )


@click.command("migrate")
@click.option(
    "--check",
    is_flag=True,
    help=(
        "List pending steps without changing anything. Exit 0 when they can be applied "
        "(pending or not), 1 when they cannot, 2 when the config is from a newer release."
    ),
)
@click.option(
    "--from-version",
    default=None,
    metavar="X.Y.Z",
    callback=_validate_from_version,
    help="Version that wrote the data (0.x imports).",
)
@click.option("--data-dir", default=None, type=click.Path(file_okay=False), help="Data directory to migrate.")
@click.option("--openclaw-home", default=None, type=click.Path(file_okay=False), help="OpenClaw home directory.")
@click.option("--gateway-binary", default=None, type=click.Path(dir_okay=False), help="Gateway used by --check.")
@click.option("--json", "as_json", is_flag=True, help="Print the result as JSON.")
def migrate_cmd(check, from_version, data_dir, openclaw_home, gateway_binary, as_json) -> None:
    """Bring config and data to this version's schema."""
    from defenseclaw.migrations import ConfigTooNewError, MigrationError, display_step_name, migrate

    # A --from-version newer than this release is warned about where it is
    # read: a 0.x config without a cursor (migrations._warn_from_version_newer).
    # The installer passes the release it replaces, newer on a downgrade.

    # With --json, stdout carries only the JSON document; step progress goes to stderr.
    progress = contextlib.redirect_stdout(sys.stderr) if as_json else contextlib.nullcontext()
    try:
        with progress:
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
        # In check mode nothing ran: list the steps under "pending" and keep
        # "applied" empty so a script never mistakes a dry run for a migration.
        click.echo(
            json.dumps(
                {
                    "from_config_version": result.from_config_version,
                    "to_config_version": result.to_config_version,
                    "applied": [] if check else result.applied,
                    "pending": result.applied if check else [],
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
        # Pending is not success: a neutral marker, the step names, and how
        # they get applied (the installer and upgrade run them as well).
        ux.echo(
            f"  {ux.bold('•')} {len(result.applied)} migration step(s) pending "
            f"(config_version {result.from_config_version} -> {result.to_config_version}):"
        )
        for step in result.applied:
            ux.echo(f"    → {display_step_name(step)}")
        ux.subhead("Nothing was changed. 'defenseclaw migrate' (or the upgrade) applies them.")
    else:
        ux.ok(f"Migrated to config_version {result.to_config_version} ({len(result.applied)} step(s)).")
    if not check and not as_json and _upgraded_from_0x(result):
        _report_ignored_dotenv_keys(data_dir or _default_data_dir())


def _report_ignored_dotenv_keys(data_dir: str) -> None:
    """Name each 0.x .env control key this release no longer reads (GAP-0387)."""
    from defenseclaw.config import ignored_dotenv_control_keys

    keys = ignored_dotenv_control_keys(data_dir)
    if not keys:
        return
    env_path = os.path.join(data_dir, ".env")
    ux.warn(f"{env_path} sets {len(keys)} variable(s) DefenseClaw no longer reads from .env:")
    for entry in keys:
        ux.subhead(entry, indent="    ")
    ux.subhead(f"Then remove those lines from {env_path}; 'defenseclaw doctor' lists them until then.", indent="    ")


# The first config_version a 1.x release wrote: below it is a 0.x config,
# whose hooks 0.8.x sealed with the global fail mode.
_FIRST_1X_CONFIG_VERSION = 8


def _upgraded_from_0x(result) -> bool:
    """Whether this run migrated a 0.x config that may contain ignored .env keys."""
    source = result.from_config_version
    return bool(result.applied) and source is not None and source < _FIRST_1X_CONFIG_VERSION
