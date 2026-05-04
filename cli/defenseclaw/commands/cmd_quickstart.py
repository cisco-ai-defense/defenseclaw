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

"""defenseclaw quickstart — zero-prompt first-run setup.

Designed for ``make all`` and ``install.sh --quickstart``. Picks safe
defaults (observe profile, local scanner, no judge) and runs every step
of the install flow without asking the user a single question. Power
users who want something different should use ``defenseclaw init`` or
``defenseclaw setup guardrail`` instead.
"""

from __future__ import annotations

import json
import sys

import click


@click.command("quickstart")
@click.option(
    "--mode",
    type=click.Choice(["observe", "action"], case_sensitive=False),
    default=None,
    show_default="observe",
    help="Protection profile. observe logs findings; action blocks.",
)
@click.option(
    "--scanner",
    "scanner_mode",
    type=click.Choice(["local", "remote", "both"], case_sensitive=False),
    default="local",
    show_default=True,
    help="Scanner backend. 'local' is the zero-key default; 'remote'/'both' require CISCO_AI_DEFENSE_API_KEY.",
)
@click.option(
    "--with-judge/--no-judge",
    "with_judge",
    default=False,
    help="Enable the LLM Judge adjudicator (reuses the unified DEFENSECLAW_LLM_KEY).",
)
@click.option(
    "--non-interactive",
    is_flag=True,
    help="Never prompt. Same as --yes; kept for install-script compat.",
)
@click.option(
    "--yes",
    is_flag=True,
    help="Assume yes for confirmations.",
)
@click.option(
    "--force",
    is_flag=True,
    help="Re-run all steps even if the environment is already initialized.",
)
@click.option(
    "--connector",
    "--agent",
    "agent_name",
    type=click.Choice(
        ["openclaw", "zeptoclaw", "claudecode", "codex"],
        case_sensitive=False,
    ),
    default=None,
    help="Agent framework connector (alias: --agent). "
         "Defaults to <data_dir>/picked_connector when set by the installer, "
         "else codex.",
)
@click.option(
    "--skip-gateway",
    is_flag=True,
    help="Do not start the sidecar at the end of quickstart.",
)
@click.option("--json-summary", is_flag=True, help="Emit the first-run summary as JSON.")
def quickstart_cmd(
    mode: str | None,
    scanner_mode: str,
    with_judge: bool,
    non_interactive: bool,
    yes: bool,
    force: bool,
    agent_name: str | None,
    skip_gateway: bool,
    json_summary: bool,
) -> None:
    """Zero-prompt end-to-end setup with safe defaults.

    Equivalent to running ``init`` → ``setup guardrail`` → ``gateway
    start`` but with a scripted, non-interactive UX. Missing API keys
    are listed at the end so the operator knows exactly what (if
    anything) to wire up before the guardrail becomes useful.
    """
    from defenseclaw import config as cfg_mod
    from defenseclaw.bootstrap import FirstRunOptions, run_first_run
    from defenseclaw.commands.cmd_init import _render_first_run_report
    from defenseclaw.commands.cmd_setup import _read_picked_connector
    from defenseclaw.ux import CLIRenderer

    if agent_name:
        connector = agent_name
    else:
        data_dir = str(cfg_mod.default_data_path())
        connector = _read_picked_connector(data_dir) or "codex"

    profile = mode or "observe"

    report = run_first_run(FirstRunOptions(
        connector=connector,
        profile=profile,
        scanner_mode=scanner_mode,
        with_judge=with_judge,
        start_gateway=not skip_gateway,
        verify=True,
        force=force,
    ))
    if json_summary:
        click.echo(json.dumps(report.to_dict(), indent=2))
    else:
        _render_first_run_report(report, CLIRenderer())
    if report.status == "needs_attention":
        sys.exit(1)
