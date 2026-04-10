"""defenseclaw sandbox — Experimental sandbox mode commands.

Groups sandbox init and setup under ``defenseclaw sandbox``.
"""

from __future__ import annotations

import click

from defenseclaw.commands.cmd_init_sandbox import sandbox_init_cmd
from defenseclaw.commands.cmd_setup_sandbox import setup_sandbox


@click.group()
def sandbox() -> None:
    """[experimental] Manage openshell-sandbox standalone mode.

    Linux-only. Creates an isolated sandbox environment with Landlock,
    seccomp, and network namespaces for running OpenClaw agents.

    \b
    Requires 'defenseclaw init' to have been run first.

    \b
    Commands:
      init    Create sandbox user, transfer OpenClaw, configure networking
      setup   Customize sandbox networking, policy, and device pairing
    """


sandbox.add_command(sandbox_init_cmd, "init")
sandbox.add_command(setup_sandbox, "setup")
