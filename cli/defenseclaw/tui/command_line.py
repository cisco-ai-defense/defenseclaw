"""Safe parser for the in-TUI command drawer."""

from __future__ import annotations

import re
import shlex
from collections.abc import Sequence
from dataclasses import dataclass

from defenseclaw.main import cli
from defenseclaw.tui.registry import CliBinary, build_registry, match_cli_args, match_command

SHELL_OPERATORS = {"|", ">", "<", "&&", "||", ";", "$(", "`"}


class CommandLineError(ValueError):
    """Raised when a command drawer entry is not safe to run."""


@dataclass(frozen=True)
class ParsedCommand:
    binary: CliBinary
    args: tuple[str, ...]
    display_name: str
    category: str
    risk: str = "read-only"
    needs_preview: bool = False
    # Secret fed to the child over stdin instead of argv (e.g. ``keys set``
    # reads a hidden prompt). ``None`` means no stdin payload. See F-0801.
    stdin_input: str | None = None
    # Secret-bearing environment variables injected into the child process
    # environment rather than exposed as ``--env KEY=secret`` argv. See F-0803.
    env_overrides: tuple[tuple[str, str], ...] = ()
    # Plain-words effect shown in the confirm modal (the intent's
    # ``consequence``), so the modal says what the command changes.
    consequence: str = ""


def display_argv(argv: tuple[str, ...] | list[str]) -> str:
    """Join argv for display, quoting an argument that is empty or contains spaces.

    ``block-message 'Blocked here'`` reads as the two arguments it runs, and
    ``--block-message ''`` shows the empty value a cleared field sends;
    joined plainly they read as three words and as nothing.
    """

    return " ".join(shlex.quote(arg) if not arg or any(ch.isspace() for ch in arg) else arg for arg in argv)


def _contains_shell_operator(text: str) -> bool:
    return any(op in text for op in SHELL_OPERATORS)


def _root_click_commands() -> set[str]:
    return set(cli.commands)


def _is_env_prefix(token: str) -> bool:
    if "=" not in token:
        return False
    name, value = token.split("=", 1)
    return bool(name) and value != "" and name.replace("_", "").isalnum()


def parse_command_line(text: str) -> ParsedCommand:
    """Parse command drawer input into structured argv.

    The parser accepts current TUI aliases and raw ``defenseclaw ...``
    commands, but it never returns a shell command.
    """

    raw = text.strip()
    if not raw:
        raise CommandLineError("Type a DefenseClaw command.")
    if _contains_shell_operator(raw):
        raise CommandLineError("Shell operators are not allowed in the TUI command drawer.")

    try:
        tokens = tuple(shlex.split(raw))
    except ValueError as exc:
        raise CommandLineError(str(exc)) from exc

    if not tokens:
        raise CommandLineError("Type a DefenseClaw command.")
    if _is_env_prefix(tokens[0]):
        raise CommandLineError("Environment-prefixed commands are not allowed.")

    if tokens[0] in {"defenseclaw", "defenseclaw-gateway"}:
        return _parse_raw_binary(tokens)

    entry, extra = match_command(raw, build_registry())
    if entry is None:
        raise CommandLineError(f"Unknown TUI command: {raw}")
    if entry.needs_arg and not extra.strip():
        raise CommandLineError(f"{entry.tui_name} needs {entry.arg_hint}")
    extra_args = tuple(shlex.split(extra)) if extra else ()
    args = entry.cli_args + extra_args
    risk = infer_command_risk(entry.category, args)
    return ParsedCommand(
        binary=entry.cli_binary,
        args=args,
        display_name=raw,
        category=entry.category,
        risk=risk,
        needs_preview=_needs_preview(entry.category, args),
    )


def _parse_raw_binary(tokens: tuple[str, ...]) -> ParsedCommand:
    binary = tokens[0]
    args = tokens[1:]
    if binary == "defenseclaw":
        if not args:
            raise CommandLineError("Raw defenseclaw commands require a subcommand.")
        if args[0] not in _root_click_commands():
            raise CommandLineError(f"Unknown defenseclaw command: {args[0]}")
        entry = match_cli_args("defenseclaw", args, build_registry())
        if entry is not None:
            _validate_registry_arg(entry, args)
        category = entry.category if entry else _category_for_args(args)
        risk = infer_command_risk(category, args)
        return ParsedCommand(
            binary="defenseclaw",
            args=args,
            display_name=" ".join(tokens),
            category=category,
            risk=risk,
            needs_preview=_needs_preview(category, args),
        )

    entry = match_cli_args("defenseclaw-gateway", args, build_registry())
    if entry is None:
        raise CommandLineError("Raw defenseclaw-gateway commands must be backed by the TUI registry.")
    _validate_registry_arg(entry, args)
    risk = infer_command_risk(entry.category, args)
    return ParsedCommand(
        binary="defenseclaw-gateway",
        args=args,
        display_name=" ".join(tokens),
        category=entry.category,
        risk=risk,
        needs_preview=_needs_preview(entry.category, args),
    )


def _validate_registry_arg(entry: object, args: tuple[str, ...]) -> None:
    cli_args = getattr(entry, "cli_args", ())
    if getattr(entry, "needs_arg", False) and len(args) == len(cli_args):
        raise CommandLineError(f"{entry.tui_name} needs {entry.arg_hint}")


def _category_for_args(args: tuple[str, ...]) -> str:
    if not args:
        return "info"
    if args[0] in {"setup", "init", "config", "keys", "uninstall", "reset", "upgrade"}:
        return "setup"
    if args[0] in {"skill", "mcp", "plugin", "tool", "registry", "policy"}:
        return "mutation"
    if args[0] in {"doctor", "version", "status", "alerts", "audit", "agent", "aibom"}:
        return "info"
    return "other"


def _needs_preview(category: str, args: tuple[str, ...]) -> bool:
    return infer_command_risk(category, args) != "read-only"


def infer_command_risk(category: str, args: tuple[str, ...]) -> str:
    """Mirror the Go TUI CommandIntent risk model for preview gating."""

    lowered = tuple(arg.lower() for arg in args)
    if _secret_arg_indexes(lowered):
        return "secret"
    if not lowered:
        return "read-only"
    if _has_any_arg(lowered, "uninstall", "reset", "remove", "delete", "quarantine", "wipe"):
        # A dry run only reports what would be removed: preview it like a
        # setup command instead of the red double-confirm.
        return "setup" if "--dry-run" in lowered else "destructive"
    if _has_any_arg(lowered, "restart", "rotate-token"):
        return "restart"
    if lowered[0] in {"upgrade", "rollback"}:
        # Replaces the binaries and restarts the gateway; the preview called
        # it read-only (GAP-1422).
        return "restart"
    if _has_any_arg(
        lowered,
        "block",
        "disable",
        "teardown",
        "stop",
        "down",
        "approve",
        "reject",
        "allow",
        "unblock",
        "unset",
        # ``alerts acknowledge``/``dismiss`` change alert state; the preview
        # called them read-only (GAP-1213).
        "acknowledge",
        "dismiss",
    ):
        return "mutation"
    if lowered[0] == "doctor" and "--fix" in lowered:
        return "setup"
    if lowered[0] == "keys":
        if len(lowered) > 1 and lowered[1] in {"list", "check"}:
            return "read-only"
        return "setup"
    if lowered[0] == "setup":
        if _setup_args_read_only(lowered):
            return "read-only"
        return "setup"
    if lowered[0] in {"config", "status", "version", "doctor"}:
        return "read-only"
    if category in {"info", "scan"}:
        return "read-only"
    if category == "daemon":
        # "watchdog status" only reads state, like "gateway status"
        # (GAP-1584).
        if lowered[-1] in {"status", "list-backups"}:
            return "read-only"
        return "mutation"
    if category in {"setup", "install"}:
        return "setup"
    if category in {"enforce", "policy", "sandbox", "other", "mutation"}:
        if _has_any_arg(
            lowered,
            "info",
            "list",
            "scan",
            "show",
            "status",
            "validate",
            "test",
            "evaluate",
            "domains",
            "export",
            "dry-run",
        ):
            return "read-only"
        return "mutation"
    return "read-only"


def _setup_args_read_only(args: tuple[str, ...]) -> bool:
    # Bare ``setup`` (length 1) used to short-circuit to "read-only",
    # which let the command drawer run ``defenseclaw setup`` without
    # the preview/confirmation screen. That subprocess is the
    # interactive connector picker — it prompts on stdin and mutates
    # config — so treat it as a setup-risk command that requires the
    # preview gate (or, better, gets intercepted and routed to the
    # Connector Setup wizard form).
    if len(args) == 1:
        return False
    last = args[-1]
    if _has_any_arg(args, "show", "list", "status", "url", "logs", "--show"):
        return True
    return last in {"--help", "-h"}


def _has_any_arg(args: tuple[str, ...], *needles: str) -> bool:
    return any(arg in needles for arg in args)


def _secret_arg_indexes(args: tuple[str, ...]) -> set[int]:
    secret_indexes: set[int] = set()
    for index, arg in enumerate(args):
        if arg.startswith("--") and _flag_is_secret(arg.split("=", 1)[0]):
            if "=" not in arg and index + 1 < len(args):
                secret_indexes.add(index + 1)
            elif "=" in arg:
                secret_indexes.add(index)
    return secret_indexes


def _flag_is_secret(flag: str) -> bool:
    normalized = flag.lower().replace("-", "_")
    return normalized == "__value" or normalized == "__api_key" or any(
        fragment in normalized for fragment in ("key", "token", "secret", "password", "credential", "value")
    )


# Readiness lives on Setup behind ``i``; a hint must name the keys that get
# there, not just "rerun readiness" (GAP-1910).
READINESS_HINT = "press 0 (Setup), then i for readiness"


def suggested_next_action(command: str, exit_code: int, *, panel: str = "") -> str:
    """Return a one-line nudge for what to do after a command finishes.

    Each hint names the key that gets there. Returns an empty string when
    there is nothing useful to say — callers should treat that as "skip the
    footer" rather than rendering "(none)". A gateway restart gets no hint:
    the status bar already shows the gateway's health.

    Lower-cases the entire command before matching so e.g. ``KEYS
    LIST`` and ``keys list`` produce the same hint. On Setup (``panel``)
    the hint leaves out "press 0 (Setup)".
    """

    readiness = "press i for readiness" if panel == "setup" else READINESS_HINT
    cmd = command.strip().lower()
    if exit_code != 0:
        if "keys" in cmd:
            return "open Credentials or run keys check"
        if "doctor" in cmd:
            return f"{readiness}, or rerun doctor"
        return "review output and rerun when fixed"
    if "keys" in cmd or "doctor" in cmd or "setup" in cmd:
        return readiness
    return ""


def is_command_hint(line: str) -> bool:
    """True for an output line that is a command to run next, not a result.

    ``setup <connector>`` ends with "defenseclaw guardrail disable
    --connector X" (how to undo it), which the drawer showed as the result
    (GAP-1910).
    """

    text = line.strip().lstrip("$>").strip()
    return text.startswith(("defenseclaw ", "defenseclaw-gateway "))


_GATEWAY_PID_RE = re.compile(r"\bOK \(PID (\d+)\)")
_SETUP_DONE_RE = re.compile(r"^[\u2713\u2714]\s+(.+ connector setup complete|\d+ connector\(s\) set up)")
_SETUP_MODE_RE = re.compile(r"^[\u2713\u2714]\s+\S+ mode=(observe|action)$")
_KEYS_ROW_RE = re.compile(r"^[\u25cf\u25cb\u00b7]\s+([A-Z][A-Z0-9_]*)\s+(.*)$")


def command_result_summary(command: str, lines: Sequence[str]) -> str:
    """The result of a finished command, or "" to fall back to its last line.

    ``keys list`` ends with a table footnote and a gateway restart with its
    log path, so the last output line read as if it were the result
    (GAP-1910). ``lines`` are the ANSI-free output lines.
    """

    if "restart" in command.lower():
        for line in lines:
            if match := _GATEWAY_PID_RE.search(line):
                return f"Gateway restarted (PID {match.group(1)})"
        return ""
    if command.strip().lower().startswith("setup"):
        done = next((m.group(1) for line in lines if (m := _SETUP_DONE_RE.match(line.strip()))), "")
        mode = next((m.group(1) for line in lines if (m := _SETUP_MODE_RE.match(line.strip()))), "")
        if done:
            return f"{done} (mode {mode})" if mode else done
    if not any("ENV NAME" in line and "REQUIREMENT" in line for line in lines):
        return ""
    rows = [match for line in lines if (match := _KEYS_ROW_RE.match(line.strip()))]
    if not rows:
        return ""
    required = [row for row in rows if "REQUIRED" in row.group(2).split()]
    missing = [row.group(1) for row in required if "\u2713 set" not in row.group(2)]
    noun = "credential" if len(rows) == 1 else "credentials"
    text = f"{len(rows)} {noun}, {len(required)} required"
    return f"{text}, missing: {', '.join(missing)}" if missing else f"{text}, all set"
