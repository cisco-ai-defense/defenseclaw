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


def _masked_display(raw: str, tokens: tuple[str, ...]) -> str:
    """The typed command for the status bar, drawer and MRU, secrets redacted (GAP-2010)."""

    from defenseclaw.tui.screens.command_preview import mask_argv  # local: that module imports this one

    masked = mask_argv(tokens)
    return raw if masked == tokens else " ".join(masked)


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
        display_name=_masked_display(raw, tokens),
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
            display_name=_masked_display(" ".join(tokens), tokens),
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
        display_name=_masked_display(" ".join(tokens), tokens),
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
        if not arg.startswith("--"):
            continue
        flag, has_value, value = arg.partition("=")
        if not _flag_is_secret(flag):
            continue
        if has_value:
            if not env_name_value_in_clear(flag, value):
                secret_indexes.add(index)
        elif index + 1 < len(args) and not env_name_value_in_clear(flag, args[index + 1]):
            secret_indexes.add(index + 1)
    return secret_indexes


_ENV_VAR_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def env_name_value_in_clear(flag: str, value: str) -> bool:
    """Whether a ``--*-env`` flag's value is an env var NAME, safe to show (GAP-2540).

    ``--api-key-env AID_KEY`` names the variable that holds the key; it is
    not the key. A value that does not look like a name (a key pasted into
    the field by mistake) stays redacted.
    """

    return flag.lower().replace("-", "_").endswith("_env") and bool(_ENV_VAR_NAME_RE.match(value))


def _flag_is_secret(flag: str) -> bool:
    normalized = flag.lower().replace("-", "_")
    return normalized == "__value" or normalized == "__api_key" or any(
        fragment in normalized for fragment in ("key", "token", "secret", "password", "credential", "value")
    )


# Readiness lives on Setup behind ``i``; a hint must name the keys that get
# there, not just "rerun readiness" (GAP-1910).
READINESS_HINT = "press 0 (Setup), then i for readiness"


# A doctor row that needs attention: "[WARN] Connector OTLP: codex  -  ..."
# (plain) or "⚠ Connector OTLP: codex  —  ..." (color), label only.
_DOCTOR_ATTENTION_RE = re.compile(r"^(\[(?:WARN|FAIL)\]|[\u26a0\u2717])\s+(.+?)(?:\s{2,}[\u2014-]\s{2,}.*)?$")
DOCTOR_DETAILS_HINT = "press A (Activity) for the check details"


def doctor_attention_checks(lines: Sequence[str]) -> list[tuple[bool, str]]:
    """``(failed, label)`` of each doctor check that failed or warned.

    Failures come first, then warnings, each in output order: a failure
    after two warnings was hidden behind "and 1 more" (GAP-2419).
    """

    checks: dict[str, bool] = {}
    for line in lines:
        if not (match := _DOCTOR_ATTENTION_RE.match(line.strip())):
            continue
        label = match.group(2).strip()
        # "⚠ Fix the failures above, then re-run" is doctor's footer, not a check.
        if not label.startswith("Fix the failures above"):
            checks[label] = checks.get(label, False) or match.group(1) in ("[FAIL]", "\u2717")
    return sorted(((failed, label) for label, failed in checks.items()), key=lambda check: not check[0])


def doctor_attention_rows(lines: Sequence[str]) -> list[str]:
    """Labels of the doctor checks that failed or warned, failures first."""

    return [label for _failed, label in doctor_attention_checks(lines)]


def suggested_next_action(
    command: str, exit_code: int, *, panel: str = "", lines: Sequence[str] = ()
) -> str:
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
    if "doctor" in cmd and doctor_attention_rows(lines):
        # Readiness passed every row while doctor warned about a connector's
        # OTLP drops: the doctor output in Activity names the check (GAP-2252).
        return DOCTOR_DETAILS_HINT if exit_code == 0 else f"{DOCTOR_DETAILS_HINT}, or rerun doctor"
    if exit_code != 0:
        if "keys" in cmd:
            return "open Credentials or run keys check"
        if "doctor" in cmd:
            return f"{readiness}, or rerun doctor"
        return "review output and rerun when fixed"
    if "keys" in cmd or "doctor" in cmd or "setup" in cmd:
        return readiness
    return ""


def _destination_rows(lines: Sequence[str]) -> int:
    """Rows of the ``setup observability list`` table (NAME header .. Retention)."""

    count = 0
    in_table = False
    for line in lines:
        text = line.strip()
        if text.startswith("NAME ") and " KIND " in text:
            in_table = True
            continue
        if not in_table:
            continue
        if not text or text.startswith(("Retention:", "Plan digest:")):
            break
        count += 1
    return count


def is_listing_detail(line: str) -> bool:
    """True for an output line that is part of a listing, not a result.

    A directory (``C:\\Users\\u\\.agents\\skills``, ``/home/u/.claude/skills``)
    or a ``Plan digest: <hex>`` line ended the output, and the footer showed
    it as ``Done: ... · <path>`` (GAP-2184).
    """

    text = line.strip()
    return bool(_PATH_LINE_RE.match(text) or _DIGEST_LINE_RE.search(text))


def is_command_hint(line: str) -> bool:
    """True for an output line that is a command to run next, not a result.

    ``setup <connector>`` ends with "defenseclaw guardrail disable
    --connector X" (how to undo it), which the drawer showed as the result
    (GAP-1910).
    """

    text = line.strip().lstrip("$>").strip()
    return text.startswith(("defenseclaw ", "defenseclaw-gateway "))


_GATEWAY_PID_RE = re.compile(r"\bOK \(PID (\d+)\)")
_CONNECTOR_HEADER_RE = re.compile(r"^(?:\u2500\u2500|--) connector: (\S+) (?:\u2500\u2500|--)$")
_PATH_LINE_RE = re.compile(r"^(?:[A-Za-z]:[\\/]|~[\\/]|/)\S*$")
_DIGEST_LINE_RE = re.compile(r"\bdigest:\s*[0-9a-f]{16,}$", re.IGNORECASE)
_SETUP_DONE_RE = re.compile(r"^[\u2713\u2714]\s+(.+ connector setup complete|\d+ connector\(s\) set up)")
_SETUP_MODE_RE = re.compile(r"^[\u2713\u2714]\s+\S+ mode=(observe|action)$")
# A Windows console without UTF-8 gets the ASCII forms "*", "o", "-" and
# "OK set" (ux.ascii_presentation_text), so match both (GAP-2238).
_KEYS_ROW_RE = re.compile(r"^[\u25cf\u25cb\u00b7*o-]\s+([A-Z][A-Z0-9_]*)\s+(.*)$")
_KEYS_SET_RE = re.compile(r"(?:\u2713|\u2714|\bOK) set\b")
_SCAN_DONE_RE = re.compile(r"^(?:[\u2713\u2714]|OK)?\s*(Scan complete: .+)$")
_SCAN_SUMMARY_RE = re.compile(r"^Summary: (\d+) (skills?) scanned\b")
_NO_SKILLS_PREFIXES = ("No skills found", "No scannable skills")


def _plugin_info_summary(lines: Sequence[str]) -> str:
    """``a2a: clean, 0 findings, not quarantined`` for ``plugin info``.

    The card showed the last line, ``Actions: -`` (GAP-2370).
    """

    fields: dict[str, str] = {}
    in_scan = False
    for line in lines:
        text = line.strip()
        key, sep, value = text.partition(":")
        if not sep:
            continue
        key, value = key.strip(), value.strip()
        if key == "Last Scan":
            in_scan = True
        elif key in {"Plugin", "Quarantined"} and not in_scan:
            fields.setdefault(key, value)
        elif key in {"Verdict", "Findings"} and in_scan:
            fields.setdefault(key, value)
        elif key == "Actions":
            fields["Actions"] = value
    name = fields.get("Plugin", "")
    if not name:
        return ""
    parts = [fields.get("Verdict", "not scanned")]
    if fields.get("Findings"):
        parts.append(fields["Findings"])
    if "Quarantined" in fields:
        parts.append("quarantined" if fields["Quarantined"] == "yes" else "not quarantined")
    actions = fields.get("Actions", "-").split(" (", 1)[0].strip()
    if actions and actions != "-":
        parts.append(f"actions: {actions}")
    return f"{name}: {', '.join(parts)}"


def failure_result_summary(command: str, lines: Sequence[str]) -> str:
    """The result of a failed command, or "" to fall back to its last line.

    A failed doctor ended with "Fix the failures above, then re-run", but
    the drawer shows nothing above it: name the failing checks (GAP-2395).
    """

    if "doctor" in command.strip().lower():
        return command_result_summary(command, lines)
    return ""


def command_result_summary(command: str, lines: Sequence[str]) -> str:
    """The result of a finished command, or "" to fall back to its last line.

    ``keys list`` ends with a table footnote and a gateway restart with its
    log path, so the last output line read as if it were the result
    (GAP-1910). ``lines`` are the ANSI-free output lines.
    """

    lowered = command.strip().lower()
    if lowered.startswith("upgrade"):
        # "Done: Upgrade · To install a specific 1.x release: ..." hid the
        # result line above it (GAP-2250).
        for line in lines:
            text = line.strip().lstrip("\u2713\u2714").strip()
            if " is up to date" in text or text.startswith(("\u2192 Installing", "Installing DefenseClaw")):
                return text.lstrip("\u2192 ").strip()
        return ""
    if "doctor" in lowered:
        attention = doctor_attention_checks(lines)
        health = next((line.strip() for line in reversed(lines) if line.strip().startswith("Health:")), "")
        if health and attention:
            # "Health: 129 passed, 1 warning" did not say which check warned
            # (GAP-2252). Failures lead, and say so when warnings follow, so
            # the failing check is never cut or hidden (GAP-2419).
            mixed = len({failed for failed, _label in attention}) > 1
            named = [f"{'failed' if failed else 'warning'} {label}" if mixed else label for failed, label in attention]
            more = f" and {len(named) - 2} more" if len(named) > 2 else ""
            return f"{health} · check: {', '.join(named[:2])}{more}"
        return ""
    if "restart" in lowered:
        for line in lines:
            if match := _GATEWAY_PID_RE.search(line):
                return f"Gateway restarted (PID {match.group(1)})"
        return ""
    if lowered.startswith(("info plugin", "plugin info")):
        return _plugin_info_summary(lines)
    if "discovery scan" in lowered:
        # ``agent discovery scan`` ends with a hint about other commands;
        # the receipt showed that hint instead of the counts (GAP-2319).
        for line in lines:
            if match := _SCAN_DONE_RE.match(line.strip()):
                return match.group(1)
        return ""
    connectors = [m.group(1) for line in lines if (m := _CONNECTOR_HEADER_RE.match(line.strip()))]
    if connectors and "scan" in command.lower():
        # ``skill scan --all`` (and the other --all scans) print one section
        # per connector; the last line was a skills directory (GAP-2184).
        noun = "connector" if len(connectors) == 1 else "connectors"
        text = f"{len(connectors)} {noun} scanned"
        # "4 connectors scanned" read the same when no connector had a
        # skill to scan (GAP-2388): say how many skills were scanned.
        skills = [int(m.group(1)) for line in lines if (m := _SCAN_SUMMARY_RE.match(line.strip()))]
        if skills:
            count = sum(skills)
            text += f" · {count} {'skill' if count == 1 else 'skills'} scanned"
        elif any(line.strip().startswith(_NO_SKILLS_PREFIXES) for line in lines):
            text += " · no scannable skills"
        return text
    for index, line in enumerate(lines):
        if "installed copy is disabled, so it does not load" in line:
            # GAP-2313: ``plugin block`` of a disabled plugin.
            return "New installs blocked; the installed copy is disabled."
        if "block only refuses new installs" in line:
            # ``plugin block`` ends with "To stop it: ..."; the card dropped
            # the sentence that says the copy still loads (GAP-2228).
            stop = next((rest.strip() for rest in lines[index + 1 :] if rest.strip().startswith("To stop it:")), "")
            text = "New installs blocked; the installed copy still loads."
            return f"{text} {stop}" if stop else text
    if any(line.strip() == "Observability v8 destinations" for line in lines):
        rows = _destination_rows(lines)
        noun = "destination" if rows == 1 else "destinations"
        return f"{rows} {noun} listed"
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
    missing = [row.group(1) for row in required if not _KEYS_SET_RE.search(row.group(2))]
    noun = "credential" if len(rows) == 1 else "credentials"
    text = f"{len(rows)} {noun}, {len(required)} required"
    return f"{text}, missing: {', '.join(missing)}" if missing else f"{text}, all set"
