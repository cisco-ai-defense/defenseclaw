# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Vault panel state (pure: no I/O, no Textual).

The app loads ``defenseclaw sandbox vault list --json`` in a worker and hands
the stdout here. Every change is a ``defenseclaw sandbox vault ...`` command
the app previews and runs; a secret value goes to the command on standard
input (``--value-stdin``), never on its command line, and the panel never
holds or shows a value.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")

STATUS_TEXT = {"ready": "ready", "needs_host": "needs a host", "exposed": "exposed: rotate", "unconfirmed": "unconfirmed"}

# Multi-step prompts of the add flow: name, then host, then the value.
PROMPT_ADD_NAME = "add-name"
PROMPT_ADD_HOST = "add-host"
PROMPT_ADD_VALUE = "add-value"
PROMPT_REPLACE = "replace"
PROMPT_BIND = "bind"
PROMPT_RENAME = "rename"

PROMPTS: dict[str, tuple[str, str, bool]] = {
    # prompt: (title, hint, password)
    PROMPT_ADD_NAME: (
        "Add a secret: name",
        "The variable the sandbox sees, for example STRIPE_API_KEY (letters, digits and _).",
        False,
    ),
    PROMPT_ADD_HOST: (
        "Add a secret: host",
        "The only host the value may be sent to, for example api.stripe.com (or host:port).",
        False,
    ),
    PROMPT_ADD_VALUE: (
        "Add a secret: value",
        "Paste the value. It is hidden here, goes to the vault on standard input and is never shown again.",
        True,
    ),
    PROMPT_REPLACE: ("Replace the value", "Paste the new value (after you rotate it). It is hidden here.", True),
    PROMPT_BIND: ("Set the host", "The only host the value may be sent to, for example api.stripe.com.", False),
    PROMPT_RENAME: ("Rename", "The new variable name, for example STRIPE_LIVE_KEY.", False),
}


@dataclass(frozen=True)
class VaultCommandIntent:
    """A CLI command the app previews and runs."""

    label: str
    args: tuple[str, ...]
    binary: str = "defenseclaw"
    category: str = "vault"
    risk: str = "mutation"
    hint: str = ""
    consequence: str = ""
    # The value, for ``--value-stdin``; never in args.
    secret_stdin: str | None = None
    stay_on_panel: bool = True

    @property
    def argv(self) -> tuple[str, ...]:
        return (self.binary, *self.args)


@dataclass(frozen=True)
class VaultPanelAction:
    """What a key asks the app to do: none, move, refresh, intent or prompt."""

    kind: str
    intent: VaultCommandIntent | None = None
    prompt: str = ""
    hint: str = ""


@dataclass(frozen=True)
class VaultRow:
    name: str
    target: str
    status: str
    source: str
    kind: str
    captured_from: str
    last_used: str
    use_count: int


def _ago(stamp: str, now: datetime) -> str:
    if not stamp:
        return "never"
    try:
        when = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except ValueError:
        return "?"
    seconds = max(0, int((now - when).total_seconds()))
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds >= size:
            return f"{seconds // size}{unit} ago"
    return "just now"


@dataclass
class VaultPanelModel:
    entries: list[dict[str, Any]] = field(default_factory=list)
    path: str = ""
    # How the vault is kept: "sealed (macOS Keychain)", "sealed (Secret
    # Service)" or "file (owner-only, not encrypted)".
    storage: str = ""
    cursor: int = 0
    loaded: bool = False
    error: str = ""
    # The add flow keeps the name and host it has asked for so far.
    pending_name: str = ""
    pending_host: str = ""
    now: datetime | None = None

    # ------------------------------------------------------------ data

    def apply_list_json(self, raw: str | bytes) -> None:
        text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw or "")
        try:
            doc = json.loads(text)
        except json.JSONDecodeError:
            self.set_error("defenseclaw sandbox vault list --json printed something that is not JSON")
            return
        entries = doc.get("entries") if isinstance(doc, dict) else None
        if not isinstance(entries, list):
            self.set_error("defenseclaw sandbox vault list --json has no entries list")
            return
        # A value never reaches the model, whatever the command printed.
        self.entries = [{k: v for k, v in e.items() if k != "value"} for e in entries if isinstance(e, dict)]
        self.path = str(doc.get("path") or "")
        self.storage = str(doc.get("storage") or "")
        self.loaded, self.error = True, ""
        self.cursor = max(0, min(self.cursor, len(self.entries) - 1))

    def set_error(self, message: str) -> None:
        self.loaded, self.error = True, message

    def rows(self) -> list[VaultRow]:
        now = self.now or datetime.now(timezone.utc)
        out = []
        for e in self.entries:
            out.append(VaultRow(
                name=str(e.get("name") or ""),
                target=str(e.get("target") or ""),
                status=str(e.get("status") or ""),
                source=str(e.get("source") or ""),
                kind=str(e.get("kind") or ""),
                captured_from=str(e.get("captured_from") or ""),
                last_used=_ago(str(e.get("last_used_at") or ""), now) + (
                    f" ({e.get('last_used_by')})" if e.get("last_used_by") else ""),
                use_count=int(e.get("use_count") or 0),
            ))
        return out

    def total_count(self) -> int:
        return len(self.entries)

    def selected(self) -> VaultRow | None:
        rows = self.rows()
        if not rows:
            return None
        return rows[max(0, min(self.cursor, len(rows) - 1))]

    def counts(self) -> dict[str, int]:
        out = {"ready": 0, "needs_host": 0, "exposed": 0}
        for e in self.entries:
            status = str(e.get("status") or "")
            if status in out:
                out[status] += 1
        return out

    def summary_line(self) -> str:
        if self.error:
            return "Vault: " + self.error
        if not self.loaded:
            return "Vault: loading…"
        n = len(self.entries)
        parts = [f"{n} secret{'s' if n != 1 else ''} for your sandboxes"]
        c = self.counts()
        if c["needs_host"]:
            parts.append(f"{c['needs_host']} need{'s' if c['needs_host'] == 1 else ''} a host")
        if c["exposed"]:
            parts.append(f"{c['exposed']} exposed: rotate")
        line = " · ".join(parts) + " · values are never shown"
        if self.storage:
            line += " · " + self.storage
        return line

    def empty_state(self) -> str:
        return ("Your vault is empty. Press a to add a secret; a secret a sandboxed agent is given "
                "also lands here. Start a sandbox with --vault NAME to use one.")

    def detail_line(self) -> str:
        row = self.selected()
        if row is None:
            return ""
        how = "added by you" if row.source == "manual" else f"captured from {row.captured_from or 'a sandbox'}"
        where = f"sent only to {row.target}" if row.target else "no host yet: press e to set one"
        return f"{row.name}: ${row.name} in a sandbox started with --vault {row.name}; {where}; {how}"

    def data_table_columns(self, compact: bool) -> tuple[str, ...]:
        if compact:
            return ("NAME", "HOST", "STATUS")
        return ("NAME", "HOST", "STATUS", "SOURCE", "LAST USED")

    def data_table_rows(self, compact: bool) -> list[tuple[str, ...]]:
        out = []
        for r in self.rows():
            status = STATUS_TEXT.get(r.status, r.status)
            target = r.target or "—"
            if compact:
                out.append((r.name, target, status))
            else:
                out.append((r.name, target, status, r.source, r.last_used))
        return out

    # ------------------------------------------------------------ keys

    def keys(self) -> list[tuple[str, str]]:
        keys = [("a", "add"), ("r", "refresh")]
        if self.entries:
            keys = [("a", "add"), ("c", "confirm"), ("v", "replace value"), ("e", "set host"), ("n", "rename"),
                    ("d", "delete"), ("enter", "details"), ("r", "refresh")]
        return keys

    def handle_key(self, key: str) -> VaultPanelAction:
        if key in ("up", "k", "down", "j"):
            count = len(self.entries)
            step = -1 if key in ("up", "k") else 1
            self.cursor = max(0, min(self.cursor + step, max(0, count - 1)))
            return VaultPanelAction("move")
        if key == "r":
            return VaultPanelAction("refresh")
        if key == "a":
            self.pending_name = self.pending_host = ""
            return VaultPanelAction("prompt", prompt=PROMPT_ADD_NAME)
        row = self.selected()
        if key in ("c", "v", "e", "n", "d", "enter") and row is None:
            return VaultPanelAction("none", hint="The vault is empty: press a to add a secret.")
        if key == "c":
            if row.status != "unconfirmed":
                return VaultPanelAction("none", hint=f"{row.name} needs no confirmation.")
            return VaultPanelAction("intent", VaultCommandIntent(
                f"sandbox vault confirm {row.name}", ("sandbox", "vault", "confirm", "--yes", row.name),
                hint=f"Confirm {row.name} is your own secret (captured from {row.captured_from or 'a sandbox'}).",
                consequence=(f"Sandboxes may then use {row.name}. An agent in a sandbox can make a call that looks like "
                             "your prompt: confirm only a secret you gave it. Check it with: defenseclaw sandbox vault confirm "
                             f"{row.name} (it shows the last 4 characters).")))
        if key == "v":
            return VaultPanelAction("prompt", prompt=PROMPT_REPLACE)
        if key == "e":
            return VaultPanelAction("prompt", prompt=PROMPT_BIND)
        if key == "n":
            return VaultPanelAction("prompt", prompt=PROMPT_RENAME)
        if key == "enter" and row is not None:
            return VaultPanelAction("intent", VaultCommandIntent(
                f"sandbox vault show {row.name}", ("sandbox", "vault", "show", row.name), risk="read-only",
                hint="Show the secret's host, status and use (never its value)."))
        if key == "d" and row is not None:
            return VaultPanelAction("intent", VaultCommandIntent(
                f"sandbox vault remove {row.name}", ("sandbox", "vault", "remove", "--yes", row.name),
                risk="destructive", hint=f"Remove {row.name} from your vault.",
                consequence=(f"Removes {row.name} from your vault. Sandboxes started from now on cannot use it; "
                             "running ones keep it until they stop. Revoke it with its issuer if it may have leaked.")))
        return VaultPanelAction("none")

    # ------------------------------------------------------------ prompts

    def prompt_spec(self, prompt: str) -> tuple[str, str, bool]:
        title, hint, password = PROMPTS[prompt]
        row = self.selected()
        if prompt in (PROMPT_REPLACE, PROMPT_BIND, PROMPT_RENAME) and row is not None:
            title = f"{title}: {row.name}"
        if prompt == PROMPT_ADD_VALUE and self.pending_name:
            title = f"Add {self.pending_name} for {self.pending_host}: value"
        return title, hint, password

    def answer_prompt(self, prompt: str, text: str) -> VaultPanelAction:
        """The next step for a prompt's answer: another prompt, an intent, or
        a hint saying why the answer was refused (the prompt is then asked
        again by the app)."""
        value = text if prompt in (PROMPT_ADD_VALUE, PROMPT_REPLACE) else text.strip()
        if not value:
            return VaultPanelAction("none", hint="Nothing entered; nothing changed.")
        row = self.selected()
        if prompt == PROMPT_ADD_NAME:
            if not _NAME.match(value):
                return VaultPanelAction("prompt", prompt=PROMPT_ADD_NAME,
                                        hint="Use letters, digits and _, starting with a letter or _.")
            self.pending_name = value
            return VaultPanelAction("prompt", prompt=PROMPT_ADD_HOST)
        if prompt == PROMPT_ADD_HOST:
            if not _plausible_host(value):
                return VaultPanelAction("prompt", prompt=PROMPT_ADD_HOST,
                                        hint="Give only a host such as api.stripe.com, without https:// or a path.")
            self.pending_host = value
            return VaultPanelAction("prompt", prompt=PROMPT_ADD_VALUE)
        if prompt == PROMPT_ADD_VALUE:
            name, host = self.pending_name, self.pending_host
            self.pending_name = self.pending_host = ""
            if not name or not host:
                return VaultPanelAction("none", hint="Start again with a.")
            return VaultPanelAction("intent", VaultCommandIntent(
                f"sandbox vault add {name} --host {host}",
                ("sandbox", "vault", "add", "--host", host, "--value-stdin", name),
                hint=f"Add {name}, sent only to {host}. The value goes on standard input.",
                secret_stdin=_one_line(value)))
        if row is None:
            return VaultPanelAction("none", hint="Pick a secret first.")
        if prompt == PROMPT_REPLACE:
            return VaultPanelAction("intent", VaultCommandIntent(
                f"sandbox vault replace {row.name}", ("sandbox", "vault", "replace", "--value-stdin", row.name),
                hint=f"Replace the value of {row.name}. The value goes on standard input.",
                secret_stdin=_one_line(value)))
        if prompt == PROMPT_BIND:
            if not _plausible_host(value):
                return VaultPanelAction("prompt", prompt=PROMPT_BIND,
                                        hint="Give only a host such as api.stripe.com, without https:// or a path.")
            return VaultPanelAction("intent", VaultCommandIntent(
                f"sandbox vault bind {row.name} --host {value}",
                ("sandbox", "vault", "bind", "--host", value, row.name),
                hint=f"{row.name} may then be sent to {value} only."))
        if prompt == PROMPT_RENAME:
            if not _NAME.match(value):
                return VaultPanelAction("prompt", prompt=PROMPT_RENAME,
                                        hint="Use letters, digits and _, starting with a letter or _.")
            return VaultPanelAction("intent", VaultCommandIntent(
                f"sandbox vault rename {row.name} {value}", ("sandbox", "vault", "rename", row.name, value),
                hint=f"Rename {row.name} to {value} (the variable the sandbox sees)."))
        return VaultPanelAction("none")


def _one_line(value: str) -> str:
    return value.strip("\r\n") + "\n"


def _plausible_host(value: str) -> bool:
    return bool(value) and "://" not in value and not any(c in value for c in "/*@ ?#") and "." in value


def vault_keys_hint(model: VaultPanelModel) -> str:
    return " · ".join(f"{k} {label}" for k, label in model.keys())


def vault_help_rows() -> list[tuple[str, str]]:
    """The ? sheet rows: every key handle_key takes."""
    rows = VaultPanelModel(entries=[{"name": "X"}]).keys()
    return [("j/k", "move"), *rows, ("K", "open this panel")]


def vault_keys_hint_for(has_rows: bool) -> str:
    """Hint bar line: the add and refresh keys, and the row keys once a row exists."""
    return vault_keys_hint(VaultPanelModel(entries=[{"name": "X"}] if has_rows else []))
