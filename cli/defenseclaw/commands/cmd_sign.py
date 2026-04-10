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

"""defenseclaw sign / trust — Cryptographic signing and trust management.

Commands for generating Ed25519 signing keys, signing skill/MCP/plugin
directories, verifying signatures, and managing the trusted publisher store.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

import click

from defenseclaw.context import AppContext, pass_ctx


def _sidecar_url(ctx: AppContext) -> str:
    if ctx.cfg:
        host = getattr(ctx.cfg, "gateway", None)
        if host and getattr(host, "bind_addr", None):
            return f"http://{host.bind_addr}"
    return "http://127.0.0.1:18970"


_API_HEADERS = {"X-DefenseClaw-Client": "cli", "Content-Type": "application/json"}


# ──────────────────────────────────────────────────────────────────────
# sign group
# ──────────────────────────────────────────────────────────────────────


@click.group()
def sign() -> None:
    """Sign skills, MCPs, or plugins with an Ed25519 key."""


@sign.command("keygen")
@click.option("--output", "-o", default=".", help="Directory to write keypair files")
def sign_keygen(output: str) -> None:
    """Generate an Ed25519 signing keypair."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
            PublicFormat,
        )
    except ImportError:
        click.echo("Error: 'cryptography' package required. Install with: pip install cryptography", err=True)
        sys.exit(1)

    private_key = Ed25519PrivateKey.generate()
    priv_bytes = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    os.makedirs(output, exist_ok=True)
    priv_path = os.path.join(output, "publisher.key")
    pub_path = os.path.join(output, "publisher.pub")

    with open(priv_path, "w") as f:
        f.write(priv_bytes.hex() + pub_bytes.hex() + "\n")
    os.chmod(priv_path, 0o600)
    with open(pub_path, "w") as f:
        f.write(pub_bytes.hex() + "\n")

    fp = hashlib.sha256(pub_bytes).hexdigest()
    click.echo("Keypair generated:")
    click.echo(f"  Private key: {priv_path}")
    click.echo(f"  Public key:  {pub_path}")
    click.echo(f"  Fingerprint: {fp}")


@sign.command("skill")
@click.argument("path")
@click.option("--key", required=True, help="Path to Ed25519 private key file")
@click.option("--publisher", required=True, help="Publisher name")
@pass_ctx
def sign_skill(ctx: AppContext, path: str, key: str, publisher: str) -> None:
    """Sign a skill directory with an Ed25519 private key."""
    import requests

    base = _sidecar_url(ctx)
    try:
        resp = requests.post(
            f"{base}/api/v1/verify",
            json={"target_type": "skill", "target_name": os.path.basename(path), "path": path},
            headers=_API_HEADERS,
            timeout=5,
        )
        if resp.ok:
            click.echo("Verified via sidecar API")
            result = resp.json()
            click.echo(f"  Signed:   {result.get('signed', False)}")
            click.echo(f"  Verified: {result.get('verified', False)}")
            click.echo(f"  Reason:   {result.get('reason', '')}")
            return
    except Exception:
        pass

    click.echo("Note: sidecar not reachable; use the Go gateway CLI for local signing", err=True)
    click.echo(f"  defenseclaw-gateway sign skill {path} --key {key} --publisher {publisher}", err=True)


@sign.command("verify")
@click.argument("path")
@click.option("--json-output", "as_json", is_flag=True, help="Output as JSON")
@pass_ctx
def sign_verify(ctx: AppContext, path: str, as_json: bool) -> None:
    """Verify the signature of a skill, MCP, or plugin directory."""
    import requests

    base = _sidecar_url(ctx)
    try:
        resp = requests.post(
            f"{base}/api/v1/verify",
            json={"target_type": "skill", "target_name": os.path.basename(path), "path": path},
            headers=_API_HEADERS,
            timeout=5,
        )
        if resp.ok:
            result = resp.json()
            if as_json:
                click.echo(json.dumps(result, indent=2))
            else:
                verified = result.get("verified", False)
                signed = result.get("signed", False)
                if verified:
                    click.secho("VERIFIED", fg="green", bold=True)
                elif signed:
                    click.secho("SIGNED (not trusted)", fg="yellow")
                else:
                    click.secho("UNSIGNED", fg="red")
                click.echo(f"  Publisher:   {result.get('publisher', '')}")
                click.echo(f"  Fingerprint: {result.get('fingerprint', '')}")
                click.echo(f"  Reason:      {result.get('reason', '')}")

            if ctx.store:
                ctx.store.set_signature_status(
                    "skill",
                    os.path.basename(path),
                    result.get("publisher", ""),
                    result.get("fingerprint", ""),
                    result.get("verified", False),
                    "",
                    result.get("reason", ""),
                )
            return
    except Exception as exc:
        click.echo(f"Error contacting sidecar: {exc}", err=True)
        sys.exit(1)


# ──────────────────────────────────────────────────────────────────────
# trust group
# ──────────────────────────────────────────────────────────────────────


@click.group()
def trust() -> None:
    """Manage the trusted publisher store."""


@trust.command("add")
@click.option("--name", required=True, help="Publisher name")
@click.option("--key", required=True, help="Path to Ed25519 public key file")
@pass_ctx
def trust_add(ctx: AppContext, name: str, key: str) -> None:
    """Add a publisher public key to the trust store."""
    import requests

    pub_hex = Path(key).read_text().strip()
    base = _sidecar_url(ctx)
    try:
        resp = requests.post(
            f"{base}/api/v1/trust",
            json={"name": name, "public_key": pub_hex},
            headers=_API_HEADERS,
            timeout=5,
        )
        if resp.ok:
            result = resp.json()
            click.echo("Added trusted publisher:")
            click.echo(f"  Name:        {result.get('name', name)}")
            click.echo(f"  Fingerprint: {result.get('fingerprint', '')}")
        else:
            click.echo(f"Error: {resp.json().get('error', resp.text)}", err=True)
            sys.exit(1)
    except Exception as exc:
        click.echo(f"Error contacting sidecar: {exc}", err=True)
        sys.exit(1)


@trust.command("list")
@click.option("--json-output", "as_json", is_flag=True, help="Output as JSON")
@pass_ctx
def trust_list(ctx: AppContext, as_json: bool) -> None:
    """List trusted publishers."""
    import requests

    base = _sidecar_url(ctx)
    try:
        resp = requests.get(f"{base}/api/v1/trust", timeout=5)
        if resp.ok:
            publishers = resp.json()
            if as_json:
                click.echo(json.dumps(publishers, indent=2))
            elif not publishers:
                click.echo("No trusted publishers.")
            else:
                click.echo(f"{'NAME':<20} {'FINGERPRINT':<20} {'ADDED'}")
                for p in publishers:
                    fp = p.get("fingerprint", "")
                    if len(fp) > 16:
                        fp = fp[:16] + "..."
                    click.echo(f"{p.get('name', ''):<20} {fp:<20} {p.get('added_at', '')}")
        else:
            click.echo(f"Error: {resp.text}", err=True)
    except Exception as exc:
        click.echo(f"Error contacting sidecar: {exc}", err=True)
        sys.exit(1)


@trust.command("remove")
@click.option("--fingerprint", required=True, help="Publisher fingerprint to remove")
@pass_ctx
def trust_remove(ctx: AppContext, fingerprint: str) -> None:
    """Remove a publisher from the trust store by fingerprint."""
    import requests

    base = _sidecar_url(ctx)
    try:
        resp = requests.delete(
            f"{base}/api/v1/trust",
            params={"fingerprint": fingerprint},
            headers=_API_HEADERS,
            timeout=5,
        )
        if resp.ok:
            click.echo(f"Removed publisher with fingerprint: {fingerprint}")
        else:
            click.echo(f"Error: {resp.json().get('error', resp.text)}", err=True)
            sys.exit(1)
    except Exception as exc:
        click.echo(f"Error contacting sidecar: {exc}", err=True)
        sys.exit(1)
