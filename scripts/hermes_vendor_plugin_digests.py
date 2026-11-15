#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Regenerate the shipped-plugin digests of every supported Hermes release.

The gateway treats a plugin in hermes-agent/plugins as vendor content (not
scanned) only while its tree matches the digest of that plugin in a Hermes
release DefenseClaw ships (internal/watcher/hermes_vendor_plugin_digests.go).
Run this after a Hermes release or a change to the Hermes hook contracts:

    python3 scripts/hermes_vendor_plugin_digests.py
    python3 scripts/hermes_vendor_plugin_digests.py --hermes-repo ~/src/hermes-agent --dry-run

The releases are the stable Hermes release tags (vX.Y.Z, and the vYYYY.M.D
releases before them) whose version resolves to a hermes-hooks contract in
cli/defenseclaw/inventory/hook_contracts.json, tested or newer than the
newest tested one. Each release is checked out from its tag with no newline
conversion, as the Hermes installer checks it out (core.autocrlf=false), and
every shipped plugin is listed and hashed by the gateway own code
(TestGenerateHermesVendorPluginDigests in internal/watcher). The tool writes
the Go digest table and cli/defenseclaw/hermes_vendor_plugin_releases.py,
which doctor and status read to say when the installed Hermes is newer than
every release covered.

Options:
  --hermes-repo PATH  a clone of the Hermes repository with its tags; fetched
                      into a scratch folder when omitted
  --dry-run           generate and report the changes, write nothing
  --help              print this text and exit
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "cli"))

HERMES_URL = "https://github.com/NousResearch/hermes-agent"
GO_OUT = REPO / "internal" / "watcher" / "hermes_vendor_plugin_digests.go"
PY_OUT = REPO / "cli" / "defenseclaw" / "hermes_vendor_plugin_releases.py"
# The release tag forms Hermes publishes; rc, canary and backup tags are not releases.
_SEMVER_TAG = re.compile(r"^v(0|[1-9][0-9]{0,2})\.([0-9]+)\.([0-9]+)$")
_DATE_TAG = re.compile(r"^v(20[0-9]{2})\.([0-9]{1,2})\.([0-9]{1,2})(?:\.([0-9]+))?$")
_INIT_VERSION = re.compile(r"^__version__\s*=\s*\"([0-9]+\.[0-9]+\.[0-9]+)\"", re.M)


def _git(repo: Path, *args: str, env: dict[str, str] | None = None) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True, env=env).stdout


def _release_version(repo: Path, tag: str) -> str:
    """The version Hermes prints for the release at tag."""
    semver = _SEMVER_TAG.match(tag)
    if semver:
        return ".".join(str(int(part)) for part in semver.groups())
    # The date-named releases carry their version in hermes_cli/__init__.py.
    match = _INIT_VERSION.search(_git(repo, "show", f"{tag}:hermes_cli/__init__.py"))
    if not match:
        raise SystemExit(f"{tag}: hermes_cli/__init__.py names no __version__")
    return match.group(1)


def _sort_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def supported_releases(repo: Path) -> list[tuple[str, str, str]]:
    """(version, tag, commit) of every stable release a hook contract covers, oldest first."""
    from defenseclaw.connector_contracts import resolve_connector_contract

    out = []
    for tag in _git(repo, "tag", "--list", "v*").split():
        if not (_SEMVER_TAG.match(tag) or _DATE_TAG.match(tag)):
            continue
        version = _release_version(repo, tag)
        if resolve_connector_contract("hermes", version).status != "known":
            continue
        commit = _git(repo, "rev-parse", f"{tag}^{{commit}}").strip()
        out.append((version, tag, commit))
    out.sort(key=lambda row: _sort_key(row[0]))
    versions = [row[0] for row in out]
    if len(set(versions)) != len(versions):
        raise SystemExit(f"two release tags name one version: {versions}")
    return out


def _checkout(repo: Path, tag: str, dest: Path, index: Path) -> None:
    """Write the plugins folder of tag below dest/hermes-agent, as a checkout does."""
    work = dest / "hermes-agent"
    work.mkdir(parents=True)
    env = dict(os.environ, GIT_INDEX_FILE=str(index))
    _git(
        repo,
        "-c",
        "core.autocrlf=false",
        "-c",
        "core.symlinks=true",
        f"--work-tree={work}",
        "checkout",
        tag,
        "--",
        "plugins",
        env=env,
    )


def generate(repo: Path, scratch: Path) -> tuple[list[tuple[str, str, str]], dict[str, dict[str, str]]]:
    releases = supported_releases(repo)
    if not releases:
        raise SystemExit("no Hermes release resolves to a hermes-hooks contract")
    trees = scratch / "trees"
    for _version, tag, _commit in releases:
        _checkout(repo, tag, trees / tag, scratch / f"index-{tag}")
    out = scratch / "digests.json"
    subprocess.run(
        [
            "go",
            "test",
            "./internal/watcher",
            "-count=1",
            "-run",
            "^TestGenerateHermesVendorPluginDigests$",
            "-args",
            f"-hermes-vendor-trees={trees}",
            f"-hermes-vendor-out={out}",
        ],
        check=True,
        cwd=REPO,
    )
    return releases, json.loads(out.read_text(encoding="utf-8"))


_HEADER = """// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Code generated by scripts/hermes_vendor_plugin_digests.py. DO NOT EDIT.
"""


def render_go(releases: list[tuple[str, str, str]], per_release: dict[str, dict[str, str]]) -> str:
    digests: dict[str, set[str]] = {}
    for _version, tag, _commit in releases:
        for name, digest in per_release[tag].items():
            if digest:
                digests.setdefault(name, set()).add(digest)
    lines = [_HEADER, "package watcher", ""]
    lines.append("// hermesPluginVendorDigests holds, for each plugin the rescan enumerates")
    lines.append("// under hermes-agent/plugins, the digest of its tree (hermesPluginTreeDigest)")
    lines.append("// in each of these Hermes releases that ships it, one per distinct tree:")
    lines.append("//")
    for version, tag, commit in releases:
        lines.append(f"//\t{version}\t{tag}\t{commit}")
    lines.append("//")
    lines.append(f"// Source: {HERMES_URL}")
    lines.append("var hermesPluginVendorDigests = map[string][]string{")
    for name in sorted(digests):
        lines.append(f"\t{json.dumps(name)}: {{")
        for digest in sorted(digests[name]):
            lines.append(f"\t\t{json.dumps(digest)},")
        lines.append("\t},")
    lines.append("}")
    return "\n".join(lines) + "\n"


def render_py(releases: list[tuple[str, str, str]], per_release: dict[str, dict[str, str]]) -> str:
    newest = releases[-1][1]
    count = sum(1 for digest in per_release[newest].values() if digest)
    lines = [
        "# Copyright 2026 Cisco Systems, Inc. and its affiliates",
        "# SPDX-License-Identifier: Apache-2.0",
        "",
        "# Code generated by scripts/hermes_vendor_plugin_digests.py. DO NOT EDIT.",
        "",
        '"""The Hermes releases whose shipped plugins the gateway recognizes by digest."""',
        "",
        "# (version Hermes prints, release tag, commit), oldest first; the same",
        "# releases as internal/watcher/hermes_vendor_plugin_digests.go.",
        "RELEASES: tuple[tuple[str, str, str], ...] = (",
    ]
    for version, tag, commit in releases:
        lines.append(f"    ({json.dumps(version)}, {json.dumps(tag)}, {json.dumps(commit)}),")
    lines.append(")")
    lines.append("")
    lines.append("# The shipped plugins of the newest release.")
    lines.append(f"NEWEST_PLUGIN_COUNT = {count}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("\n\n", 1)[1],
    )
    parser.add_argument("--hermes-repo", type=Path, help="a clone of the Hermes repository with its tags")
    parser.add_argument("--dry-run", action="store_true", help="report the changes, write nothing")
    args = parser.parse_args(argv)
    with tempfile.TemporaryDirectory(prefix="hermes-vendor-") as tmp:
        scratch = Path(tmp)
        repo = args.hermes_repo
        if repo is None:
            repo = scratch / "hermes-agent"
            subprocess.run(
                ["git", "clone", "--quiet", "--filter=blob:none", "--no-checkout", HERMES_URL, str(repo)], check=True
            )
        releases, per_release = generate(repo.resolve(), scratch)
    outputs = {GO_OUT: render_go(releases, per_release), PY_OUT: render_py(releases, per_release)}
    for version, tag, _commit in releases:
        unverified = sorted(name for name, digest in per_release[tag].items() if not digest)
        print(
            f"{version} ({tag}): {len(per_release[tag]) - len(unverified)} plugins"
            + (f", not verifiable: {unverified}" if unverified else "")
        )
    for path, text in outputs.items():
        current = path.read_text(encoding="utf-8") if path.exists() else ""
        state = "unchanged" if current == text else "changed"
        if args.dry_run:
            print(f"{path.relative_to(REPO)}: {state} (dry run, not written)")
        elif state == "changed":
            path.write_text(text, encoding="utf-8")
            print(f"{path.relative_to(REPO)}: written")
        else:
            print(f"{path.relative_to(REPO)}: unchanged")
    return 0


if __name__ == "__main__":
    sys.exit(main())
