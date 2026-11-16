#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Print VENDOR_DIGESTS rows for published OpenClaw provider releases.

Pinned rows let a host without registry access identify a release; a release
that is not pinned is confirmed against the npm registry when it is scanned,
so adding rows is optional. To pin a release, paste the rows into
cli/defenseclaw/scanner/plugin_scanner/vendor_identity.py:

    python3 scripts/openclaw_provider_digests.py 2026.11.1 2026.11.2

Each release is fetched with ``npm pack`` and unpacked into a scratch folder.
The digest covers the package own files only, exactly as the scanner computes
it for an installed plugin, so an install by OpenClaw and the published
package give the same value.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "cli"))

from defenseclaw.scanner.plugin_scanner.vendor_identity import _package_digest  # noqa: E402

PACKAGE = "@openclaw/amazon-bedrock-provider"


def digest_of_release(version: str) -> str:
    with tempfile.TemporaryDirectory() as scratch:
        subprocess.run(
            ["npm", "pack", f"{PACKAGE}@{version}", "--silent"],
            cwd=scratch, check=True, stdout=subprocess.DEVNULL,
        )
        (archive,) = Path(scratch).glob("*.tgz")
        target = Path(scratch) / "unpacked"
        with tarfile.open(archive) as bundle:
            bundle.extractall(target, filter="data")
        digest = _package_digest(str(target / "package"))
    if digest is None:
        raise SystemExit(f"{PACKAGE}@{version}: tree cannot be identified")
    return digest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("versions", nargs="+")
    for version in parser.parse_args().versions:
        print(f"    (\"{PACKAGE}\", \"{version}\"):")
        print(f"        \"{digest_of_release(version)}\",")


if __name__ == "__main__":
    main()
