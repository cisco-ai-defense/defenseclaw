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

"""Keep ``<policy_dir>/rego`` on the Rego modules this release ships.

The gateway evaluates the admission and guardrail modules it finds in
``<policy_dir>/rego``. ``init`` used to copy a shipped module only when the
file was missing, so an install kept the modules of the release that first
seeded it, and a fix in a shipped module never reached an upgraded user
(GAP-0776). A module whose bytes are those of a module some release shipped
(``STOCK_REGO_DIGESTS``) was not edited.

- ``init`` writes a missing module and brings an unedited one to this
  release. An edited module is kept and reported: it was edited for the
  installed release.
- An upgrade (``defenseclaw migrate``) brings every shipped module to this
  release, an edited one too, because the modules carry enforcement fixes.
  The previous copy is kept in ``<data_dir>/backups/rego-<time>/`` and the
  upgrade names the edited ones. An unedited copy of a module this release no
  longer ships (0.8's sandbox.rego, skill_actions.rego) moves there as well.

Rules in a file of another name (the policy creator writes
``custom-<name>.rego``) are never touched. Run
``python -m defenseclaw.rego_policies`` to print the digests of the shipped
modules; a release that changes a module adds its digest here.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import shutil
import stat
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

# SHA-256 (CRLF read as LF) of every version of each module that a release
# or a 1.0 stack build shipped, the retired ones included.
STOCK_REGO_DIGESTS: dict[str, frozenset[str]] = {
    "admission.rego": frozenset(
        {
            "010208a88c34e89705d4ced437543ed1b89f65d2b545ccc90f8599a1717a84f5",
            "04128e88a2125c8ae6dad2811a57b90a4f61702db7b50904fc9be670373b39ab",
            "08157cd0c1de8cb7feb040624016f71165b8b1baa2f7676db5f6af5a24c9bdac",
            "4dc4d8b0cf838157423c06a7e594e0110d6c19c0828db331845a3d540bf7ec57",
            "67a1831178e23d6bf8a4dd6d95ea53402c6827c6b1dc0536c8e7667c7586a53b",
            "9dfe95603d4a738909795a4e77eb7315fc114768dee4f87ec9fab7759f8f30d5",
            "a54e581eb230bb0dd3f97938daca5dcc4d3afef42d48c224f29081f37d8dc3d0",
            "b105ce0e0d756f4ab4be3b185b6201049cc044733572d19deb33e6b24f8f4071",
            "b7cc8b152464899618781de6ae23eb37efbac5c5f9717c0642068013f7e63011",
            "bf31313dded61d6de664ce71c15644c3817adc8d402d0a5c6805603eff653bf1",
            "c08676ddf79eafee6deae18589c30a2167c708bc8d2dc633b4992d8c8e7a97f2",
        }
    ),
    "audit.rego": frozenset(
        {
            "71461c94eef2883a6351bfb1d999ecff6f45acd810136ea16eb2a74e30de309e",
            "a40b408b08f976153e5937220efaaeb73460055b3ba10831061b5be55ae2c108",
            "a49b54100fd60e1fcac10d5d0c312cbfdfb9d90b6ab7a6aa814c4d9753764731",
        }
    ),
    "firewall.rego": frozenset(
        {
            "cc51d978cf63b63f5bb0f21c4710019d106e9bcf7f9100536d35525b8d4ce5a5",
            "f25789d7f70eac393f8ecbc14981b87e7ae36dbb49ba97f1e8f0cb7156166037",
        }
    ),
    "guardrail.rego": frozenset(
        {
            "045a23ecd4a75731be58e0bb2e0b4bc2e7b3f58d5da9ace56806c1ba0bdfd4d6",
            "18a563b37c0bec87a3743f566f4f4200bbac87977b783a290841d1aaeedfb753",
            "263694287d114334fc967cbead74ebd87222a2704154a9a1698eb7b6eb7fb599",
            "7f23ccd790fe9d71052b4f5fb21439b3c9eb2a51e9d26974ae724767faf514ad",
            "9b6a05b25105cd38b33d0c41aa417a849b07fe382008770748012baecf6fc0a1",
            "b17b0841d21f8ac431f7b095df4ad4f2f19f49266251ba5ec040549eb2577112",
            "c6379fa813cd36afcb3444f7c93b1583b7cdff51d2ed50c9d795c94b227258b5",
            "d1c270a84d27b83e135632bcea2ed0c518838b237f4a421b79b404ce8a4c2ac9",
            "da4c2d505bf311e13ee0f3d27677804606ab8ddbf6dcfac10267190f019d6002",
        }
    ),
    "sandbox.rego": frozenset(
        {
            "99d7f6cdf3f67ce252f606856d89e48107de40fae92ae34f7227d00695998509",
            "c0a7cb1c76e3d72b2cf458d775d622be2c6c97a72a9ab178ec130e69c00d2d40",
        }
    ),
    "skill_actions.rego": frozenset(
        {
            "7b22b15859ee0396e0bca8bee2e9d82236ae37614f7d765bb87a08ea7b3d93d3",
            "89c69787e0ac4e5d5e6bb9ac88496610d4ed102758bb2322c12b1d8a3df02f42",
            "c3cb1ab336b9799ccecaef453cd33d583aeada0571e87092e1491c2c8ded924a",
        }
    ),
}


@dataclass
class RegoResult:
    dest: str = ""
    seeded: list[str] = field(default_factory=list)
    refreshed: list[str] = field(default_factory=list)
    replaced_edited: list[str] = field(default_factory=list)
    kept: list[str] = field(default_factory=list)
    retired: list[str] = field(default_factory=list)
    backup_dir: str = ""
    errors: list[str] = field(default_factory=list)


def module_digest(data: bytes) -> str:
    return hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()


def _is_stock(name: str, data: bytes) -> bool:
    return module_digest(data) in STOCK_REGO_DIGESTS.get(name, frozenset())


def shipped_modules() -> dict[str, Path]:
    """The Rego modules this release installs; unit tests are not installed."""

    from defenseclaw.paths import bundled_rego_dir

    bundled = bundled_rego_dir()
    if not bundled.is_dir():
        return {}
    return {
        path.name: path
        for path in sorted(bundled.iterdir())
        if path.suffix == ".rego"
        and not path.name.startswith(".")
        and not path.name.endswith("_test.rego")
        and path.is_file()
    }


def seed_rego(policy_dir: str, backups_root: str, *, refresh_stock: bool = True) -> RegoResult:
    """init: write the missing modules and bring unedited ones to this release."""

    result = RegoResult()
    shipped = shipped_modules()
    if not shipped or not policy_dir:
        return result
    dest = Path(policy_dir) / "rego"
    result.dest = str(dest)
    try:
        dest.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        result.errors.append(f"mkdir {dest}: {exc}")
        return result
    for name, source in shipped.items():
        target = dest / name
        try:
            if not os.path.lexists(target):
                shutil.copy2(source, target)
                result.seeded.append(name)
                continue
            if not refresh_stock:
                continue
            current = _regular_bytes(target)
            if current is None or current == source.read_bytes():
                continue
            if not _is_stock(name, current):
                result.kept.append(name)
                continue
            _replace(source, target, _backup_dir(result, backups_root))
            result.refreshed.append(name)
        except OSError as exc:
            result.errors.append(f"{name}: {exc}")
    return result


def refresh_rego(policy_dir: str, backups_root: str) -> RegoResult:
    """An upgrade: bring the shipped modules in ``<policy_dir>/rego`` to this
    release, and move unedited copies of retired modules to the backup."""

    result = RegoResult()
    shipped = shipped_modules()
    dest = Path(policy_dir) / "rego" if policy_dir else None
    if not shipped or dest is None or not dest.is_dir():
        return result
    result.dest = str(dest)
    for name, source in shipped.items():
        target = dest / name
        try:
            current = _regular_bytes(target)
            if current is None:
                if os.path.lexists(target):
                    result.kept.append(name)
                continue
            if current == source.read_bytes():
                continue
            stock = _is_stock(name, current)
            _replace(source, target, _backup_dir(result, backups_root))
            (result.refreshed if stock else result.replaced_edited).append(name)
        except OSError as exc:
            result.errors.append(f"{name}: {exc}")
    for path in sorted(dest.glob("*.rego")):
        if path.name in shipped:
            continue
        try:
            current = _regular_bytes(path)
            if current is None or not _is_stock(path.name, current):
                continue
            shutil.move(str(path), os.path.join(_backup_dir(result, backups_root), path.name))
            result.retired.append(path.name)
        except OSError as exc:
            result.errors.append(f"{path.name}: {exc}")
    return result


def stale_modules(policy_dir: str) -> list[str]:
    """The shipped modules in ``<policy_dir>/rego`` that differ from this release's."""

    dest = Path(policy_dir) / "rego"
    stale = []
    for name, source in shipped_modules().items():
        with contextlib.suppress(OSError):
            current = _regular_bytes(dest / name)
            if current is not None and current != source.read_bytes():
                stale.append(name)
    return stale


def _regular_bytes(path: Path) -> bytes | None:
    """The content of path when it is a regular file (not a link), else None."""

    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode):
        return None
    return path.read_bytes()


def _backup_dir(result: RegoResult, backups_root: str) -> str:
    if not result.backup_dir:
        os.makedirs(backups_root, mode=0o700, exist_ok=True)
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        path = os.path.join(backups_root, f"rego-{stamp}")
        suffix = 1
        while True:
            try:
                os.mkdir(path, 0o700)
                break
            except FileExistsError:
                suffix += 1
                path = os.path.join(backups_root, f"rego-{stamp}.{suffix}")
        result.backup_dir = path
    return result.backup_dir


def _replace(source: Path, target: Path, backup_dir: str) -> None:
    """Copy target into backup_dir, then put source in its place in one rename."""

    shutil.copy2(target, os.path.join(backup_dir, target.name))
    mode = stat.S_IMODE(os.stat(target).st_mode)
    fd, staged = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(source.read_bytes())
        os.chmod(staged, mode)
        os.replace(staged, target)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(staged)
        raise


def _main() -> None:
    for name, path in shipped_modules().items():
        print(name, module_digest(path.read_bytes()))


if __name__ == "__main__":
    _main()
