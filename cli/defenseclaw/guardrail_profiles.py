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

"""Refresh seeded guardrail rule-pack profiles on upgrade.

``init`` copies the bundled profiles (default, strict, permissive) into
``<policy_dir>/guardrail/`` once and never overwrites them, because operators
may edit them in place. An upgrade therefore kept enforcing the rules of the
release that first seeded them. A profile whose files are exactly those of a
profile some release shipped (``STOCK_PROFILE_DIGESTS``) was not edited, so
the upgrade replaces it with this release's copy and keeps the old one in a
backup. An edited profile is kept and reported.

Run ``python -m defenseclaw.guardrail_profiles`` to print the digests of the
bundled profiles; a release that changes a profile adds its digest here.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path

# Digests of every default/strict/permissive profile that a release or a
# 1.0 stack build shipped (profile_digest of policies/guardrail/<name> at
# each release tag and at each commit that changed it).
STOCK_PROFILE_DIGESTS: dict[str, frozenset[str]] = {
    "default": frozenset(
        {
            "0678175caa680c77ffd723c5ffd7d581e5d6747c884e71b61aa3bfedba92e1b6",
            "20a9adcda34d02c061e6f1c0073546fcc540f97ee604b55401ba0f9946ef4a70",
            "3b60ff13444113a2d41cf9f4002794685267b61ec82ccf309fa6d6419fb3bdfd",
            "3eec0102c3fd29f3cb9205b0cb3750cbc2b88de821ed5d943081e5605d5fefad",
            "55f5a0278318615f350752ff4f00d1ccd995cd52a46a9a7f0a32c5f783f7bb35",
            "5b9ca53ad605b53d1d1618b51e52c658140d42190e6f903abaaca604ae145c93",
            "60eca49dfa2a1f7578e40a288d93a0849755204602fe68044726b14db30d5d4d",
            "681d8e7f28cb4030cdd68aae6cc494517f034e355aa4b964fccd391d8b1dd0a4",
            "8c28e4d946d9c9fe01d3fb4a7254db347e6183c1b659fbfb37a1aeaebc08f63c",
            "9dc9a1aa028a8b2232babe38e8519f864a1f6d3a6b3990150c2ec3f907d71b8a",
            "a3481c6ce6bf367a0282b4ba97329d78ee40ab32371b3b0bbab6980d31f5fa56",
            "ac605bb145db8df3803a27cfcbe9958ef3a22c7038a626e6f8c1503887813905",
            "aee0a2044e72b0ae9b028b7d40105bb275e60387e2f561e52d729074b7bf1198",
            "b4cfd6a7301e6ca9ca77cef547e5461da54602bae979343fb69ec576877f69c4",
            "b5966ccf711d96c4d4797cc722fa6a23794c3516a2bbb204adce313ed86ca045",
            "c152251f48fe5e3c217202b60d1ca8dfd46d245900c758dce45ebdde31f707b8",
            "d20d889c468919185d2c175d6131bdd8824fb572d00ee3d285095f7507534019",
            "e58d2d497dd75d9ee38dd6a5fc7b30aef00ae7d4966a5b5d6cc33c6005acdbe8",
            "eb35cfd63246ee6343faf4114ea9a6b62155f8faf6825f05a2bb9180444bb61d",
            "ef527c66677705936f1ee319b24a76f3401286a1362265251ae2a69dc4f6dd22",
        }
    ),
    "permissive": frozenset(
        {
            "06295d7fc02c0168fb93403a27f42b41127756d251a3d04c2c167db5dfca3f49",
            "09e49a34880ace6a9b29d613a8af16bd7f96063e7a6361897a77df475abd7859",
            "25a73df95116e71d06b8043f82df3e79e4bf943cb2e2e72529448e5ef91c009b",
            "29ce292e52f2fac289d6567ec7994b1f17af98e3fd1c4a5e2084f8c8a97b5371",
            "3ecdef60681cc5922962c48882de64b97f56605e22c6952bd49bb156ea445328",
            "45b3e39a75a57d6220b62c35bfa57ea3fcbd55ad0f8bdc97c20ac7523fc5a61a",
            "69256416b4fcdcce3c9981d153242cc8a68fc659ed216767bc44e89052e2499c",
            "6dd147550abcb729f5bc59f4f7be5ff04ff4d40b57a45a7848a8139b8c35ffe9",
            "6ded828057977035dc763c35fc117ab2caf63ebc42bf79c70b2eb78d3c44a228",
            "7be65bc5f810de910c07ed0cc955606d0c49fecc9644b438f043ec0eddba3883",
            "9006dc19c958f8b2fa5fe7aba6d54e2fb8454f634b3fc6b6abf777c15a9e6604",
            "a1291dd16dbd6350daa6b94425bcfa19e734d99e1962e38e64915573d64f27c2",
            "a8c864dc71a7201897b4bfe5770187dedaae939ed51d8923ca6b2367b3501d79",
            "b890f74b17262c155256632e92d5b7545c39c5a02ddbbde88f9421ee5a15e91b",
            "ba3c328ac60c00cd249228cc36cb0cc2bec6ae5141b302b5ca9fc89c6ac0914e",
            "db652db02c4570c3a630a61c4239746134e1125430af4d1f119aa5564207944e",
            "dd435b76cb1905e89cd6cd4b97cec7f48e19576b837d4b2d0fb693f114cc17f5",
            "e091aa508431e9ad0adcf04a9a17cf38ab7957019f5df58d8d5f2e23b0e3fc6b",
            "f1e4fd9a0be9cfac47f5eb47f3086378cd6f9d8f82bfd462ea75296c99d0d913",
            "fa8ca0ad415436e8b4f5d6043f36de782cfe27bfbfca83f27d2359b97914f5f7",
        }
    ),
    "strict": frozenset(
        {
            "3bff549d5860011cd63f0654455b6cc0d49e9493bd607284c12be6c764e10893",
            "4f9b68412f1cb102b54dad54a08c6e45d254e79984dccd84451cfdca62470e7f",
            "5b9b0f79c491c27b3feed63b90765091d37345621a95792ebcd34195abb097fd",
            "6e83a82ef15257b0d184e3418dba66625bd3f15736193582779dc7be07719021",
            "75e46a0c8a460f001bd3783909ffb781d3e46450cffc0361e4bb6f8601031b3e",
            "9239bfef0d18ad54bbe55f955885d7a4391556f3d272223d347669f77f54b32b",
            "9308580254480e56c1b865592186226f3c83e72e01c65e6c6b4c8e414e4980ba",
            "9a718f87b06f75cfb1f4fa223fc6f3692ced3ecc17c10b5c8b96fff617d5da67",
            "9e8416be13a3a62f9e5a486570b6fce4673b86e2d834aa4d8891732bbaecea9c",
            "9f54aa385dffab92b7c08180ea2e37142d4fcf6ce3a53a29d9c0fc63374e0ff9",
            "a30346773809eb3571e1e44508e343cfc72ac70ed605b9837d0dcd663f2375e0",
            "c31e5e90da9c3a6521c328adb9ac7883555d1acd7ad287cc43e5fa56237bfa35",
            "c78061e9d90d91005913add8b0c046b05ecf921648494e7b035b6a4bf37956c1",
            "c7b0103f24c84a775050494b6fff77bebe5f6404ec8a62097f8a6f97dc81b3ac",
            "db6ca1ece31914feab3234c49b469094e2c5997f09b37578eb981b17a30d9a10",
            "e21488344cfb0ca04d3cbe7c90f1101df2dd5bfcb0319af201655d3766289e6c",
            "e5b085aa79494d1b7b78279b9a301841cb8c4bbea76e1b3f4af2ff11dec2ed0d",
            "e9e7bde2dccb00dd7207ee1cf372ecd901bdac84bb0fea5098770af10de04206",
            "f5d6d19b78fe7d3897acb6a28a9fae08049fcda9745f944d5cdb45e573669bc5",
        }
    ),
}


@dataclass
class ProfileRefreshResult:
    refreshed: list[str] = field(default_factory=list)
    kept_modified: list[str] = field(default_factory=list)
    backup_dir: str = ""
    errors: list[str] = field(default_factory=list)


def _profile_files(root: Path) -> list[Path]:
    files = []
    for path in root.rglob("*"):
        rel = path.relative_to(root)
        if any(part.startswith(".") or part == "__pycache__" for part in rel.parts):
            continue
        if path.is_file():
            files.append(path)
    return sorted(files, key=lambda p: p.relative_to(root).as_posix())


def profile_digest_from_files(files: dict[str, bytes]) -> str:
    """Digest of a profile given ``{relative posix path: content}``."""

    digest = hashlib.sha256()
    for rel in sorted(files):
        digest.update(rel.encode("utf-8") + b"\0" + hashlib.sha256(files[rel]).hexdigest().encode() + b"\n")
    return digest.hexdigest()


def profile_digest(root: str | Path) -> str:
    """Digest of the files of a profile directory (dot files ignored)."""

    root = Path(root)
    return profile_digest_from_files({p.relative_to(root).as_posix(): p.read_bytes() for p in _profile_files(root)})


def refresh_stock_profiles(policy_dir: str, backups_root: str) -> ProfileRefreshResult:
    """Replace unedited seeded profiles that differ from the bundled ones."""

    from defenseclaw.paths import bundled_guardrail_profiles_dir

    result = ProfileRefreshResult()
    bundled = bundled_guardrail_profiles_dir()
    if bundled is None or not policy_dir:
        return result
    dest_root = Path(policy_dir) / "guardrail"
    for profile in sorted(bundled.iterdir()):
        if not profile.is_dir() or profile.name.startswith("."):
            continue
        dst = dest_root / profile.name
        if not dst.is_dir() or dst.is_symlink():
            continue
        try:
            current = profile_digest(dst)
            if current == profile_digest(profile):
                continue
            if current not in STOCK_PROFILE_DIGESTS.get(profile.name, frozenset()):
                result.kept_modified.append(profile.name)
                continue
            if not result.backup_dir:
                stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
                result.backup_dir = os.path.join(backups_root, f"guardrail-profiles-{stamp}")
                os.makedirs(result.backup_dir, exist_ok=True)
            _swap_in(profile, dst, Path(result.backup_dir) / profile.name)
            result.refreshed.append(profile.name)
        except OSError as exc:
            result.errors.append(f"{profile.name}: {exc}")
    return result


def _swap_in(source: Path, dst: Path, backup: Path) -> None:
    """Move dst to backup and put a copy of source in its place."""

    staged = dst.with_name(f".{dst.name}.refresh")
    shutil.rmtree(staged, ignore_errors=True)
    try:
        shutil.copytree(source, staged)
        shutil.move(str(dst), str(backup))
        try:
            os.replace(staged, dst)
        except OSError:
            shutil.move(str(backup), str(dst))
            raise
    finally:
        shutil.rmtree(staged, ignore_errors=True)


def _main() -> None:
    from defenseclaw.paths import bundled_guardrail_profiles_dir

    bundled = bundled_guardrail_profiles_dir()
    if bundled is None:
        raise SystemExit("no bundled guardrail profiles")
    for profile in sorted(p for p in bundled.iterdir() if p.is_dir()):
        print(profile.name, profile_digest(profile))


if __name__ == "__main__":
    _main()
