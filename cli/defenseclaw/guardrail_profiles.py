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

A downgrade has the same problem the other way round (GAP-1077): the older
release only knows the digests it shipped, so it reads an unedited profile of
this release as the user's edit and keeps it. The older release cannot change,
so the downgrade of this release puts the target release's own profiles in
place of the unedited ones before it hands over (``restore_unedited_profiles``).
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
            "19f3cf6086023cfc419756c4b30fe395820b008ba831653949b0c33f2daf76a4",
            "20a9adcda34d02c061e6f1c0073546fcc540f97ee604b55401ba0f9946ef4a70",
            "30833ca25490a295a65c778827394fa64a8d3f4aedc589648355aa55509b72d6",
            "37d8dc92222a208b8a769155b44040a2ebcd7bffebd7691461f28c079594407a",
            "3b60ff13444113a2d41cf9f4002794685267b61ec82ccf309fa6d6419fb3bdfd",
            "3eec0102c3fd29f3cb9205b0cb3750cbc2b88de821ed5d943081e5605d5fefad",
            "4dd01c0e72595849517354cbb4e7910d2b0116a62825e5c6578d2e0d5a99f0ef",
            "55f5a0278318615f350752ff4f00d1ccd995cd52a46a9a7f0a32c5f783f7bb35",
            "5b9ca53ad605b53d1d1618b51e52c658140d42190e6f903abaaca604ae145c93",
            "60eca49dfa2a1f7578e40a288d93a0849755204602fe68044726b14db30d5d4d",
            "681d8e7f28cb4030cdd68aae6cc494517f034e355aa4b964fccd391d8b1dd0a4",
            "8c28e4d946d9c9fe01d3fb4a7254db347e6183c1b659fbfb37a1aeaebc08f63c",
            "9dc9a1aa028a8b2232babe38e8519f864a1f6d3a6b3990150c2ec3f907d71b8a",
            "9fba3bb1b2c4eec5b675643b6a08f823dc6f61502a4bbacf0f2b60157df737bf",
            "a0d12b51f95bc89984029f75f05b4d72bae10616f70989cdb579a70791da4bc7",
            "a3481c6ce6bf367a0282b4ba97329d78ee40ab32371b3b0bbab6980d31f5fa56",
            "a46aeb365366f023836828a9436b959037c15530b5a20cf3dde3fad34f9b393f",
            "ac605bb145db8df3803a27cfcbe9958ef3a22c7038a626e6f8c1503887813905",
            "ae355baebd30f92166f073f811828470e6f539363f8ca1af88427aa8208d110c",
            "aee0a2044e72b0ae9b028b7d40105bb275e60387e2f561e52d729074b7bf1198",
            "b4cfd6a7301e6ca9ca77cef547e5461da54602bae979343fb69ec576877f69c4",
            "b5966ccf711d96c4d4797cc722fa6a23794c3516a2bbb204adce313ed86ca045",
            "b974b0cef8f33b0ae11db340911a2a5a12510e4f030c8be35cf23b5701f7d245",
            "baa78282c632122c9a883a4cb329c1bfdee589e28efc7a2064b8673c1d6144f4",
            "c152251f48fe5e3c217202b60d1ca8dfd46d245900c758dce45ebdde31f707b8",
            "cb255ef84956b68ddfd6e045737a5dfbd46f84b8dcb805756f2dce6cae8f4b80",
            "d20d889c468919185d2c175d6131bdd8824fb572d00ee3d285095f7507534019",
            "dea626828ba51945f7c3aaa6b9ee3cebbfd15750427d4d6ef6c62342c60d04b7",
            "e58d2d497dd75d9ee38dd6a5fc7b30aef00ae7d4966a5b5d6cc33c6005acdbe8",
            "ea81d7cea6c23a7de47e62379572f29704df1a24e0e5efe22e9b02a6f159af95",
            "eb35cfd63246ee6343faf4114ea9a6b62155f8faf6825f05a2bb9180444bb61d",
            "ef527c66677705936f1ee319b24a76f3401286a1362265251ae2a69dc4f6dd22",
            "f24c07c3beea7d1b590347461d9d263db597aad5bd73f1a43b4a546f60df4ad0",
            # 1.0.10 (rel/1.0.10, e681992abf): tool-injection judge answer template shows "none".
            "eff50a0531271623e510832a1cb3d7044940cbc8096ecf2a6bc8da190f4504da",
            # 1.0.10 (s7/shellrecall): five alert-only effect rules
            # (staged file, stdin password, download-run, git, inline code).
            "fbb392bb8ac84607447cefa5a889cfe95ad396026c46159501d634c52bdd25ef",
            # 1.0.10 (s7/pii-email merged with rel/1.0.10 and s7/cascade): adds the two email PII rules.
            "55665ae8a227130bb6d1ee97a3610e43b58256f7763b495cb684631ca0d56cda",
            # 1.0.10 (s7/promptfloor + s7/pii-email, GAP-0175/GAP-0172): prompt-injection floor
            # and the two email PII rules.
            "3c30a91dfbda99fe4f72e5d78d300979fa0fb1561f8495018b9b1184ba10ff29",
            # 1.0.10 (s7/secret-recall): SEC-SECRET-ASSIGN, a generic credential-assignment rule.
            "bada955b0ca029db29465c2ab0d5b4ffde02406eed0e16c36e70c7bc1de27ec6",
            # 1.0.10 (s7/ad-pack): credentialed NetExec folded into credential.directory_ticket_request.
            "0dcc0d9a1cd54d73c8267c8950bb759806cd8e5a36b50b90d979ac39cc9eae18",
            # 1.0.10 (rel/1.0.10 INT batch 4): s7/pii-email email rules plus s7/ad-pack NetExec fold.
            "b82abc998f4b917dbbc856bda3bb4f9211ce829b3ab86a6464a031b6953b680a",
            # 1.0.10 (s7/promptfloor merged with rel/1.0.10 a5d59bf2b9): prompt-injection floor,
            # email PII rules and the NetExec fold.
            "e77d12c6c5ccec6408c3e0587dea4ddc8ff6c7377e892d699ce077355d6cf833",
            # 1.0.10 (s7/promptfloor-rel on rel/1.0.10 46ba344cbc): prompt-injection floor on INT
            # batch 10 and sed-suffix.
            "c25d5c970e44f2e337381e31d463e61107e95d896b420f02d98dad591b157505",
            # 1.0.10 (s7/secret-recall delta sr5, merged with rel/1.0.10): SEC-SECRET-ASSIGN reads = ( ) in a value.
            "ab20b275b3c44a0ade2cc47942dbe18d40a4cadb5626315ecb097b905f110f76",
            # 1.0.10 (s7/secret-recall delta sr6, merged with rel/1.0.10 a75abaec78): the profile with SEC-SECRET-ASSIGN
            # and the batch 9 shell recall rules.
            "b5cd7987ebc0047977727d2ce6ed58bee849229f4b6b6e3a5e07f3d3e6275e79",
            # 1.0.10 (s7/toolresult, rel-1-0-10 GAP-0171): contact tag on the email/phone rules; ENT-DL-CA and
            # ENT-BULK-SSN-NOHYPHEN carry their label in the pattern.
            "09f044aa6791dab5e73c031c65d7217098cef576c5f8d16a02ce059d4da5a7a2",
            # 1.0.10 (rel/1.0.10 INT batch 11): sysone, openclaw-msg, secret-recall, toolresult, nonshell,
            # psfloor, sender and response-fields packs.
            "bcea83c78cdebc78f4cd5ac07321a9ce8cc91f9d7d6f0d9b49dbb6d7f6829870",
            # 1.0.10 (rel/1.0.10 INT batch 11 delta 3): + g596 self-protection rules.
            "b8be2e07c3cdfcd48ea89580512d0c79629bfa61bb84a9571313a82997fd5267",
            # 1.0.10 (rel/1.0.10 INT delta 4): + partjoin, browserjs, g594, parity P1 packs.
            "e40590dad7e43d9d37c30a8e6e54c4515d435fbf882d900d944edebd18e2eff1",
            # 1.0.10 (s7/nonshell merged with rel/1.0.10 7f32dbb3a0): MCP and app tool rules, credential-store and
            # command rule ids.
            "b10430a9f09cf9341d1810047bdc4db50be2987e2f27584af20e579e13e20b09",
            # 1.0.10 (rel/1.0.10, s7/nonshell): MCP and app tool rules (toolshape), credential-store and command rule
            # ids.
            "bae849da47c25cb44132971419ea52e8c7a87b0bd994fece05d1f98bccda2392",
            # 1.0.10 (rel/1.0.10 INT batch 10): shellrecall effect rules plus nonshell toolshape rules.
            "a86801cc5e8efd1c6c8c4b88164c9bcd608fad5200371e7cc0632e297309bd7a",
            # 1.0.10 (s7/response-fields): SEC-BEARER-BARE and SEC-PASSWORD-ASSIGN (GAP-0371).
            "69e71164e4798439ed96acd8070ff36eb03bfe2ce260b3c46221824497610275",
            # 1.0.10 (s7/response-fields merged with rel/1.0.10 a75abaec78): plus the s7/shellrecall effect rules.
            "657b41873648522db2f5f1d2237a822f94712b4775267cd7e129b62c2bfbbc16",
            # 1.0.10 (s7/gemma4-judge-rel): tool-injection judge context packet
            # (DEFENSECLAW CONTEXT) and two benign-case lines.
            "70b55b216a595762d2fbcd26aa00bc10f08f7852a7b4c95642a0e1f6ff478ac4",
            # 1.0.10 (s7/gemma4-judge-rel merged with int/r110-b11d3 a35d0653ef): the judge context packet on
            # the delta 3 packs.
            "107d55a8f760e474f198f9ebaff521e4ca8306c8a7d84d1730f8fe2db0309b0d",
            # 1.0.10 (s7/partjoin-pf-rel + int/r110-b11 1876efd336 + s7/partjoin-p3 02491003b4): prompt-injection floor,
            # joined-parts views and TRUST-AUTHORITY \s+ on the batch 11 packs.
            "41540a4a3658634f407df598c53e1c4177c2d486b40170f791299856c95aaf99",
            # 1.0.10 (pjb11 x int/r110-b11d3 06b44c691f): the pf-rel + p3 packs with the delta-3 rules
            # (s7/response-fields SEC-BEARER-BARE, SEC-PASSWORD-ASSIGN).
            "5f564596c05ab95046fd8a51c749a9c4b8c107d125733e6f31a0b6fa10c046a1",
            # 1.0.10 (s7/partjoin-pf-rel 54d074e01f x int/r110-b11d3 664a7caa8c): the pjb11 packs with
            # the delta-3 g596 self-protection rules.
            "d04b477b9e8776d7cd94385cccfebb18fa498091719fab8357f2a0491ce1526b",
            # 1.0.10 (s7/browserjs merged with int/r110-b11d3 a35d0653ef): PAGE-SCRIPT-SESSION-EGRESS (alert only).
            "1c75c960dc15577086448f319605479c553acbcbd600dfa5102ed2ecdbe0936b",
            # 1.0.10 (s7/gemma4-judge-rel merged with int/r110-b11d4 033c5cbd2b): the judge context packet on
            # the delta 4 packs.
            "48b9e16495f0d8b860964b0b813cd6347edc20eba48e0194ddd7cc84b45ecff9",
            # 1.0.10 (s7/g1058fix on s7/td327fix7 a41329ba08): the td327 train on the delta 4 packs;
            # the typed path check of PATH-ETC-SHADOW is a Go rule of internal/toolshape (rel-1-0-10:GAP-1058).
            "142564606e41360723658f06c3d71f449b80849d789767370e9b948697316882",
            # 1.0.10 (s7/g0210port-r2 on rel da4177e225, rel-1-0-10:GAP-0210, GAP-1267, GAP-1268): SEC-HF-TOKEN and
            # the SEC-PASSWORD-ASSIGN value class (backticks, next line, comma) in secrets.yaml.
            "ca7e62eec5d39e2f6f1f3eeec648c25c5bfd32c19d05380e19aa44aaa1bddf1e",
            # 1.0.10 (s7/rules-fu12, rel-1-0-10:GAP-1574): cognitive.yaml CRITICAL -> HIGH (87a7927568).
            "6a7668cde7efc0eb7ec557a04a205a7416a4edd9e6f0f39c0a9d7a8597f4b870",
            # 1.0.11 (t6/close-auth CLOSE-AUTH stages 2/3, substrate-1 GAP-0727): SEC-AWS-SECRET also matches
            # the spaced, dashed and quoted key spellings and an access-key id followed by its secret.
            "b8d2429990d76d73d9ff909ed8f7f9b848d0bef33fe887b0ce4d69f6690f7cb0",
        }
    ),
    "permissive": frozenset(
        {
            "06295d7fc02c0168fb93403a27f42b41127756d251a3d04c2c167db5dfca3f49",
            "09e49a34880ace6a9b29d613a8af16bd7f96063e7a6361897a77df475abd7859",
            "10191910ef94b2f3bb78ec9c70092c4c2ad5fd96077ab9b251fdea1178132f9f",
            "25a73df95116e71d06b8043f82df3e79e4bf943cb2e2e72529448e5ef91c009b",
            "29ce292e52f2fac289d6567ec7994b1f17af98e3fd1c4a5e2084f8c8a97b5371",
            "3ecdef60681cc5922962c48882de64b97f56605e22c6952bd49bb156ea445328",
            "45b3e39a75a57d6220b62c35bfa57ea3fcbd55ad0f8bdc97c20ac7523fc5a61a",
            "4fa0f0c4119e6aa67e8e4365d9b1f0b4b506749d5898c700d9d18ffbf98f9b2f",
            "60a9e2d62ecb7496464e2f93194dc128a3d61749071f106aec0235e643159eac",
            "69256416b4fcdcce3c9981d153242cc8a68fc659ed216767bc44e89052e2499c",
            "6dd147550abcb729f5bc59f4f7be5ff04ff4d40b57a45a7848a8139b8c35ffe9",
            "6ded828057977035dc763c35fc117ab2caf63ebc42bf79c70b2eb78d3c44a228",
            "7be65bc5f810de910c07ed0cc955606d0c49fecc9644b438f043ec0eddba3883",
            "8487451e43767a1f0136da3a8b346e143ad9e33ec864f74c49381eff64155aec",
            "9006dc19c958f8b2fa5fe7aba6d54e2fb8454f634b3fc6b6abf777c15a9e6604",
            "a1291dd16dbd6350daa6b94425bcfa19e734d99e1962e38e64915573d64f27c2",
            "a8c864dc71a7201897b4bfe5770187dedaae939ed51d8923ca6b2367b3501d79",
            "b0ade92e8990e321af88bc657a198b2ab49c06c420d66c0908cb5e8aa2e9b3f1",
            "b890f74b17262c155256632e92d5b7545c39c5a02ddbbde88f9421ee5a15e91b",
            "ba3c328ac60c00cd249228cc36cb0cc2bec6ae5141b302b5ca9fc89c6ac0914e",
            "d584ee82e7f786c1b434e9504091f654d24d98c7750598f8af3647c3b7a7fc34",
            "daa1b33a274a3c9f286ed5e9dc94a7081058c9a88832892afc7bec90e296f052",
            "db652db02c4570c3a630a61c4239746134e1125430af4d1f119aa5564207944e",
            "dd435b76cb1905e89cd6cd4b97cec7f48e19576b837d4b2d0fb693f114cc17f5",
            "e091aa508431e9ad0adcf04a9a17cf38ab7957019f5df58d8d5f2e23b0e3fc6b",
            "f029522590e2eee1735242ac58171bd7162b8814225833c311b39be4f8150ab5",
            "f1e4fd9a0be9cfac47f5eb47f3086378cd6f9d8f82bfd462ea75296c99d0d913",
            "f8addded6944af03eaad33d26f34f700a7ceda919697ac3f76528331aa4d4a77",
            "fa8ca0ad415436e8b4f5d6043f36de782cfe27bfbfca83f27d2359b97914f5f7",
            # 1.0.10 (rel/1.0.10, e681992abf): tool-injection judge answer template shows "none".
            "a23660e6371f3b640001b0437a039fdbbf78a2f07998c17dd7a49d1c60621030",
            # 1.0.10 (s7/shellrecall): five alert-only effect rules
            # (staged file, stdin password, download-run, git, inline code).
            "9a79a431a425ee9a61e856af9bccfe840d0dbc1cd14757d7ba352eee704c671a",
            # 1.0.10 (s7/pii-email merged with rel/1.0.10 and s7/cascade): adds the two email PII rules.
            "2bac0a30348b309bc44a85d9c05c5917a0c8738d43d0efb9ce027bbed653b1f5",
            # 1.0.10 (s7/promptfloor + s7/pii-email, GAP-0175/GAP-0172): prompt-injection floor
            # and the two email PII rules.
            "7ff6d705d7fa27e88f79060c0172119e17d4b19206ea44f0e84e79616e1cb8e5",
            # 1.0.10 (s7/secret-recall): SEC-SECRET-ASSIGN, a generic credential-assignment rule.
            "a35b1f3babbf06082de85953c1b6f7743233cff459a7ec19dbbf6c64181c5177",
            # 1.0.10 (s7/ad-pack): credentialed NetExec folded into credential.directory_ticket_request.
            "976c0343636d8163f496e37746aa26c57f5495c906a5cd7142fda001d78bdeb0",
            # 1.0.10 (rel/1.0.10 INT batch 4): s7/pii-email email rules plus s7/ad-pack NetExec fold.
            "969de899d5a8544152cd09ad05b1e67ac841a4da53c4bb1e992a3b55c796f7a1",
            # 1.0.10 (s7/promptfloor merged with rel/1.0.10 a5d59bf2b9): prompt-injection floor,
            # email PII rules and the NetExec fold.
            "ad735709469cd4d9906315c4c50d2ab8658494d3c170fb825e5d7f3052648b17",
            # 1.0.10 (s7/promptfloor-rel on rel/1.0.10 46ba344cbc): prompt-injection floor on INT
            # batch 10 and sed-suffix.
            "4568087775ef9d826573553399c7fa5f56f4107822cb8f3cbace301b45d71abe",
            # 1.0.10 (s7/secret-recall delta sr5, merged with rel/1.0.10): SEC-SECRET-ASSIGN reads = ( ) in a value.
            "33c8403eee2442fcde01f22d118261ac3e8ded4d6652875d335ffaef70d823bc",
            # 1.0.10 (s7/secret-recall delta sr6, merged with rel/1.0.10 a75abaec78): the profile with SEC-SECRET-ASSIGN
            # and the batch 9 shell recall rules.
            "2bc8b27f12facb6c1b1356c52801fc529a39f63110e4d8ac6742acc9c3e25b41",
            # 1.0.10 (s7/toolresult, rel-1-0-10 GAP-0171): contact tag on the email/phone rules; ENT-DL-CA and
            # ENT-BULK-SSN-NOHYPHEN carry their label in the pattern.
            "d86064891b13281853484ff4f038b6e2c7c88c6aa049437ad631675b6e77f828",
            # 1.0.10 (rel/1.0.10 INT batch 11): sysone, openclaw-msg, secret-recall, toolresult, nonshell,
            # psfloor, sender and response-fields packs.
            "b27db48e2e35664d39cdcf1bdd022de5b8a6514ed42088faf8de6e34fdeb9b1a",
            # 1.0.10 (rel/1.0.10 INT batch 11 delta 3): + g596 self-protection rules.
            "098589e5aad658e8e575589b3f3c0fbceeb50433f6d4935a05c77d3ffe7102bd",
            # 1.0.10 (rel/1.0.10 INT delta 4): + partjoin, browserjs, g594, parity P1 packs.
            "a942145df3e47c97fa0f7d4c26b2001bf65790ad0f699a159f301f8fb438a292",
            # 1.0.10 (s7/nonshell merged with rel/1.0.10 7f32dbb3a0): MCP and app tool rules, credential-store and
            # command rule ids.
            "2fc01f00e12d004a400b70939788dda568c097ba4ef895f5392735f698238142",
            # 1.0.10 (rel/1.0.10, s7/nonshell): MCP and app tool rules (toolshape), credential-store and command rule
            # ids.
            "e37c3a00b671321ae3e047606610d2fe08083a6282e8ed8778f2b1aac82959a4",
            # 1.0.10 (rel/1.0.10 INT batch 10): shellrecall effect rules plus nonshell toolshape rules.
            "6632604f57eb9a3d0618857cadeaa1ffa53b031115492e82799e917b7d21cc50",
            # 1.0.10 (s7/response-fields): SEC-BEARER-BARE and SEC-PASSWORD-ASSIGN (GAP-0371).
            "1e424c14053a75a0eb15df080839833433717195bd0bd7736ec35cddd4564524",
            # 1.0.10 (s7/response-fields merged with rel/1.0.10 a75abaec78): plus the s7/shellrecall effect rules.
            "d0744d25ec528674c66da161034c6bfe2478a54cde9167647fe80c3e86454d8b",
            # 1.0.10 (s7/gemma4-judge-rel): tool-injection judge context packet
            # (DEFENSECLAW CONTEXT) and two benign-case lines.
            "dbf9436a3f8c1d266ce0f5c0f664b72a1785e7a386988388832ff358d4f36423",
            # 1.0.10 (s7/gemma4-judge-rel merged with int/r110-b11d3 a35d0653ef): the judge context packet on
            # the delta 3 packs.
            "5fb55ba370269899e425e70e001d13a24178ec5b057c25e74b40793494fb798d",
            # 1.0.10 (s7/partjoin-pf-rel + int/r110-b11 1876efd336 + s7/partjoin-p3 02491003b4): prompt-injection floor,
            # joined-parts views and TRUST-AUTHORITY \s+ on the batch 11 packs.
            "e64d4b457fd45024db8743471bbffb20ac46a189d10355681d83a99a5db8fc46",
            # 1.0.10 (pjb11 x int/r110-b11d3 06b44c691f): the pf-rel + p3 packs with the delta-3 rules
            # (s7/response-fields SEC-BEARER-BARE, SEC-PASSWORD-ASSIGN).
            "cf8f3acd754c741ff4e6e19d512200be78728a58731f9859622b5941a84d9ede",
            # 1.0.10 (s7/partjoin-pf-rel 54d074e01f x int/r110-b11d3 664a7caa8c): the pjb11 packs with
            # the delta-3 g596 self-protection rules.
            "41971070bc6c01d5dedd83191c6a098b61125447a23d0d409ff5545cad5fc6ea",
            # 1.0.10 (s7/browserjs merged with int/r110-b11d3 a35d0653ef): PAGE-SCRIPT-SESSION-EGRESS (alert only).
            "4cd86a37760c2ae72de899e9b8df0080ba2bbd96b89dab0e735b11aa6e907c29",
            # 1.0.10 (s7/gemma4-judge-rel merged with int/r110-b11d4 033c5cbd2b): the judge context packet on
            # the delta 4 packs.
            "e0b99daa614eaa547fee67f0c87e805e8bffa208dd9b9bb82578756db58eba87",
            # 1.0.10 (s7/g1058fix on s7/td327fix7 a41329ba08): the td327 train on the delta 4 packs;
            # the typed path check of PATH-ETC-SHADOW is a Go rule of internal/toolshape (rel-1-0-10:GAP-1058).
            "ec4d531ac9c39d223b257ebb032fab8c62a945e528557622d7bd4cc460fd7089",
            # 1.0.10 (s7/g0210port-r2 on rel da4177e225, rel-1-0-10:GAP-0210, GAP-1267, GAP-1268): SEC-HF-TOKEN and
            # the SEC-PASSWORD-ASSIGN value class (backticks, next line, comma) in secrets.yaml.
            "185cf3ac23ddfdb95542daad3d62f3e165da9d62edfc08802497c722ea367a10",
            # 1.0.11 (t6/close-auth CLOSE-AUTH stages 2/3, substrate-1 GAP-0727): SEC-AWS-SECRET also matches
            # the spaced, dashed and quoted key spellings and an access-key id followed by its secret.
            "8d817b012e5e158bdcf6b95b5789e61f020729f58c673b0fbf4a0cd5c8c20171",
        }
    ),
    "strict": frozenset(
        {
            "1031aaa480cd71c5544f54acd59b25086f63c545867e2dc33b94bb692c09b209",
            "2720dce36378e7ef8cf3e196af5ef6e0c40777be43cc168e6e8d3b6b57728ca4",
            "3bff549d5860011cd63f0654455b6cc0d49e9493bd607284c12be6c764e10893",
            "409ec41d6070542d67370ab9fe469291263a097e69a44ff1b7fce4cea2edcc94",
            "4f9b68412f1cb102b54dad54a08c6e45d254e79984dccd84451cfdca62470e7f",
            "5b9b0f79c491c27b3feed63b90765091d37345621a95792ebcd34195abb097fd",
            "5ef5ff7ce9ff577fcf3a557b61b25b971be62d6ff1e45b8fd3b1771fac6a290b",
            "633786bfd3512fe1de7721c5c68beaff99245769c61df65b8720ea63729449bf",
            "6e83a82ef15257b0d184e3418dba66625bd3f15736193582779dc7be07719021",
            "75e46a0c8a460f001bd3783909ffb781d3e46450cffc0361e4bb6f8601031b3e",
            "9239bfef0d18ad54bbe55f955885d7a4391556f3d272223d347669f77f54b32b",
            "9308580254480e56c1b865592186226f3c83e72e01c65e6c6b4c8e414e4980ba",
            "9a718f87b06f75cfb1f4fa223fc6f3692ced3ecc17c10b5c8b96fff617d5da67",
            "9e8416be13a3a62f9e5a486570b6fce4673b86e2d834aa4d8891732bbaecea9c",
            "9f54aa385dffab92b7c08180ea2e37142d4fcf6ce3a53a29d9c0fc63374e0ff9",
            "a30346773809eb3571e1e44508e343cfc72ac70ed605b9837d0dcd663f2375e0",
            "b700765caa6ca379ad3a65456a467c586b0fc8cd7b846b827a90b6d1b97c04f8",
            "ba9afe634aff068a0d79ff219c4d9d8eb99cc32fd955ab6b8607bae3835f7623",
            "c31e5e90da9c3a6521c328adb9ac7883555d1acd7ad287cc43e5fa56237bfa35",
            "c78061e9d90d91005913add8b0c046b05ecf921648494e7b035b6a4bf37956c1",
            "c7b0103f24c84a775050494b6fff77bebe5f6404ec8a62097f8a6f97dc81b3ac",
            "ccc8bbf8312eaaec3b9203bfe84de27fe692cbf97834cd5d78119156741fd689",
            "db6ca1ece31914feab3234c49b469094e2c5997f09b37578eb981b17a30d9a10",
            "e21488344cfb0ca04d3cbe7c90f1101df2dd5bfcb0319af201655d3766289e6c",
            "e5b085aa79494d1b7b78279b9a301841cb8c4bbea76e1b3f4af2ff11dec2ed0d",
            "e9e7bde2dccb00dd7207ee1cf372ecd901bdac84bb0fea5098770af10de04206",
            "eabc629d3b25da4515c280ea0bb947686a891029dbf186328a947d7a6d91f7d0",
            "f5d6d19b78fe7d3897acb6a28a9fae08049fcda9745f944d5cdb45e573669bc5",
            # 1.0.10 (rel/1.0.10, e681992abf): tool-injection judge answer template shows "none".
            "6a5ac830ea0c6f7b2a7e5addefaf418711d5fc77a62bbd49d54700242197fbb2",
            # 1.0.10 (s7/shellrecall): five alert-only effect rules
            # (staged file, stdin password, download-run, git, inline code).
            "bdd27d5347627c74b8b90da944b7dca7de20d5488c6e36c50b28d5a9d73763fc",
            # 1.0.10 (s7/pii-email merged with rel/1.0.10 and s7/cascade): adds the two email PII rules.
            "7b2c63557d7a67123a73900b744524991200ec33cc3ef0090a13c75c8448fd44",
            # 1.0.10 (s7/promptfloor + s7/pii-email, GAP-0175/GAP-0172): prompt-injection floor
            # and the two email PII rules.
            "5db217d923f7cc8d20e1af9077f11478e568cba974add100cb5ed6fb5d5174b5",
            # 1.0.10 (s7/secret-recall): SEC-SECRET-ASSIGN, a generic credential-assignment rule.
            "18bef68d5e6cf60390d9f3925667fa2afa39d9d74b70ee5114c02de8b714c3ec",
            # 1.0.10 (s7/ad-pack): credentialed NetExec folded into credential.directory_ticket_request.
            "437f688e218aef5d3c5b47eb1591330401fecc157964c742f7570781f885a9b3",
            # 1.0.10 (rel/1.0.10 INT batch 4): s7/pii-email email rules plus s7/ad-pack NetExec fold.
            "f6ba060634b55b87887932700fbd73cd7d658f175f2bc83a75b057e45e8355aa",
            # 1.0.10 (s7/promptfloor merged with rel/1.0.10 a5d59bf2b9): prompt-injection floor,
            # email PII rules and the NetExec fold.
            "c200921e9d1c36b52fb305f1ec8bc5b9d693719999dac03a981c494f563b3065",
            # 1.0.10 (s7/promptfloor-rel on rel/1.0.10 46ba344cbc): prompt-injection floor on INT
            # batch 10 and sed-suffix.
            "ad4cbb03aea70a2ceb80c61f242ef06423e36a90d01d2c04d48091c2068827aa",
            # 1.0.10 (s7/secret-recall delta sr5, merged with rel/1.0.10): SEC-SECRET-ASSIGN reads = ( ) in a value.
            "5353b7ce79f3fc38085c93b43cae0075973d4f38f34a0ebd7bc11b065f870caa",
            # 1.0.10 (s7/secret-recall delta sr6, merged with rel/1.0.10 a75abaec78): the profile with SEC-SECRET-ASSIGN
            # and the batch 9 shell recall rules.
            "67d67ccace7e9cac5dfdf024d9492b92917af77ca6795bd5f194765ec95814b7",
            # 1.0.10 (s7/toolresult, rel-1-0-10 GAP-0171): contact tag on the email/phone rules; ENT-DL-CA and
            # ENT-BULK-SSN-NOHYPHEN carry their label in the pattern.
            "d907a3f35099a86d92ebbf062e92fdb3ee4eee38a7ff9b3b75be6f05a70fc12b",
            # 1.0.10 (rel/1.0.10 INT batch 11): sysone, openclaw-msg, secret-recall, toolresult, nonshell,
            # psfloor, sender and response-fields packs.
            "6f5ab18b2bbbbfe1c6852b58ac5c2b6949632f28620518d7f5c9ad157531876d",
            # 1.0.10 (rel/1.0.10 INT batch 11 delta 3): + g596 self-protection rules.
            "235f5925f206724402760fbd8aa969def4c3518e3b3c3d4d82e55d7d3426301b",
            # 1.0.10 (rel/1.0.10 INT delta 4): + partjoin, browserjs, g594, parity P1 packs.
            "3f108829faef7ed471046ddbc49c7af7be3bc4fdecb7a9b59f66f4ee1beddeb7",
            # 1.0.10 (s7/nonshell merged with rel/1.0.10 7f32dbb3a0): MCP and app tool rules, credential-store and
            # command rule ids.
            "80a72f2d44b59278db1dec7d86ec2c26709638f4f56de6948de7f4040b5802d6",
            # 1.0.10 (rel/1.0.10, s7/nonshell): MCP and app tool rules (toolshape), credential-store and command rule
            # ids.
            "d7e4600212678a341448694e23e271de3dce897e0897dde4d7eaf9f4a12f8e23",
            # 1.0.10 (rel/1.0.10 INT batch 10): shellrecall effect rules plus nonshell toolshape rules.
            "b70be45b7d2384a6b05eeb85893ad80926d19207e7a6896390e16aadb06a551b",
            # 1.0.10 (s7/response-fields): SEC-BEARER-BARE and SEC-PASSWORD-ASSIGN (GAP-0371).
            "23259c8008f836ee1e60f5dd9ebe86050736da685dc76e8bf4fdcbd56ab53f0f",
            # 1.0.10 (s7/response-fields merged with rel/1.0.10 a75abaec78): plus the s7/shellrecall effect rules.
            "b956db73b9de22f9b3d9b107754c458bf4c042d7d109ae4baeb32803f9f378d7",
            # 1.0.10 (s7/gemma4-judge-rel): tool-injection judge context packet
            # (DEFENSECLAW CONTEXT) and two benign-case lines.
            "eafe7ba6873ae3beb10f1b209b90fa47b9e282fede74af77a10a3079fc188de1",
            # 1.0.10 (s7/gemma4-judge-rel merged with int/r110-b11d3 a35d0653ef): the judge context packet on
            # the delta 3 packs.
            "d232c2e79edde44565ff1a51b1f9f691ab1e26a1ac7b9c71566983d910c39465",
            # 1.0.10 (s7/partjoin-pf-rel + int/r110-b11 1876efd336 + s7/partjoin-p3 02491003b4): prompt-injection floor,
            # joined-parts views and TRUST-AUTHORITY \s+ on the batch 11 packs.
            "720da98b000e4294cbb96e0d8902e4a21b780fd54edbb243d939d5c7c4eec1b5",
            # 1.0.10 (pjb11 x int/r110-b11d3 06b44c691f): the pf-rel + p3 packs with the delta-3 rules
            # (s7/response-fields SEC-BEARER-BARE, SEC-PASSWORD-ASSIGN).
            "1c0c3c7775ea27fcdf9bff305e7ededfa62f3e045fd4eea2efa64860ea9434ee",
            # 1.0.10 (s7/partjoin-pf-rel 54d074e01f x int/r110-b11d3 664a7caa8c): the pjb11 packs with
            # the delta-3 g596 self-protection rules.
            "b8448b37aaa68a8fe573804ed2ce53cc0bb6c7e25e6c47c9096af26b14899ce1",
            # 1.0.10 (s7/browserjs merged with int/r110-b11d3 a35d0653ef): PAGE-SCRIPT-SESSION-EGRESS (alert only).
            "3c02f7c449076e385af4548ec6019d7ca821847b888a432a254be88bab3796fe",
            # 1.0.10 (s7/gemma4-judge-rel merged with int/r110-b11d4 033c5cbd2b): the judge context packet on
            # the delta 4 packs.
            "2237afe661765bf883ec757d5195149b15171872ffbef9b1b134195c02f4c189",
            # 1.0.10 (s7/g1058fix on s7/td327fix7 a41329ba08): the td327 train on the delta 4 packs
            # (b1d66c243c: a copy of a credential file is a read of it).
            "2f4db7a9e2296cac025499b7785766eec2f82d4d75c2cb78873b542b8292a18d",
            # 1.0.10 (s7/g0210port-r2 on rel da4177e225, rel-1-0-10:GAP-0210, GAP-1267, GAP-1268): SEC-HF-TOKEN and
            # the SEC-PASSWORD-ASSIGN value class (backticks, next line, comma) in secrets.yaml.
            "51cc060958667eaea175b46c6ce542175e0af2667646ffe69b56b9a917218670",
            # 1.0.11 (t6/close-auth CLOSE-AUTH stages 2/3, substrate-1 GAP-0727): SEC-AWS-SECRET also matches
            # the spaced, dashed and quoted key spellings and an access-key id followed by its secret.
            "43d89f5201e1a168203fd8fe26003217684f9d6a81a237b91392c428ab802288",
        }
    ),
}


@dataclass
class ProfileRefreshResult:
    refreshed: list[str] = field(default_factory=list)
    kept_modified: list[str] = field(default_factory=list)
    backup_dir: str = ""
    errors: list[str] = field(default_factory=list)
    # The digest each refreshed profile had right after the swap, so an undo
    # puts a profile back only while it is still exactly that copy.
    refreshed_digests: dict[str, str] = field(default_factory=dict)


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


def unedited_profiles(policy_dir: str) -> list[str]:
    """The seeded profiles in ``policy_dir`` whose files are exactly those some release shipped."""

    dest_root = Path(policy_dir) / "guardrail" if policy_dir else None
    if dest_root is None or not dest_root.is_dir():
        return []
    names = []
    for dst in sorted(dest_root.iterdir()):
        if dst.is_symlink() or not dst.is_dir() or dst.name.startswith("."):
            continue
        try:
            if profile_digest(dst) in STOCK_PROFILE_DIGESTS.get(dst.name, frozenset()):
                names.append(dst.name)
        except OSError:
            continue
    return names


def restore_unedited_profiles(
    policy_dir: str, backups_root: str, target_profiles: str | Path, result: ProfileRefreshResult | None = None
) -> ProfileRefreshResult:
    """Put a release's own profiles in place of the unedited seeded ones (GAP-1077).

    A downgrade runs the older release's migrate, which keeps every profile
    whose digest it does not know, and it does not know the digests of this
    release. ``target_profiles`` is the older release's ``policies/guardrail``;
    a profile the user edited is left as it is. A caller that passes ``result``
    keeps what was swapped so far even when this is interrupted, to undo it.
    """

    return refresh_stock_profiles(policy_dir, backups_root, bundled=Path(target_profiles), result=result)


def undo_profile_refresh(policy_dir: str, result: ProfileRefreshResult) -> tuple[list[str], list[str]]:
    """Put back the profiles a refresh replaced, from its backup (GAP-1081).

    Used when the downgrade that asked for the swap did not happen. A profile
    changed since the swap is left alone. Returns the profiles put back and
    the problems met.
    """

    restored: list[str] = []
    problems: list[str] = []
    dest_root = Path(policy_dir) / "guardrail"
    for name in result.refreshed:
        backup = Path(result.backup_dir) / name
        dst = dest_root / name
        staged = dst.with_name(f".{name}.undo")
        try:
            if not backup.is_dir():
                problems.append(f"{name}: its backup is gone")
                continue
            if result.refreshed_digests.get(name) != profile_digest(dst):
                problems.append(f"{name}: changed since the swap, left as it is")
                continue
            shutil.rmtree(staged, ignore_errors=True)
            shutil.move(str(dst), str(staged))
            try:
                shutil.move(str(backup), str(dst))
            except OSError:
                shutil.move(str(staged), str(dst))
                raise
            shutil.rmtree(staged, ignore_errors=True)
            restored.append(name)
        except OSError as exc:
            problems.append(f"{name}: {exc}")
    try:
        os.rmdir(result.backup_dir)  # only when every backup left it
    except OSError:
        pass
    return restored, problems


def refresh_stock_profiles(
    policy_dir: str, backups_root: str, bundled: Path | None = None, result: ProfileRefreshResult | None = None
) -> ProfileRefreshResult:
    """Replace unedited seeded profiles that differ from ``bundled`` (this release's by default)."""

    from defenseclaw.paths import bundled_guardrail_profiles_dir

    if result is None:
        result = ProfileRefreshResult()
    if bundled is None:
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
            result.refreshed_digests[profile.name] = profile_digest(dst)
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
