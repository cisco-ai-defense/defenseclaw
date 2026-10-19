<!-- Copyright 2026 Cisco Systems, Inc. and its affiliates -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Fixed read-only profile query observations

One reviewed query02 invocation ran outside PSEC. The helper accepted its exact
eight private environment values and found no thread token. Its fixed
`SHGetKnownFolderPath` query returned `0x00000000`; the fixed unregistered
synthetic AppContainer SID query returned `0x80070002`. It stopped at
`synthetic_native_folder_query_refused`, with all path classes null. No alternate
SID, profile creation, registry/ACL mutation or retry was attempted.

The outer receipt records 2.926 seconds, exit 1, no deadline, capture overflow,
stream-read or pin-close error. The helper's explicit profile-creation and
filesystem-write call flags are false; these describe its source API surface,
not instrumentation of every OS-internal side effect. The supervisor used the
existing `processutil.RunTree` owned Job. It makes no complete-tree or Job-empty
qualification claim. The synthetic fixture and bounded receipts were retained.

| Retained input or observation | SHA256 |
| --- | --- |
| Query helper | `0e5123f5f20d992b36f07ce8a6670675996e1d333e37bf07ea5668e9cae8d24e` |
| Query supervisor | `b12b05233e89f00980953b81d5b0b936e611ff3ec583d1035fbb513aeebcb564` |
| Actual outer query02 result | `e470d41ac2cf782c09131bdfd3258ec76f63cc2e2508ff58b4017e838e81f5fe` |

This control cannot explain the Case10 caller-base mismatch or provide the failed
contained child's native SID authority. It does not reproduce the Rust parent's
startup DLL loading followed by environment mutation. No mapping assertion was
changed based on this refusal. Raw paths, environment values and native profile
components are absent from this public record.
