<!-- Copyright 2026 Cisco Systems, Inc. and its affiliates -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Inert native peer artifact review

`verify_native_artifact.py` reviews build evidence as data. It never executes the
peer, Bubblewrap, a payload, a compiler or an archive tool. Its receipt does not
enable a customer provider or populate the manual harness's reviewed registry.
The trusted host tools are Git and authenticated GitHub CLI metadata queries;
their code and the review machine remain trusted. No artifact-supplied program
or executable path is invoked.

Provide independently reviewed source, run, attempt, artifact, ZIP and
provenance pins. The verifier requires a successful same-repository Actions run
of the exact workflow and head, an explicit admitted branch/event, GitHub's ZIP
digest and a caller-supplied provenance digest. Missing or unknown evidence
refuses. It checks:

- Exact ZIP member inventory and every manifest hash/size, including the
  separately uploaded root lock and workflow identity record.
- All committed build-source Git bytes, upstream locks/licenses, the reviewed
  combined registry lock and every applied overlay's reconstructed file bytes.
- The exact 19 peer, six dependency and five inert C test inventories.
- Both identical static-musl images, their ELF structure, original source
  archives/licenses, static `dlopen` refusal and exact source/compiler/musl/
  libcap link inputs. Retained GCC runtime objects must match the recorded
  installed package payloads; UAPI headers must match `linux-libc-dev` bytes.
  ELF entry points must lie in executable file-backed load segments. Each
  package notice must match its exact archive-resolved copyright file;
  shared documentation links are resolved only in bounded archive metadata.

The fixed reviewed workflow's authenticated Ubuntu APT and rustup environment
remains a build trust assumption. The verifier independently compares retained
package archives, payload bytes and recorded inputs, but does not independently
verify Ubuntu repository signatures or bootstrap the compiler. It does not
verify compiler shared libraries or the dynamically loaded LTO linker plugin.
Those bytes remain part of the trusted runner environment. It does not
establish namespace, filesystem, process cleanup, PTY, credential or model
traffic boundaries. Static headers alone are insufficient; the full evidence
is required, and the resulting receipt still states runtime admission false.

Readers enforce compressed/member/total byte bounds, normalized paths, member
counts, a shared 512MiB decoded budget across all nested source/package tars,
non-reparse file inputs, strict JSON keys and exact required regular
members. No archive paths are extracted. Debian gzip/xz payloads use stdlib
codecs; zstd requires Python 3.14 `compression.zstd` with a bounded window.
Older Python without that module refuses zstd, without a helper-tool fallback.
Unsupported archive metadata or compression also refuses.

The first successful revised-mount build, `b622d925`, does not retain one
intermediate shared-documentation link owner's archive. The stricter verifier
refuses it; its earlier review receipts do not satisfy the current gate. The
build recipe now records every intermediate link and owning package. A new
successful artifact and independently reviewed pins are required. The
historical refusal can be reproduced with:

```powershell
python internal/axis/native/verify_native_artifact.py `
  --archive C:\path\to\artifact.zip `
  --archive-sha256 b399c3459dd2bee83a8d27eaa18d62af8f1d25ea05ecfd6a175057c9f8ad1156 `
  --provenance-sha256 7aeb0f552eabd6ae06a80813b21c68780032260f2a4eb8d9b1f62f6d346f1904 `
  --commit b622d925105efc53d78e3aa548f2bfd0057d626c `
  --run 39134040491 --attempt 1 --artifact 12139093266 `
  --repository C:\path\to\defenseclaw `
  --axis C:\path\to\axis-git `
  --mxc C:\path\to\mxc-git `
  --bubblewrap C:\path\to\bubblewrap-git `
  --staging C:\path\to\fresh-owned-peer-review
```

The three upstream Git object stores must contain their exact pinned commits;
no checkout, submodule or source execution is needed. The staging directory
must not exist. Successful review writes data copies at `images/peer` and
`images/bwrap-static-musl`, retained proofs, reconstruction evidence and
`PEER-REVIEW.json`. Failure after creating staging retains a failure record;
it never writes into an existing staging directory.

This is a peer-only receipt. A separately reviewed fixed payload artifact is
needed before combining the three images and proof files into the manual
harness's `REVIEWED-ARTIFACTS.json`. Only a later explicitly reviewed source
registry entry can admit that exact receipt. Neither a CLI hash nor this
verifier's `verified` field grants execution authority.

Pure tests (no metadata tools, artifacts or runtime images execute):

```powershell
cd internal/axis/native
python -m unittest -v test_artifact_archive test_verify_native_artifact
```
