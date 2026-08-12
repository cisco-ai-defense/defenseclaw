# s-gw vendored source

`upstream/` is an exact, byte-for-byte mirror of the runtime source selection
from the public s-gw Git tree pinned in `release/s-gw-module.json`. The explicit
selection omits most upstream tests, CI, artwork, and native desktop UI while
retaining the reviewed test inputs needed by the module build. It also contains
no private execution-core checkout or compiled proprietary runner.

Verify the mirror before review or packaging:

```shell
python3 scripts/sync_sgw_vendor.py verify
```

To refresh it, first update the pinned revision, tree and package version in
`release/s-gw-module.json`, then run:

```shell
python3 scripts/sync_sgw_vendor.py sync --source /clean/path/to/s-gw
```

The source checkout must be clean and exactly at the pinned commit. The sync
command replaces only `third_party/s-gw/upstream/` and regenerates
`SOURCE_MANIFEST.json` from Git objects. Every selected file records its Git
blob object ID as well as SHA-256, size, and mode; offline verification
recomputes both content identities. Review the upstream diff and all license
changes before committing the result.

DefenseClaw-specific changes belong in a visible patch queue under `patches/`
until the same change is accepted in the standalone s-gw repository. Never
edit `upstream/` directly.

The upstream mirror pins the cross-platform credential-store, lifecycle
parity, independent Windows helper lifetime work, and macOS Keychain alert-noise
hardening through standalone commit `9cbe37e`, plus the Linux Preview support
documentation correction at `a9ffa79`.
The current patch queue advances the integrated module to 0.2.0, replaces the
standalone Linux Secret Service CLI with the packaged helper contract, and
keeps restricted setup help side-effect
free. Raw proxy tokenization, pending-enrollment
ciphertext, the approval console, and approval mutations are deliberately
absent from the TypeScript runtime; the signed native runner owns those
surfaces. The DefenseClaw native gateway performs platform-specific runner
admission before opening the console or sending proxy segments. The upstream
package version remains 0.1.19; the exact unreleased revision is recorded in
`release/s-gw-module.json`.

Production packages require an approved execution runner, OS credential-store
helper, built approval UI, and target-specific third-party license bundle for
every supported target. The non-empty `THIRD_PARTY_LICENSES.txt` bundle must be
generated from the exact locked dependencies used by the runner, helper, and
UI. It records their versions and sources and includes every required license,
copyright, and notice text. Each artifact and the complete installed module
inventory are pinned by Ed25519 signatures in `release/s-gw-runners.json`. The
native runner contract admits exactly the
DefenseClaw tokenizer MCP tool and owns the authenticated approval session,
browser handoff, and user-presence mutations. The signed approval UI must
declare both `defenseclaw.pending-enrollment.v1` and
`defenseclaw.approval-console-session.v1`; it is static content served by that
runner, not an authority on its own.

The runner launch admission is also signed. Linux uses a sealed executable
snapshot, Windows holds the admitted image against write/delete replacement,
and macOS verifies the exact running code identity and CDHash. The runner must
serve the already-verified UI snapshot and use a native OS browser API or an
absolute system-owned launcher. Node.js never launches the runner or hosts the
approval surface.

The manifest is deliberately fail-closed while redistribution approval and
those signed artifacts are absent. An explicit `--allow-incomplete-components`
build produces a source-only archive with `production_ready: false`; it is not
installable as the production broker.

## Prepare an offline signing request

Signing enrollment is intentionally separate from production packaging. Create
an untracked candidate JSON file with the target, its launch admission, and the
reviewed SHA-256 and path for each candidate component. A Linux request has this
shape:

```json
{
  "schema_version": 1,
  "target": "linux-x64",
  "runner_launch_admission": {
    "schema_version": 1,
    "mode": "linux-sealed-memfd-v1",
    "signature_scope": "installed-runner-bytes",
    "dependency_policy": "system-only-v1"
  },
  "components": {
    "runner": {"path": "/reviewed/s-gw-core", "sha256": "<64 lowercase hex>"},
    "credential_helper": {"path": "/reviewed/s-gw-secret-service-helper", "sha256": "<64 lowercase hex>"},
    "approval_ui": {"path": "/reviewed/s-gw-console-ui.tar.gz", "sha256": "<64 lowercase hex>"},
    "license_bundle": {"path": "/reviewed/THIRD_PARTY_LICENSES.txt", "sha256": "<64 lowercase hex>"}
  }
}
```

Use the exact Node.js and npm versions pinned by `build_toolchain` in
`release/s-gw-module.json`, then run:

```shell
.venv/bin/python scripts/build_sgw_module.py \
  --prepare-signing \
  --target linux-x64 \
  --candidate-components /untracked/linux-x64-candidates.json \
  --output-dir /untracked/signing-output
```

The command snapshots the candidate files, builds the patched module twice,
and refuses non-reproducible inventories. It emits a deterministic unsigned
inspection archive plus a bounded JSON request containing the canonical
component, runner-contract, launch-admission, and whole-module signing
payloads. It does not mark a runtime approved, stage a production module,
write a signature, or modify either tracked release manifest. Production
checks still require all final signatures, the canonical public key and
fingerprint, and the byte-matching public key compiled into the Go gateway.

Protected releases build all six target modules, stage them under the wheel's
`defenseclaw/_data/sgw/modules/` resources, and verify every archive and
checksum before the release candidate is sealed. Build-source paths in the
private component manifest are replaced with `null` in the public wheel.

`defenseclaw-module.json` inventories every regular package file except itself.
The installer verifies that exact inventory from the authenticated archive,
then adds the metadata file's actual digest to the private receipt. Runtime
status requires the receipt to match every installed file, including imported
`dist` chunks, `node_modules`, helpers, runner, UI assets, the signed license
bundle, and the metadata file.
The release build pins Node.js 24.18.1 and npm 11.16.0 and removes npm's mutable
`node_modules/.package-lock.json` before inventorying runtime files.
