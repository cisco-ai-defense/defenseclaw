# Signing and trust channels (standalone profile)

Every standalone deployment trusts its payload through exactly one channel.
The artifact and the options you install it with choose the channel:

- **Windows Setup**: the unsigned Setup (flavor `standalone-unsigned`) always
  installs with `hash_pinned` trust, anchored in the manifest embedded in
  the Setup. An Authenticode-signed Setup (flavor `standalone`) installs
  with `authenticode` trust; `ALLOWEDSIGNERS=` pins its signers. The
  enterprise marker's `TrustMode` value records the trust mode the
  deployment was installed with. A later `ensure` by the installed CLI (for
  example the Intune Remediations script) keeps it, so a hash-pinned
  deployment stays `hash_pinned`.
- **Windows CLI** (`defenseclaw.exe enterprise windows ...` from an extracted
  payload): `--trust-mode authenticode` is the default; `--trust-mode
  hash_pinned` needs `--payload-manifest`, and `--allowed-signer` pins
  signers.
- **Wrappers** (`packaging/mdm`): `-TrustMode` / `--trust-mode` decides how
  the wrapper verifies the artifact before installing it. Hash-pinned is
  the default.

On Windows the config keys `enterprise.trust.mode` and
`enterprise.trust.allowed_signers` narrow what the standalone lifecycle
accepts: `authenticode` refuses a hash-pinned run and any run over a
hash-pinned deployment (exit `1639`); `hash_pinned` or an unset mode admits
both; `allowed_signers` pins signers like `--allowed-signer`. Linux and macOS
accept and validate the keys but do not use them. The lifecycle re-verifies
every installed file on `verify` and `ensure`.

| Channel | Windows | Linux | macOS | Pin |
| --- | --- | --- | --- | --- |
| **Hash-pinned** (default for the wrappers; works unsigned) | `DefenseClawSetup-Enterprise-Standalone-x64.exe` (flavor `standalone-unsigned`). Setup records the SHA-256 of each inner file from its embedded manifest as the lifecycle's `hash_pinned` anchor. | deb / rpm / payload `.tar.gz` | pkg / payload `.tar.gz` | The artifact's SHA-256, taken from the release's cosign-verified `checksums.txt`, passed to the wrapper as `-Sha256` / `--sha256` |
| **Cisco release signing** (optional release job) | Authenticode on the seven inner files and the outer Setup (flavor `standalone`) | GPG detached `.asc` per release file, and `defenseclaw-enterprise-release-key.asc` | Developer ID Application (binaries) + Developer ID Installer (pkg) + notarization | Windows: signer certificate SHA-256 (`-AllowedSigners` / `ALLOWEDSIGNERS=`); Linux: the public key in a root-owned keyring; macOS: Team ID (`--allowed-team-id`) |
| **Customer re-signing** | Sign the inner files with your certificate, then `packaging/windows/standalone/build-setup.sh --payload-dir <signed>`, or `--sign-command packaging/mdm/signing/authenticode-sign.sh` | Re-sign the packages with your key | Re-sign the pkg with your Developer ID | Your certificate's SHA-256 thumbprint, key or Team ID |

The release job signs only when its signing secrets are configured; otherwise
it ships the unsigned artifacts, which the hash-pinned channel covers. The
cosign-signed `checksums.txt` is produced for every release, whichever
channel you use.

On Linux, `gpgv` reads only binary keyrings. Convert the release key once
and deploy the result as a root-owned file:

```sh
gpg --dearmor < defenseclaw-enterprise-release-key.asc > defenseclaw-enterprise-release-key.gpg
```

On macOS, signed trust applies only to the `.pkg`: the wrapper checks the
Developer ID Installer signature, the Team ID and Gatekeeper's notarization
verdict. Use hash-pinned trust for a payload archive.

## Windows: `authenticode-sign.sh`

```sh
export AUTHENTICODE_PFX=/secure/codesign.pfx AUTHENTICODE_PFX_PASSWORD=...
packaging/windows/standalone/build-setup.sh --version 1.4.0 \
  --sign-command packaging/mdm/signing/authenticode-sign.sh
```

The helper:

- signs PE files and PowerShell scripts in place with osslsigncode 2.5 or
  later, SHA-256, with an RFC 3161 timestamp;
- verifies the result;
- prints `signer_sha256=<thumbprint>`.

The thumbprint is the SHA-256 of the DER signer certificate, the value to
pin. It matches what Windows computes from `SignerCertificate.RawData`, and
that match was checked with a test CA during development. Set
`AUTHENTICODE_EXPECTED_SHA256` to refuse any other certificate.

The helper never takes secrets on the command line. The PFX password
travels through a temporary file inside a `0700` temporary directory.

## Why the Secure Client kit is not parameterized here

The Secure Client signing pipeline's build kit (`packaging/scripts/*.sh`,
`packaging/scripts/lib/*`) is pinned by the Secure Client release gate,
because it ships production Secure Client builds. Its fixed `Cisco Systems, Inc.` signer assertion
therefore stays as it is.

Configurable signer pinning lives in the standalone path instead:

- Setup's `ALLOWEDSIGNERS=`;
- `defenseclaw.exe enterprise windows ... --allowed-signer`;
- the MDM wrappers' `-AllowedSigners`.
