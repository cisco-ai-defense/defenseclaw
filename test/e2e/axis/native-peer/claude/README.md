# Fixed official Linux Claude inspection

This manual workflow inspects the official Claude Code **2.1.292** Linux x64
and Linux x64 musl distributions as data. It never runs the installer, either
vendor binary, a loader, `ldd`, package scripts, or a sandbox. It installs no
tools. The disposable Ubuntu runner must already provide Python 3, GPG and GNU
readelf; missing or incompatible inputs cause refusal. This is an inspection
recipe whose first CI run refused during the first public metadata fetch before
downloading any release data. An independent HTTP check found the old install
URL returned a 302 to the corrected recipe's pinned official destination,
`https://downloads.claude.ai/claude-code-releases/bootstrap.sh`, as text only;
redirects remain refused. The corrected acquisition result is pending.
The canonical branch's own-workflow push trigger registers the workflow; the
entire inspection job is guarded by `workflow_dispatch`, so registration pushes
skip every download and inspection step. Registration and an accepted manual
dispatch still require separate observed GitHub API results.

The [official setup documentation](https://code.claude.com/docs/en/setup#binary-integrity-and-code-signing)
publishes the release manifest location, detached signature, checksum field and
primary key fingerprint `31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE`. This independently
pinned fingerprint is the trust anchor. A new private GPG home checks the key,
imports only that key, and requires one valid manifest signature with that
primary fingerprint and a SHA-256/384/512 digest. An expired, revoked, unknown or
failed signature refuses acquisition of the binary. Manifest JSON duplicate
keys and a different version are refused. Only each fixed platform's
`platforms.<platform>.checksum` and optional size are read; manifest URLs or
commands never select a download or process.
GPG automatic key retrieval/import, dirmngr use and implicit helper-daemon
startup are explicitly disabled; verification cannot start an agent or keyserver
helper as a side effect.

All download URLs are fixed in reviewed source. HTTPS certificate validation
remains enabled, proxies and every redirect are refused, and unexpected origin
or release layout requires another source review. The installer is retained as
text only, at most 128 KiB. The manifest is at most 1 MiB; signature, public key
and release repository license notice are each at most 128 KiB. Each binary is
streamed to a private non-executable regular file, at most 512 MiB, and its SHA256
must match the signed manifest before inspection. Linux x64 must be published;
musl is inspected in the same run when present, otherwise its absence is
explicit. There is no alternate version, platform, bucket or install fallback.
Each connection has a 15-second socket timeout and each streamed request a
180-second checked deadline; a blocked read can finish after that deadline by
one socket timeout. The entire job is limited to 15 minutes.

Only the installed `/usr/bin/gpg` and `/usr/bin/readelf` run against acquired
data. Literal argv, an empty credential environment, closed stdin, a 30-second
tool deadline, effective aggregate 8 MiB pipe capture limits, and kill/wait on
failure bound those readers. Tool executable SHA256, resolved path and version
are retained. This trusts the disposable runner's installed reader tools and
their runtime libraries; it does not attest a hermetic toolchain.

The report records ELF class, architecture, type, entry and PT_INTERP, readelf's
program/dynamic tables, symbol versions and notes, DT_NEEDED, RPATH/RUNPATH and
visible dlopen/dlsym imports. Tool text is untrusted metadata, never shell or
launch input. These facts cannot prove all runtime dlopen dependencies,
filesystem probes or syscalls, or compatibility with the offline AXIS filter.
The [license notice at the official release tag's commit](https://github.com/anthropics/claude-code/blob/fbe20e00e2851fc01506f54f98a8f0b875af3847/LICENSE.md)
is retained as publisher licensing evidence. It is not an inventory or legal
clearance of all embedded third-party components.

The uploaded artifact contains only the four exact committed recipe sources,
public installer text, manifest/signature/key/license evidence, bounded reader
text and JSON reports. A fixed member allowlist and 20 MiB total limit exclude
both vendor binaries and the GPG home; the private directory is outside the
upload path. Failure evidence remains available. Known download gates have fixed
reason codes; arbitrary exception text and private runner paths are omitted. No provider credentials are
passed to a reader process. Runtime admission and production certification
remain false on success as well as failure. A future fixed `--version` canary
needs separately reviewed held images and any interpreter/library objects,
native policy translation, exact output, native wait and whole-wrapper cleanup;
the earlier static Go payload cases do not qualify this binary.
The result's failure projection contains only a fixed inspection stage, closed
category and bounded numeric OS/HTTP codes; exception messages are omitted.

Local validation runs only `python -m unittest discover -s
test/e2e/axis/native-peer/claude -p test_inspect_artifact.py -v`, Ruff and actionlint.
Its synthetic tests never invoke network or an external reader. Source review
by ROOT and the independent reviewer must precede a coordinated manual workflow
dispatch; this source addition does not authorize a native workload run.
