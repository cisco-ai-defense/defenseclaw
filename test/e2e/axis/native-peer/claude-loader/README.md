# Fixed shared musl loader input

This build-only recipe produces a loader for a future, separately admitted Linux
Claude Code 2.1.292 `--version` canary in the existing native peer harness. It
executes neither the loader nor Claude, a sandbox, or an installer. No runtime
or production capability is admitted by these files.

The official signed `linux-x64-musl` image inspected in run 39189744507 is
245,203,032 bytes, SHA256
`d23f28ef84f5459a25d2d4cf999a7debd41df83507160446983d4ca65554e50f`.
It requests `/lib/ld-musl-x86_64.so.1` and declares one dependency,
`libc.musl-x86_64.so.1`. Both guest paths can name separately held, read-only
mounts of the same reviewed shared-musl bytes. No host library directory is
granted. Its imported `dlopen`/`dlsym` do not establish the full agent's runtime
dependency closure; a successful future canary would prove only exact version
output and bounded owned cleanup under the unchanged offline filter.

The recipe reuses the existing musl 1.2.6 official archive/license pins and
bounded source extractor. `compiler-inputs.json` is byte-equal to the selected
compiler/startup/link inventory independently reviewed in the c914 peer artifact.
Every selected input must still match those exact bytes, then its exact Ubuntu
package payload is checked before compilation. Missing or changed tooling
refuses; there is no implicit installation or compiler alternative.

Two fresh build roots compile only musl's `lib/libc.so`, with fixed source date,
mapped build paths and an empty build ID. There is no `make install`. The two
outputs must be byte-identical, ELF64 x86-64 shared objects with a file-backed
executable entry, no interpreter, additional `DT_NEEDED`, search path, or writable
executable segment. Link maps, compiler/package evidence, official archive,
license, source bytes and command diagnostics are retained for independent review.

The disposable runner and its shell/runtime are trusted build inputs. Compiler
dynamic libraries and LTO plugins are outside the selected-input verification;
this is not a fully hermetic compiler bootstrap. A separately reviewed artifact
digest must be fixed in the canary receipt before any native execution.
