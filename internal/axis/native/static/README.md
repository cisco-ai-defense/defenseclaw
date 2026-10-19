<!-- Copyright 2026 Cisco Systems, Inc. and its affiliates -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Static-musl Bubblewrap build-only closure

This is a reviewed-source candidate recipe, not an admitted runtime. The private
peer build workflow explicitly selects `prepare_build.py locked --static-musl`
(or discovery before a lock is committed). It also retains the existing dynamic
C compile check. Neither Bubblewrap output, the peer nor a contained workload
is executed. The static recipe executes libcap's fixed `_makenames` build tool;
the parent build also executes the separately described inert C unit entry
point, which never calls Bubblewrap's main or namespace/mount/workload setup.
Unit gates execute fake/inert tests only.

`sources.json` records exact official sources and SHA256 values. Inert local
review matched every musl archive file to all 2660 blobs at the pinned commit;
all 312 libcap archive files matched its pinned commit, with only `.gitignore`
omitted. No archive supplied extra source files or special entries. The libcap
archive SHA also matches the official
[kernel.org checksum manifest](https://www.kernel.org/pub/linux/libs/security/linux-privs/libcap2/sha256sums.asc).
The exact musl `COPYRIGHT`, libcap `License` and Bubblewrap `COPYING` must be
retained with the artifact. Select libcap's BSD-3-Clause alternative explicitly.

The official musl release signature verifies against its published key
`836489290BB6B70F99FFDA0556BCDB593020450F`, fetched from
`https://musl.libc.org/musl.pub`. That release signature uses SHA1; it is
supplementary evidence, not the artifact admission hash. Mandatory SHA256 pins
and exact Git-tree byte comparisons are retained separately.

The static [musl source](https://git.musl-libc.org/cgit/musl/tree/src/ldso/dlopen.c?id=9fa28ece75d8a2191de7c5bb53bed224c5947417)
provides a `dlopen` stub that refuses dynamic loading. The static-libc object
must be source-built from this pin, rather than relying on an ELF header check
or an unidentified system `libc.a`. libcap sources in this pin contain no
`dlopen`/`dlsym`/passwd lookup calls. Bubblewrap's four linked C files do not call
passwd/group/host lookup functions. Link input inventories must confirm the
actual closure; these source observations alone do not qualify execution.

The candidate build uses only a disposable Ubuntu24.04 x86_64 runner. It stages
all files below an owned build directory and performs no global install,
service/capability/ACL setup, namespace setup or sandbox execution. The compiler
and binutils come from that runner's authenticated Ubuntu packages. Before any
runtime use, the receipt must retain their package/version/architecture,
repository archive SHA256 and exact installed-file hashes. This is compiler
provenance, not a claim to have bootstrapped GCC from source.

This is not a fully hermetic build. The fixed configure/Makefile commands also
use the disposable runner's shell and ordinary coreutils. Compiler/binutils
shared libraries and GCC's dynamically loaded LTO linker plugin are also not
independently inventoried or compared with package payloads. The receipt marks
only the selected executable, startup, runtime-archive and link-input bytes as
package verified, and explicitly marks compiler dynamic libraries and the LTO
plugin unverified. The complete transitive executable closure is not
independently inventoried. The receipt
pins source, compiler/UAPI bytes, startup and link inputs, with that runner
remaining a trusted build environment.

The fixed build sequence is:

1. Fetch only the two fixed official archive URLs into fresh staging, with a
   4MiB download cap, verify size/SHA256, and validate every tar entry before
   extracting. Accept only regular files/directories under the exact top-level
   name, no duplicates, links, device entries, traversal or privileged modes;
   cap total extracted bytes/count. Verify exact license bytes. The Bubblewrap
   checkout and owned-FD overlay keep the existing pinned identities.
2. Pin `/usr/bin/x86_64-linux-gnu-gcc-13`, its `cc1`/`collect2`, the actual `as`/
   `ld`, `ar`/`ranlib`, generated GCC specs/search directories and every GCC
   startup/runtime input by hash and Ubuntu binary-package provenance. Download
   the exact package archives, verify their SHA256 against authenticated APT
   metadata, and compare each installed input with its package payload bytes.
   Retain package archives, exact copyright notices and file hashes. Inventory
   every intermediate shared-documentation symlink and its owning package;
   compare each target with that owner's exact package payload. The independent
   reviewer can then resolve each notice through archive metadata alone. Scrub
   environment; use only `/usr/bin:/bin`, `LC_ALL=C`, `TZ=UTC` and a recorded
   `SOURCE_DATE_EPOCH`. No caller `REALGCC`, loader, compiler or linker override
   is inherited.
3. Configure musl with that exact compiler, `--disable-shared --enable-static`
   and an absolute **owned staging prefix**, then build and stage its headers,
   `libc.a`, `Scrt1.o`/`crt1.o`, `crti.o`/`crtn.o`, wrapper and generated specs.
   Retain config/commands/compiler logs and hashes of every staged object.
   This is the only permitted libc/startup origin.
4. Stage only the Linux UAPI `linux/`, `asm-generic/` and architecture `asm/`
   directories from the exactly inventoried `linux-libc-dev` package. Never add
   the host `/usr/include` tree to musl's include search, which could select
   glibc headers. Retain all UAPI file hashes/package provenance.
5. Build only libcap's static archive and `.pc` using the staged musl wrapper:
   `make -C libcap/libcap libcap.a libcap.pc` with explicit `CC`, `BUILD_CC`,
   `AR`, `RANLIB`, `SHARED=no PTHREADS=no GOLANG=no PAM_CAP=no USE_GPERF=no`,
   `lib=lib` and the owned prefix. The fixed `_makenames` build helper is the
   only libcap-produced executable used during compilation. Preserve the
   upstream build macros; pass optimization/prefix-map flags through `COPTS`.
   No shared libcap, libpsx, PAM, Go tooling or privileged utility is built/used.
6. Compile exactly `bubblewrap.c`, `bind-mount.c`, `network.c`, `utils.c` into
   fixed object names using the staged musl wrapper, the source-controlled C
   overlay, `-D_GNU_SOURCE -O2 -fno-pie -fstack-protector-strong`, the reviewed
   upstream warning set, and mapped build paths. `config.h` contains only the
   pinned package string, with SELinux disabled. A retained `mount-compat.h`
   verifies the three overlapping musl mount constants before selecting their
   equivalent UAPI spellings; warnings remain errors. Include only staged
   musl, source libcap headers and the staged UAPI headers.
7. Link the four fixed objects and literal source-built `libcap.a` with the
   staged musl wrapper using `-static -no-pie -Wl,--build-id=none`, a full link
   map/cross-reference and linker input trace. Retain the unstripped output
   symbol/ELF tables and input hashes before any stripping. No dependency is
   found through caller PATH, `-lcap`, host pkg-config or a fallback toolchain.
8. Refuse any link input outside those four objects, staged musl CRT/libc,
   source-built libcap and the exact inventoried GCC `crtbeginS.o`/`crtendS.o`,
   `libgcc.a`/`libgcc_eh.a` inputs. The generated
   [musl GCC specs](https://git.musl-libc.org/cgit/musl/tree/tools/musl-gcc.specs.sh?id=9fa28ece75d8a2191de7c5bb53bed224c5947417)
   deliberately use those GCC runtime objects; record them rather than claiming
   all startup code came from musl. Retain their runtime-exception/copyright
   notices from the exact GCC package too.
9. Parse the output without executing it: require ELF64 little-endian x86_64,
   ET_EXEC, valid bounded program headers and executable load segments; refuse
   `PT_INTERP`, `PT_DYNAMIC`, `DT_NEEDED`, foreign libc or unexpected link input.
   Repeat the build in a second independent staging root and require identical
   runtime bytes after prefix mapping. A mismatch is a reproducibility failure.

All command arguments, a fixed environment and stdout/stderr are retained,
including diagnostics from a failed build. Source archives, both static images,
full link input copies/maps/traces, generated config/specs, UAPI file hashes and
package payload attestations form the candidate evidence. `STATIC-CLOSURE.json`
requires identical image bytes from both independent roots and states runtime
admission false. The artifact's outer manifest includes all this evidence.

The exact compiler package versions/hashes are not known until the first
build-only receipt is reviewed. The recipe must fail on an unavailable compiler
or unexpected link input; it cannot select another compiler/libc silently.
An independently reviewed source/lock/toolchain/static-image receipt and a
locked peer rebuild are still required before the host factory may admit this
image. Native mount/FD/lifecycle gates remain as listed in the parent README.
