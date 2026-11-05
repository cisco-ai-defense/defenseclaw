#!/bin/bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# Contract test for the Claude Cowork VM package tools, run in CI: the build is
# deterministic and passes check-package.py, sign.sh output passes
# verify-signature.py, and every signature Claude would refuse (armored, text
# mode, notation, policy URL, key server, no expiry, over 730 days, wrong key,
# changed package) is refused. sign.sh refuses a key other than the pinned
# fingerprint, and a re-sign with a key other than the one the release
# carries. install.sh's refusals (exit 11-14) are checked on the built
# package; with passwordless sudo the root-only ones run too.
# Stand-in ELF files replace the real binaries, so no Go build is needed.
#
#   test-package.sh
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
t="$(mktemp -d)"; trap 'gpgconf --homedir "$t/gnupg" --kill all > /dev/null 2>&1 || true; rm -rf "$t"' EXIT
fails=0
ok() { echo "ok   $*"; }
bad() { echo "FAIL $*"; fails=$((fails + 1)); }
case "$(uname -m)" in x86_64) arch=amd64 other=arm64 ;; aarch64) arch=arm64 other=amd64 ;; *) echo "unsupported host"; exit 1 ;; esac
cp "$(type -P true)" "$t/gw"; cp "$(type -P true)" "$t/helper"
export SOURCE_DATE_EPOCH=1792000000

# Build: deterministic, rules hold.
"$here/build.sh" --arch "$arch" --version 9.9.9-test --gateway "$t/gw" --helper "$t/helper" \
  --policies "$here/../../policies" --out-dir "$t/a" > /dev/null
"$here/build.sh" --arch "$arch" --version 9.9.9-test --gateway "$t/gw" --helper "$t/helper" \
  --policies "$here/../../policies" --out-dir "$t/b" > /dev/null
pkg="$t/a/defenseclaw-cowork-$arch.tar.gz"
if cmp -s "$pkg" "$t/b/defenseclaw-cowork-$arch.tar.gz"; then ok "two builds are byte-identical"; else bad "two builds differ"; fi
if [ "$(tar tzf "$pkg" | grep -c '^install.sh$')" = 1 ]; then ok "install.sh at the top level"; else bad "no top-level install.sh"; fi
if "$here/build.sh" --arch "$other" --version 9.9.9-test --gateway "$t/gw" --helper "$t/helper" --out-dir "$t/c" > /dev/null 2>&1; then
  bad "build accepted $arch binaries for $other"
else ok "build refuses binaries of the other architecture"; fi
python3 - "$t" << 'PY'
import io, sys, tarfile
t = sys.argv[1]
with tarfile.open(f"{t}/link.tar.gz", "w:gz", format=tarfile.USTAR_FORMAT) as out:
    data = b"#!/bin/sh\n"
    info = tarfile.TarInfo("install.sh"); info.size = len(data); info.mode = 0o755
    out.addfile(info, io.BytesIO(data))
    link = tarfile.TarInfo("bin"); link.type = tarfile.SYMTYPE; link.linkname = "/usr/bin"
    out.addfile(link)
PY
if python3 "$here/check-package.py" "$t/link.tar.gz" > /dev/null 2>&1; then bad "check-package accepted a symlink"; else ok "check-package refuses a symlink"; fi
mkdir "$t/nolic"; tar xzf "$pkg" -C "$t/nolic"; rm "$t/nolic/licenses/NOTICE"
(cd "$t/nolic" && tar --format=ustar --owner=0 --group=0 --numeric-owner -czf "$t/nolic.tar.gz" -- *)
if python3 "$here/check-package.py" "$t/nolic.tar.gz" > /dev/null 2>&1; then bad "check-package accepted a package without licenses/NOTICE"; else ok "check-package refuses a package without a license file"; fi

# Signatures.
export GNUPGHOME="$t/gnupg"; mkdir -m 0700 "$GNUPGHOME"
gpg --batch --quiet --passphrase '' --quick-gen-key "Cowork test <cowork-test@example.invalid>" ed25519 sign 30d 2> /dev/null
fpr="$(gpg --batch --with-colons --list-secret-keys | awk -F: '$1 == "fpr" {print $10; exit}')"
gpg --batch --armor --export-secret-keys "$fpr" > "$t/secret.asc"
gpg --batch --armor --export "$fpr" > "$t/public.asc"
gpg --batch --quiet --check-trustdb 2> /dev/null || true
if (unset GNUPGHOME; "$here/sign.sh" --key-file "$t/secret.asc" --fingerprint "$fpr" --public-key-out "$t/pub-out.asc" "$pkg") > /dev/null; then
  ok "sign.sh signs and verifies (180d default)"
else bad "sign.sh failed"; fi
if (unset GNUPGHOME; "$here/sign.sh" --key-file "$t/secret.asc" "$t/b/defenseclaw-cowork-$arch.tar.gz") > /dev/null 2>&1; then
  bad "sign.sh signed without a pinned fingerprint"; else ok "sign.sh refuses to sign without a pinned fingerprint"; fi
if (unset GNUPGHOME; "$here/sign.sh" --key-file "$t/secret.asc" --fingerprint 0000000000000000000000000000000000000000 "$t/b/defenseclaw-cowork-$arch.tar.gz") > /dev/null 2>&1 ||
  [ -e "$t/b/defenseclaw-cowork-$arch.tar.gz.sig" ]; then
  bad "sign.sh signed with a key that is not the pinned one"; else ok "sign.sh refuses a key that is not the pinned fingerprint"; fi
cmp -s <(gpg --batch --dearmor < "$t/pub-out.asc") <(gpg --batch --dearmor < "$t/public.asc") && ok "sign.sh exports the public key" || bad "sign.sh public key differs"
verify() { python3 "$here/verify-signature.py" "$@" > /dev/null 2>&1; }
verify "$pkg.sig" --package "$pkg" --public-key "$t/public.asc" --fingerprint "$fpr" && ok "verify: good signature passes" || bad "verify: good signature refused"
sig() { # sig <name> <gpg options...>: sign $pkg into $t/<name>/<pkg>.sig
  local out
  mkdir -p "$t/$1"; cp "$pkg" "$t/$1/"; out="$t/$1/$(basename "$pkg")"; shift
  gpg --batch --yes --no-options --pinentry-mode loopback --passphrase '' -u "$fpr" "$@" --output "$out.sig" "$out" 2> /dev/null
  echo "$out"
}
expect_refused() { # expect_refused <what> <package>
  if verify "$2.sig" --package "$2" --public-key "$t/public.asc"; then bad "verify accepted: $1"; else ok "verify refuses: $1"; fi
}
expect_refused "ASCII armor" "$(sig armor --armor --detach-sign --default-sig-expire 180d)"
expect_refused "text mode (sigclass 0x01)" "$(sig text --textmode --detach-sign --default-sig-expire 180d)"
expect_refused "a notation" "$(sig notation --sig-notation test@example.invalid=1 --detach-sign --default-sig-expire 180d)"
expect_refused "a policy URL" "$(sig policy --sig-policy-url https://example.invalid/p --detach-sign --default-sig-expire 180d)"
expect_refused "a key server URL" "$(sig keyserver --sig-keyserver-url https://example.invalid/k --detach-sign --default-sig-expire 180d)"
expect_refused "no expiry" "$(sig noexpiry --detach-sign --default-sig-expire 0)"
expect_refused "731 days" "$(sig d731 --detach-sign --default-sig-expire 731d)"
p730="$(sig d730 --detach-sign --default-sig-expire 2y)"
verify "$p730.sig" --package "$p730" --public-key "$t/public.asc" && ok "verify: 2y (730 days) passes" || bad "verify: 2y refused"
changed="$(sig changed --detach-sign --default-sig-expire 180d)"; printf x >> "$changed"
expect_refused "a changed package" "$changed"
if verify "$pkg.sig" --package "$pkg" --public-key "$t/public.asc" --fingerprint 0000000000000000000000000000000000000000; then
  bad "verify accepted the wrong signing key"; else ok "verify refuses the wrong signing key"; fi
if (unset GNUPGHOME; "$here/sign.sh" --key-file "$t/secret.asc" --fingerprint "$fpr" --expire 731d "$pkg") > /dev/null 2>&1; then
  bad "sign.sh accepted --expire 731d"; else ok "sign.sh refuses --expire 731d"; fi
gpg --batch --quiet --passphrase '' --quick-gen-key "Other <other@example.invalid>" ed25519 sign 30d 2> /dev/null
gpg --batch --armor --export-secret-keys > "$t/two-secret.asc"
other_fpr="$(gpg --batch --with-colons --list-secret-keys | awk -F: '$1 == "fpr" {print $10}' | grep -vx "$fpr" | head -n 1)"
gpg --batch --armor --export "$other_fpr" > "$t/other-public.asc"
if (unset GNUPGHOME; "$here/sign.sh" --key-file "$t/two-secret.asc" --fingerprint "$fpr" "$pkg") > /dev/null 2>&1; then
  bad "sign.sh signed with a key file holding two secret keys"; else ok "sign.sh refuses a key file with two secret keys"; fi
# A re-sign (cowork-sign --clobber) keeps the key the release already carries.
sum_before="$(sha256sum < "$pkg.sig")"
if (unset GNUPGHOME; "$here/sign.sh" --key-file "$t/secret.asc" --fingerprint "$fpr" --published-key "$t/other-public.asc" "$pkg") > /dev/null 2>&1 ||
  [ "$(sha256sum < "$pkg.sig")" != "$sum_before" ]; then
  bad "sign.sh re-signed a release that carries a different key"; else ok "sign.sh refuses to replace signatures made with a different key"; fi
(unset GNUPGHOME; "$here/sign.sh" --key-file "$t/secret.asc" --fingerprint "$fpr" --published-key "$t/public.asc" "$pkg") > /dev/null 2>&1 &&
  ok "sign.sh re-signs with the key the release carries" || bad "re-sign with the Cowork key failed"

# install.sh refusals, from the unpacked package.
mkdir "$t/unpack"; tar xzf "$pkg" -C "$t/unpack"
run() { # run <want rc> <what> <as> [VAR=value...]
  local want=$1 what=$2 as=$3 out rc; shift 3
  if [ "$as" = root ]; then
    out="$(cd "$t/unpack" && sudo -n env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin "$@" bash ./install.sh 2>&1)" && rc=0 || rc=$?
  else
    out="$(cd "$t/unpack" && env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin "$@" bash ./install.sh 2>&1)" && rc=0 || rc=$?
  fi
  if [ "$rc" = "$want" ] && [[ "$(tail -n 1 <<< "$out")" == "defenseclaw-cowork: FAILED: "* ]]; then ok "install.sh exit $rc: $what"
  else bad "install.sh $what: rc=$rc (want $want), last line: $(tail -n 1 <<< "$out")"; fi
}
if [ "$(id -u)" != 0 ]; then run 11 "not root" user COWORK_VM_ARCH="$arch"; fi
if [ "$(id -u)" = 0 ] || sudo -n true 2> /dev/null; then
  as=root
  run 12 "package for the other architecture" $as COWORK_VM_ARCH="$other" COWORK_EDR_INTEGRATION_ARGS=collector=c.example:4318
  run 12 "unknown architecture" $as COWORK_VM_ARCH=riscv64 COWORK_EDR_INTEGRATION_ARGS=collector=c.example:4318
  run 13 "unknown argument" $as COWORK_VM_ARCH="$arch" COWORK_EDR_INTEGRATION_ARGS=collector=c.example:4318,token=abc
  run 13 "argument given twice" $as COWORK_VM_ARCH="$arch" COWORK_EDR_INTEGRATION_ARGS=device=a,device=b,collector=c.example:4318
  run 13 "argument without a value" $as COWORK_VM_ARCH="$arch" COWORK_EDR_INTEGRATION_ARGS=tenant,collector=c.example:4318
  run 13 "a space in the arguments" $as COWORK_VM_ARCH="$arch" "COWORK_EDR_INTEGRATION_ARGS=tenant=a b,collector=c.example:4318"
  run 14 "no collector" $as COWORK_VM_ARCH="$arch" COWORK_EDR_INTEGRATION_ARGS=tenant=t1,device=d1
  run 14 "collector without a port" $as COWORK_VM_ARCH="$arch" COWORK_EDR_INTEGRATION_ARGS=collector=c.example
  run 14 "collector port out of range" $as COWORK_VM_ARCH="$arch" COWORK_EDR_INTEGRATION_ARGS=collector=c.example:70000
  # 18: a package missing a file, and any unexpected 200-243 status (Claude
  # reserves them), forced by an exit 201 injected after the cleanup trap.
  rm "$t/unpack/bin/defenseclaw-sensor-helper"
  run 18 "package without the sensor helper" $as COWORK_VM_ARCH="$arch" COWORK_EDR_INTEGRATION_ARGS=collector=c.example:4318
  tar xzf "$pkg" -C "$t/unpack" bin/defenseclaw-sensor-helper
  cp "$t/unpack/install.sh" "$t/install.orig"
  sed -i "/^trap 'rc=\$?; rm -rf/a exit 201" "$t/unpack/install.sh"
  if grep -qx 'exit 201' "$t/unpack/install.sh"; then
    run 18 "unexpected status 201 is mapped to 18" $as COWORK_VM_ARCH="$arch" COWORK_EDR_INTEGRATION_ARGS=collector=c.example:4318
  else bad "could not inject exit 201 after the cleanup trap"; fi
  cp "$t/install.orig" "$t/unpack/install.sh"
else
  echo "skip install.sh exit 12-14 and 18 checks: they need root (passwordless sudo)"
fi
if [ "$fails" = 0 ]; then echo "all Cowork package checks passed"; else echo "$fails Cowork package checks failed"; exit 1; fi
