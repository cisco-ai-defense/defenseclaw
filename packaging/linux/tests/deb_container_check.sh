#!/bin/sh
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# #1210: run the enterprise package's real prerm and postrm under dpkg and
# Debian's /bin/sh (dash) in a disposable container, and check that a
# removal stops the sandbox user units in a signed-in account's user
# manager, as that account, after the system units, and removes the
# socket's global enable link; and that an upgrade leaves them alone.
# systemctl is a stub that records its calls (a container runs no systemd);
# runuser, getent, stat and dpkg are the distribution's own.
#
#   docker run --rm -v "$PWD:/src:ro" debian:bookworm sh /src/packaging/linux/tests/deb_container_check.sh
#
# A removal whose user manager does not answer fails and keeps the package,
# and the next removal goes on once it answers.
#
# On a host without docker (dc-build-1), unpack a Debian rootfs into a
# scratch folder and run it there as root in a private mount and pid
# namespace, with DC_CONTAINER_CHECK=1:
#   sudo unshare --mount --pid --fork --propagation private sh -c \
#     "mount --rbind /dev ROOT/dev && mount -t proc proc ROOT/proc && \
#      mount -t tmpfs tmpfs ROOT/run && mount -t tmpfs tmpfs ROOT/tmp && \
#      chroot ROOT /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin DC_CONTAINER_CHECK=1 \
#      sh /src/packaging/linux/tests/deb_container_check.sh"
set -eu
src=${1:-/src}
fail() { echo "FAIL: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || fail "run as root in a disposable container"
[ -f /.dockerenv ] || [ -n "${DC_CONTAINER_CHECK:-}" ] || fail "run only in a disposable container"
log=/var/log/systemctl-calls.log
: >"$log"
# The stub also runs as the account.
chmod 666 "$log"
mkdir -p /usr/local/bin /run/systemd/system
cat >/usr/local/bin/systemctl <<STUB
#!/bin/sh
echo "\$(id -un) systemctl \$*" >>$log
# A user manager answers every unit's state; is-active exits 3 when none
# is active. With /run/dc-check-no-answer the user manager does not answer.
case "\$*" in
    "--user stop "* | "--user is-active "*)
        [ -e /run/dc-check-no-answer ] && { echo "Failed to connect to bus" >&2; exit 1; }
        case "\$*" in *is-active*) printf 'inactive\\ninactive\\ninactive\\n'; exit 3 ;; esac ;;
    *is-active*) exit 1 ;;
esac
exit 0
STUB
chmod 755 /usr/local/bin/systemctl
useradd -m -u 4242 sample-user
runtime=/run/user/4242
mkdir -p "$runtime/systemd"
chown -R sample-user "$runtime"
chmod 700 "$runtime"
# The user manager's private socket.
perl -MIO::Socket::UNIX -e 'IO::Socket::UNIX->new(Type => SOCK_STREAM(), Local => $ARGV[0], Listen => 1) or die "$!"' "$runtime/systemd/private"
[ -S "$runtime/systemd/private" ] || fail "no private socket"

build() {
    version=$1
    root=$(mktemp -d)
    mkdir -p "$root/DEBIAN" "$root/usr/share/doc/defenseclaw-enterprise"
    echo "check" >"$root/usr/share/doc/defenseclaw-enterprise/README"
    cat >"$root/DEBIAN/control" <<CONTROL
Package: defenseclaw-enterprise
Version: $version
Architecture: all
Maintainer: check <check@example.invalid>
Description: maintainer script check
CONTROL
    cp "$src/packaging/linux/preremove.sh" "$root/DEBIAN/prerm"
    cp "$src/packaging/linux/postremove.sh" "$root/DEBIAN/postrm"
    chmod 755 "$root/DEBIAN/prerm" "$root/DEBIAN/postrm"
    dpkg-deb --root-owner-group --build "$root" "/tmp/dc-$version.deb" >/dev/null
}
build 1.0.3
build 1.0.4
[ "$(readlink -f /bin/sh)" = /usr/bin/dash ] || fail "/bin/sh is not dash"

dpkg -i /tmp/dc-1.0.3.deb >/dev/null
: >"$log"
dpkg -i /tmp/dc-1.0.4.deb >/dev/null
if grep -q "systemctl --user\|systemctl --global" "$log"; then
    cat "$log"; fail "an upgrade touched the user units"
fi
echo "ok: an upgrade leaves the user units alone"

: >/run/dc-check-no-answer
if dpkg -r defenseclaw-enterprise >/tmp/dc-check-refused.log 2>&1; then
    cat /tmp/dc-check-refused.log; fail "dpkg -r went on while a user manager did not answer"
fi
grep -q "could not stop, or confirm stopped, the sandbox user units of sample-user; package files were kept" /tmp/dc-check-refused.log ||
    { cat /tmp/dc-check-refused.log; fail "the refusal does not name the account"; }
# dpkg -r marks the package for removal (deinstall) whether or not it goes.
[ "$(dpkg-query -W -f="\${db:Status-Status}" defenseclaw-enterprise 2>/dev/null)" = installed ] || fail "the package was not kept"
rm -f /run/dc-check-no-answer
echo "ok: a user manager that does not answer keeps the package"

: >"$log"
dpkg -r defenseclaw-enterprise
cat "$log"
units="defenseclaw-sandbox.socket defenseclaw-sandbox.service defenseclaw-openshell-gateway.service"
system=$(grep -n "^root systemctl stop " "$log" | head -1 | cut -d: -f1)
user=$(grep -n "^sample-user systemctl --user stop $units\$" "$log" | head -1 | cut -d: -f1)
global=$(grep -n "^root systemctl --global disable defenseclaw-sandbox.socket\$" "$log" | head -1 | cut -d: -f1)
[ -n "$system" ] || fail "the system units were not stopped"
[ -n "$user" ] || fail "the user units were not stopped as the account"
[ -n "$global" ] || fail "the global enable link was not removed"
if [ "$system" -ge "$user" ] || [ "$user" -ge "$global" ]; then
    fail "wrong order: system=$system user=$user global=$global"
fi
[ "$(dpkg-query -W -f="\${db:Status-Status}" defenseclaw-enterprise 2>/dev/null)" = installed ] && fail "the package is still installed"
echo "ok: dpkg -r stopped the user units as sample-user after the system units, then removed the enable link"

dpkg -i /tmp/dc-1.0.4.deb >/dev/null
: >"$log"
dpkg -P defenseclaw-enterprise >/dev/null
grep -q "^sample-user systemctl --user stop $units\$" "$log" || fail "dpkg -P did not stop the user units"
echo "ok: dpkg -P stopped the user units"
echo "PASS deb maintainer scripts"
