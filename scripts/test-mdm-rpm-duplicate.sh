#!/bin/sh
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
# Regression for a same-version RPM repair after an interrupted upgrade left
# two versions installed. Exercise the wrapper's package function with a mock
# RPM database and installer, without requiring root or modifying the host.
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
functions=$(mktemp)
trap 'rm -f "$functions"' EXIT HUP INT TERM
sed -n '/^dc_install_package() {/,/^}/p' "$repo/packaging/mdm/linux/defenseclaw-enterprise.sh" >"$functions"
. "$functions"

DC_STAGED_SOURCE=/tmp/defenseclaw-enterprise.rpm
DC_SCRIPT_OS=linux
DC_LINUX_PACKAGE=defenseclaw-enterprise
DC_EXIT_FAILURE=1
DC_EXIT_INVALID=2
DC_EXIT_BUSY=75
DC_PACKAGE_ACTION=''
dc_require_product_version() { :; }
dc_binaries_damaged() { return 0; }
dc_package_release_version() { printf '%s\n' "$1"; }
dc_package_step() { DC_PACKAGE_ACTION=upgrade; }
dc_busy_output() { return 1; }
dc_fail_result() { printf 'unexpected package failure: %s\n' "$3" >&2; exit 1; }
rpm() {
    case "$1:$2" in
        -qp:--qf)
            case "$3" in
                '%{NAME}') printf '%s' defenseclaw-enterprise ;;
                '%{VERSION}-%{RELEASE}') printf '%s' '1.0.4101-1' ;;
                *) return 1 ;;
            esac ;;
        -q:--qf) printf '1.0.3602-1\n1.0.4101-1\n' ;;
        -q:*) return 0 ;;
        -U:*)
            case " $* " in
                *' --replacepkgs '*) : ;;
                *) printf '%s\n' 'package is already installed' >&2; return 1 ;;
            esac ;;
        *) return 1 ;;
    esac
}

dc_install_package
[ "$DC_PACKAGE_ACTION" = upgrade ]
printf '%s\n' 'MDM RPM duplicate-version repair: PASS'
