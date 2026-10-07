#!/bin/sh
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# defenseclaw-enterprise deb: apt Pre-Install-Pkgs hook that refuses to
# downgrade the package before dpkg runs, so the running deployment is left
# alone. The older release cannot read the config_version 9 file this release
# writes, so its services would fail to start. A package script cannot do
# this: dpkg runs the installed package's prerm with the incoming version,
# but when it fails dpkg falls back to the incoming package's own prerm and
# unpacks the older files anyway. rpm has no such hook, and a plain
# `dpkg -i` does not run apt hooks, so only an apt install is covered.
#
# apt sends the "VERSION 2" protocol on stdin (see apt.conf(5)): the
# configuration, a blank line, then one line per package action:
#   name old-version direction new-version action
# A deliberate rollback creates the root-owned marker first; the marker is
# used up by the downgrade it allows.

set -u
gateway=/opt/defenseclaw/bin/defenseclaw-gateway
state=/var/lib/defenseclaw-enterprise

change=$(awk 'body && $1 == "defenseclaw-enterprise" && $3 == ">" && $4 != "-" { print $2, $4; exit } $0 == "" { body = 1 }')
[ -n "$change" ] || exit 0
# shellcheck disable=SC2086 # two version strings without blanks
set -- $change
installed=$1
incoming=$2

# Snapshot builds share a release number; compare the release only.
release() { printf '%s' "$1" | sed 's/[-~+].*$//'; }
dpkg --compare-versions "$(release "$incoming")" lt "$(release "$installed")" || exit 0

marker=$state/allow-downgrade
if [ -f "$marker" ] && [ ! -L "$marker" ]; then
    rm -f "$marker"
    exit 0
fi
echo "defenseclaw-enterprise: $installed is installed; refusing to downgrade to $incoming, because the older release cannot read this release's config_version 9 config. Nothing was changed." >&2
echo "  For a deliberate rollback create the marker first: sudo touch $marker" >&2
echo "  then install the older package and finish with: sudo $gateway enterprise linux ensure --from-package --allow-downgrade --config /etc/defenseclaw/config.yaml.v8.bak" >&2
exit 1
