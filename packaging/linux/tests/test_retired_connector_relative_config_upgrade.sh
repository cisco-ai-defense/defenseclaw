#!/bin/sh
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
set -eu

# The upgrade installer may start the gateway from another directory. Its
# inherited relative OmniGent paths must still name the caller's files.
repo=$(CDPATH= cd "$(dirname "$0")/../../.." && pwd -P)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/caller/policyhome" "$work/caller/config" "$work/home"
cat >"$work/print-env.sh" <<'SH'
trap 'printf "BOUND_HOME=%s\nBOUND_FILE=%s\n" "${OMNIGENT_CONFIG_HOME-}" "${OMNIGENT_CONFIG-}"' EXIT
SH
cd "$work/caller"
out=$(HOME="$work/home" OMNIGENT_CONFIG_HOME=./policyhome OMNIGENT_CONFIG=./config/agent.yaml \
    BASH_ENV="$work/print-env.sh" bash "$repo/scripts/install.sh" --help 2>&1)
case "$out" in
    *"BOUND_HOME=$work/caller/./policyhome"*"BOUND_FILE=$work/caller/./config/agent.yaml"*) ;;
    *) printf '%s\n' "$out"; echo 'relative OmniGent paths were not bound to the caller directory' >&2; exit 1 ;;
esac
out=$(HOME="$work/home" OMNIGENT_CONFIG_HOME='~/policyhome' OMNIGENT_CONFIG='~/config/agent.yaml' \
    BASH_ENV="$work/print-env.sh" bash "$repo/scripts/install.sh" --help 2>&1)
case "$out" in
    *'BOUND_HOME=~/policyhome'*'BOUND_FILE=~/config/agent.yaml'*) ;;
    *) printf '%s\n' "$out"; echo 'home-relative OmniGent paths were changed by the installer' >&2; exit 1 ;;
esac
