#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# Reproduce the static official-artifact portion of the Copilot macOS evidence.
# This does not authenticate Copilot or certify the connector lifecycle.

set -euo pipefail

requested="${1:-latest}"
arch="${2:-$(uname -m)}"
case "${requested}" in
  latest) api_url="https://api.github.com/repos/github/copilot-cli/releases/latest" ;;
  *[!0-9.]*|"") echo "invalid Copilot version: ${requested}" >&2; exit 2 ;;
  *) api_url="https://api.github.com/repos/github/copilot-cli/releases/tags/v${requested}" ;;
esac
case "${arch}" in
  arm64|aarch64) asset_name="copilot-darwin-arm64.tar.gz" ;;
  x86_64|amd64) asset_name="copilot-darwin-x64.tar.gz" ;;
  *) echo "unsupported macOS architecture: ${arch}" >&2; exit 2 ;;
esac

for dependency in curl jq shasum tar codesign xattr; do
  command -v "${dependency}" >/dev/null || {
    echo "required command not found: ${dependency}" >&2
    exit 2
  }
done

probe_dir="$(mktemp -d "${TMPDIR:-/tmp}/defenseclaw-copilot-macos.XXXXXX")"
trap 'rm -rf "${probe_dir}"' EXIT
release_json="${probe_dir}/release.json"
archive="${probe_dir}/${asset_name}"

curl --proto '=https' --tlsv1.2 -fsSL "${api_url}" -o "${release_json}"
tag="$(jq -er '.tag_name | select(test("^v[0-9]+[.][0-9]+[.][0-9]+$"))' "${release_json}")"
asset_url="$(jq -er --arg name "${asset_name}" '.assets[] | select(.name == $name) | .browser_download_url' "${release_json}")"
digest="$(jq -er --arg name "${asset_name}" '.assets[] | select(.name == $name) | .digest | select(test("^sha256:[0-9a-f]{64}$"))' "${release_json}")"
expected_sha="${digest#sha256:}"

curl --proto '=https' --tlsv1.2 -fsSL "${asset_url}" -o "${archive}"
printf '%s  %s\n' "${expected_sha}" "${archive}" | shasum -a 256 -c -

entries="$(tar -tzf "${archive}")"
if printf '%s\n' "${entries}" | grep -Eq '(^/|(^|/)[.][.](/|$))'; then
  echo "archive contains an unsafe path" >&2
  exit 1
fi
if [[ "$(printf '%s\n' "${entries}" | grep -Ec '(^|/)copilot$')" -ne 1 ]]; then
  echo "archive does not contain exactly one Copilot executable" >&2
  exit 1
fi
binary_entry="$(printf '%s\n' "${entries}" | grep -E '(^|/)copilot$')"
binary="${probe_dir}/copilot"
tar -xOzf "${archive}" "${binary_entry}" >"${binary}"
chmod 0700 "${binary}"

codesign --verify --strict --verbose=2 "${binary}"
signature="$(codesign --display --verbose=4 "${binary}" 2>&1)"
grep -Fq 'TeamIdentifier=VEKTX9H2N7' <<<"${signature}" || {
  echo "Copilot artifact is not signed by GitHub team VEKTX9H2N7" >&2
  exit 1
}
set +e
quarantine_probe="$(xattr -p com.apple.quarantine "${binary}" 2>&1)"
quarantine_status=$?
set -e
if [[ "${quarantine_status}" -eq 0 ]]; then
  echo "extracted Copilot artifact is quarantined" >&2
  exit 1
fi
if [[ "${quarantine_status}" -ne 1 || "${quarantine_probe}" != *"No such xattr"* ]]; then
  echo "unable to prove Copilot quarantine state: ${quarantine_probe}" >&2
  exit 1
fi
version_output="$("${binary}" version)"
grep -Fq "GitHub Copilot CLI ${tag#v}" <<<"${version_output}" || {
  echo "artifact version does not match release tag ${tag}" >&2
  exit 1
}

printf 'tag=%s\nasset=%s\nsha256=%s\nteam_identifier=VEKTX9H2N7\nversion_output=%s\n' \
  "${tag}" "${asset_name}" "${expected_sha}" "${version_output//$'\n'/ }"
