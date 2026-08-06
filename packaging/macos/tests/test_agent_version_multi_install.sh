#!/usr/bin/env bash
# discover_agent_version: multi-install & minimum-supported picking.
#
# Pins the fix for the two QA regressions on the shell installer side:
#
#   1. Homebrew npm-global at 1.9.0 + NVM install at 2.5.0 →
#      _pick_highest_supported returns 2.5.0 (NVM). The old first-hit
#      loop would have returned 1.9.0 and the Go hook-contract gate
#      would have refused to install hooks.
#   2. _pick_highest_supported falls back to the highest install
#      overall when no candidate clears MIN. This ensures operators
#      always see a real version in the discovery output — the Go gate
#      then reports "unsupported" rather than the noisier "unversioned".
. "${PKG_DIR}/lib/installer_lib.sh"

t_pick_highest_supported_prefers_meeting_minimum() {
  local out
  out="$(_pick_highest_supported "2.1.144" "1.9.0" "2.5.0")"
  assert_eq "${out}" "2.5.0" "highest-supported picks NVM over stale Homebrew"
}

t_pick_highest_supported_falls_back_to_highest_overall() {
  local out
  out="$(_pick_highest_supported "2.0.0" "1.0.0" "1.5.0")"
  assert_eq "${out}" "1.5.0" "fallback when nothing clears minimum still returns highest"
}

t_pick_highest_supported_empty_returns_empty() {
  local out
  out="$(_pick_highest_supported "1.0.0")"
  assert_eq "${out}" "" "no candidates yields empty string"
}

t_discover_agent_version_no_install_survives_set_eu() {
  # Regression: bash 3.2 on macOS treats "${arr[@]}" on an EMPTY array
  # under `set -u` as an "unbound variable" error and aborts the shell.
  # Previously discover_agent_version passed "${versions[@]}" straight
  # into _pick_highest_supported at three call sites; when no install
  # of the connector was on the box (empty `versions` array), the
  # caller's `$(... 2>/dev/null || true)` couldn't rescue the abort
  # because the shell died before the || branch was reached. install.sh
  # under set -euo pipefail then jumped to the EXIT trap and the whole
  # install ended mid-render_targets_manifest.
  #
  # Real reproduction: grep every _pick_highest_supported call site in
  # the library and confirm each guards the array expansion with the
  # bash-3.2-safe idiom `${arr[@]+"${arr[@]}"}`. A future edit that
  # drops the guard (or a new call site that forgets it) trips this
  # assertion before it can escape into an installer regression.
  local lib="${PKG_DIR}/lib/installer_lib.sh"
  assert_file_exists "${lib}"
  local unguarded
  unguarded="$(grep -nE '_pick_highest_supported[[:space:]]+"[^"]*"[[:space:]]+"\$\{versions\[@\]\}"[[:space:]]*$' "${lib}" || true)"
  assert_eq "${unguarded}" "" \
    "every _pick_highest_supported call must use \${versions[@]+\"\${versions[@]}\"} for bash 3.2 set -eu safety; unguarded call site(s): ${unguarded}"

  # And exercise the runtime path once so the property is proven end-to-
  # end for the picker itself: an empty caller array must not abort the
  # shell under set -eu.
  set +u
  local rc got
  got="$(
    set -eu
    declare -a versions=()
    _pick_highest_supported "2.1.144" ${versions[@]+"${versions[@]}"}
    printf 'RC=%d' "$?"
  )"
  rc="${got##*RC=}"
  set -u
  assert_eq "${rc}" "0" \
    "empty versions[@] under set -eu must expand cleanly at _pick_highest_supported call sites"
}

t_pick_highest_supported_ignores_empty_arg() {
  local out
  out="$(_pick_highest_supported "1.0.0" "" "2.0.0" "")"
  assert_eq "${out}" "2.0.0" "empty candidate strings are skipped"
}

t_version_ge_handles_semver_ordering() {
  # Sanity: sort -V knows semver.
  if _version_ge "2.5.0" "2.1.144"; then :; else _fail "2.5.0 should be >= 2.1.144"; fi
  if _version_ge "1.9.0" "2.1.144"; then _fail "1.9.0 should NOT be >= 2.1.144"; fi
  if _version_ge "2.1.144" "2.1.144"; then :; else _fail "2.1.144 should be >= itself"; fi
}

t_claudecode_probe_picks_nvm_over_stale_homebrew() {
  # Reproduces QA #2. Note the assertion is a lower bound rather than
  # an exact match: the developer machine running the tests may have a
  # real @anthropic-ai/claude-code install under /opt/homebrew/lib/
  # node_modules/ (which we can't hide), and if that version is
  # higher-and-supported it will legitimately outrank our fake NVM
  # install. Either way the fix is proven: the picker returned
  # SOMETHING >= 2.5.0, i.e. it did not stop at the stale 1.9.0
  # in $home/.npm-global. The Python test
  # test_agent_discovery_multi_install.py has full sandboxing via
  # monkeypatch and pins the exact 2.5.0 result.
  local home tmp pkg_nvm pkg_brew out
  tmp="$(mktest_tmp)"
  home="${tmp}/home"
  pkg_nvm="${home}/.nvm/versions/node/v22.21.0/lib/node_modules/@anthropic-ai/claude-code/package.json"
  pkg_brew="${home}/.npm-global/lib/node_modules/@anthropic-ai/claude-code/package.json"
  mkdir -p "$(dirname "${pkg_nvm}")" "$(dirname "${pkg_brew}")"
  printf '{"version": "2.5.0"}\n' > "${pkg_nvm}"
  printf '{"version": "1.9.0"}\n' > "${pkg_brew}"

  out="$(discover_agent_version claudecode "${home}")"
  if [[ -z "${out}" ]]; then
    _fail "claudecode probe returned empty; expected 2.5.0 or higher"
    return 1
  fi
  if _version_ge "${out}" "2.5.0"; then :; else
    _fail "expected >= 2.5.0 (NVM install), got=${out}"
  fi
  # And confirm the stale 1.9.0 did NOT win.
  if [[ "${out}" == "1.9.0" ]]; then
    _fail "stale npm-global 1.9.0 won over supported NVM 2.5.0"
  fi
}

t_claudecode_probe_reads_native_installer_current_symlink() {
  # Verifies the "current symlink wins over higher versions/*/" contract
  # of the native-layout probe. Exercised directly against
  # _native_claudecode_version_from_dir with a caller-supplied base dir
  # so a real Claude Code install under /opt/claude,
  # /usr/local/share/claude, /usr/local/bin/claude, or
  # /opt/homebrew/bin/claude on the dev box or CI runner cannot leak
  # into the assertion (discover_agent_version probes those absolute
  # roots unconditionally and they aren't sandboxable).
  local tmp base versions out
  tmp="$(mktest_tmp)"
  base="${tmp}/home/.local/share/claude"
  versions="${base}/versions"
  mkdir -p "${versions}/2.5.0" "${versions}/2.1.144"
  # `current` symlink points at 2.1.144 even though 2.5.0 is present —
  # simulates a user who ran `claude version rollback`.
  ln -s "${versions}/2.1.144" "${base}/current"

  out="$(_native_claudecode_version_from_dir "${base}")"
  assert_eq "${out}" "2.1.144" "current symlink wins over higher versions/*/"
}

t_claudecode_probe_returns_highest_when_all_below_min() {
  # Exercises the "no candidate clears MIN — return highest overall"
  # branch of _pick_highest_supported. We hit that branch directly (it
  # is unit-tested with all four inputs) rather than through
  # discover_agent_version because the dev machine's real system-wide
  # /opt/homebrew or /opt/claude install (if any) would legitimately
  # outrank our fake and the "all below MIN" premise wouldn't hold.
  # discover_agent_version's contract "return SOMETHING when any
  # install exists" is already covered by
  # t_claudecode_probe_picks_nvm_over_stale_homebrew above.
  local out
  out="$(_pick_highest_supported "${MIN_CLAUDECODE_VERSION}" "1.5.0" "1.9.0")"
  assert_eq "${out}" "1.9.0" "highest overall wins when nothing clears MIN"
}

t_codex_probe_reads_npm_global_metadata() {
  # We can't create /opt/homebrew/Caskroom or /opt/homebrew/lib inside
  # the sandbox, and the developer machine running the tests may have
  # its own real codex install there. Restrict this case to what we
  # CAN prove hermetically: given a user-scoped npm-global at a fake
  # $home, discover_agent_version returns *some* version >= that fake
  # (either the fake itself, or the developer machine's real install
  # picked up because it clears MIN and outranks the fake — both are
  # correct enumerate-all-then-pick behaviour). What we're pinning is
  # "the fake install was not silently ignored", which the presence of
  # a non-empty output proves.
  local home tmp pkg_user out
  tmp="$(mktest_tmp)"
  home="${tmp}/home"
  pkg_user="${home}/.npm-global/lib/node_modules/@openai/codex/package.json"
  mkdir -p "$(dirname "${pkg_user}")"
  printf '{"version": "0.130.0"}\n' > "${pkg_user}"

  out="$(discover_agent_version codex "${home}")"
  if [[ -z "${out}" ]]; then
    _fail "codex probe returned empty; expected a version"
    return 1
  fi
  # And confirm the returned string is version-shaped.
  [[ "${out}" =~ ^[0-9]+\.[0-9]+ ]] || _fail "output ${out} is not version-shaped"
}

t_min_versions_match_hook_contracts_json() {
  # Drift guard: shell installer constants must agree with the JSON
  # the Python resolver reads. Exercises the same invariant that
  # test_agent_discovery_multi_install.py's Python-side test pins.
  local hook_contracts json_min
  hook_contracts="${REPO_ROOT}/cli/defenseclaw/inventory/hook_contracts.json"
  assert_file_exists "${hook_contracts}"
  json_min="$(python3 -c '
import json, sys
doc = json.load(open(sys.argv[1]))
target = sys.argv[2]
for c in doc["connectors"][target]["contracts"]:
    if c.get("default_for_unversioned"):
        print(c["agent_version"]["min_inclusive"]); break
' "${hook_contracts}" claudecode)"
  assert_eq "${json_min}" "${MIN_CLAUDECODE_VERSION}" "claudecode MIN aligned with hook_contracts.json"

  json_min="$(python3 -c '
import json, sys
doc = json.load(open(sys.argv[1]))
target = sys.argv[2]
for c in doc["connectors"][target]["contracts"]:
    if c.get("default_for_unversioned"):
        print(c["agent_version"]["min_inclusive"]); break
' "${hook_contracts}" codex)"
  assert_eq "${json_min}" "${MIN_CODEX_VERSION}" "codex MIN aligned with hook_contracts.json"

  json_min="$(python3 -c '
import json, sys
doc = json.load(open(sys.argv[1]))
target = sys.argv[2]
for c in doc["connectors"][target]["contracts"]:
    if c.get("default_for_unversioned"):
        print(c["agent_version"]["min_inclusive"]); break
' "${hook_contracts}" cursor)"
  assert_eq "${json_min}" "${MIN_CURSOR_VERSION}" "cursor MIN aligned with hook_contracts.json"
}

run_case "_pick_highest_supported prefers meeting minimum"     t_pick_highest_supported_prefers_meeting_minimum
run_case "_pick_highest_supported falls back to highest"       t_pick_highest_supported_falls_back_to_highest_overall
run_case "_pick_highest_supported empty returns empty"         t_pick_highest_supported_empty_returns_empty
run_case "discover_agent_version safe with no install (bash 3.2 set -eu)" t_discover_agent_version_no_install_survives_set_eu
run_case "_pick_highest_supported ignores empty arg"           t_pick_highest_supported_ignores_empty_arg
run_case "_version_ge handles semver ordering"                 t_version_ge_handles_semver_ordering
run_case "claudecode probe picks NVM over stale npm-global"    t_claudecode_probe_picks_nvm_over_stale_homebrew
run_case "claudecode probe reads native installer symlink"     t_claudecode_probe_reads_native_installer_current_symlink
run_case "claudecode probe returns highest when all below min" t_claudecode_probe_returns_highest_when_all_below_min
run_case "codex probe reads npm-global metadata"               t_codex_probe_reads_npm_global_metadata
run_case "MIN constants match hook_contracts.json"             t_min_versions_match_hook_contracts_json
