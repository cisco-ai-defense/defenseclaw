#!/usr/bin/env bash
# render-targets.sh resilience: the enumerator never publishes an empty
# manifest on a directory-service failure, re-stamps an unchanged manifest,
# refuses to follow a symlinked hook-guardian folder, turns a missing config
# into defenseclaw_degraded instead of exit 1, and logs one defenseclaw_skip
# per filtered user per streak. Markers use the Go resilience format.

RT_SH="${PKG_DIR}/lib/render-targets.sh"

# _rt_fixture DIR: a support dir with the real library, a config naming one
# connector, and a fake dscl on PATH driven by files under DIR/dscl.
_rt_fixture() {
  local dir="$1"
  mkdir -p "${dir}/support/lib" "${dir}/support/etc" "${dir}/bin" "${dir}/dscl/home"
  cp "${PKG_DIR}/lib/installer_lib.sh" "${dir}/support/lib/installer_lib.sh"
  cat > "${dir}/support/etc/config.yaml" <<'YAML'
guardrail:
  connector: claudecode
YAML
  cat > "${dir}/bin/dscl" <<EOF
#!/usr/bin/env bash
state="${dir}/dscl"
if [[ -f "\${state}/fail" ]]; then
  exit 1
fi
case "\$2" in
  -list) cat "\${state}/list" ;;
  -read)
    [[ -f "\${state}/readfail" ]] && exit 56
    name="\${3##*/}"
    case "\$4" in
      NFSHomeDirectory) [[ -f "\${state}/home/\${name}" ]] && printf 'NFSHomeDirectory: %s\n' "\$(cat "\${state}/home/\${name}")" ;;
      PrimaryGroupID) printf 'PrimaryGroupID: 20\n' ;;
    esac
    ;;
esac
exit 0
EOF
  chmod 0755 "${dir}/bin/dscl"
  printf 'root 0\n_spotlight 89\n' > "${dir}/dscl/list"
}

# _rt_run DIR -> stdout: "rc<TAB>stderr"
_rt_run() {
  local dir="$1" err rc
  err="$(PATH="${dir}/bin:${PATH}" SUPPORT_DIR="${dir}/support" \
    DEFENSECLAW_CONFIG="${dir}/support/etc/config.yaml" \
    DC_ENUMERATOR_TEST_UNPRIVILEGED=1 DC_ENUMERATOR_CONSOLE_USER="" \
    bash "${RT_SH}" 2>&1 >/dev/null)"
  rc=$?
  printf '%s\t%s' "${rc}" "${err}"
}

_rt_skip_unless_darwin() {
  [[ "$(uname -s)" == "Darwin" ]]
}

t_rt_marker_matches_go_format() {
  local dir wrapper out
  dir="$(mktest_tmp)"
  wrapper="${dir}/marker.sh"
  {
    printf '#!/usr/bin/env bash\n'
    /usr/bin/awk '/^rt_quote\(\)/{found=1} found{print} found && /^}$/{exit}' "${RT_SH}"
    /usr/bin/awk '/^rt_marker\(\)/{found=1} found{print} found && /^}$/{exit}' "${RT_SH}"
    printf 'rt_marker "$@"\n'
  } > "${wrapper}"
  out="$(bash "${wrapper}" defenseclaw_skip unit "user:bob" reason 'say "hi"' path $'/Users/a b\tc\\d' 2>&1)"
  assert_eq "${out}" 'defenseclaw_skip path="/Users/a b\tc\\d" reason="say \"hi\"" unit="user:bob"' "marker line"
  out="$(bash "${wrapper}" defenseclaw_degraded 2>&1)"
  assert_eq "${out}" 'defenseclaw_degraded' "marker without fields"
}

t_rt_dscl_failure_keeps_previous_manifest() {
  _rt_skip_unless_darwin || return 0
  local dir result rc err previous
  dir="$(mktest_tmp)"
  _rt_fixture "${dir}"
  mkdir -p "${dir}/support/hook-guardian"
  previous=$'version: 1\ntargets:\n  - user: "alice"\n    connector: "claudecode"\n'
  printf '%s' "${previous}" > "${dir}/support/hook-guardian/targets.yaml"
  touch "${dir}/dscl/fail"
  result="$(_rt_run "${dir}")"
  rc="${result%%$'\t'*}"; err="${result#*$'\t'}"
  assert_status "${rc}" 0 "dscl failure exit"
  assert_eq "$(cat "${dir}/support/hook-guardian/targets.yaml")" "${previous%$'\n'}" "previous manifest kept"
  assert_contains "${err}" 'defenseclaw_degraded component="hook-enumerator"' "degraded marker"
  assert_contains "${err}" 'opendirectory_unavailable' "degraded reason"
}

t_rt_unchanged_manifest_is_restamped() {
  _rt_skip_unless_darwin || return 0
  local dir result rc err
  dir="$(mktest_tmp)"
  _rt_fixture "${dir}"
  _rt_run "${dir}" >/dev/null
  assert_file_mode "${dir}/support/hook-guardian/targets.yaml" 640
  chmod 0666 "${dir}/support/hook-guardian/targets.yaml"
  chflags uchg "${dir}/support/hook-guardian/targets.yaml"
  result="$(_rt_run "${dir}")"
  rc="${result%%$'\t'*}"; err="${result#*$'\t'}"
  chflags nouchg "${dir}/support/hook-guardian/targets.yaml" 2>/dev/null
  assert_status "${rc}" 0 "re-stamp exit"
  assert_file_mode "${dir}/support/hook-guardian/targets.yaml" 640
  assert_contains "${err}" "defenseclaw_repair" "repair marker"
  assert_contains "${err}" "path=\"${dir}/support/hook-guardian/targets.yaml\"" "repair path"
}

t_rt_symlinked_manifest_dir_is_never_followed() {
  _rt_skip_unless_darwin || return 0
  local dir result rc err elsewhere
  dir="$(mktest_tmp)"
  _rt_fixture "${dir}"
  elsewhere="${dir}/elsewhere"
  mkdir -p "${elsewhere}"
  chmod 0700 "${elsewhere}"
  ln -s "${elsewhere}" "${dir}/support/hook-guardian"
  result="$(_rt_run "${dir}")"
  rc="${result%%$'\t'*}"; err="${result#*$'\t'}"
  assert_status "${rc}" 0 "symlinked folder exit"
  if [[ -L "${dir}/support/hook-guardian" || ! -d "${dir}/support/hook-guardian" ]]; then
    _fail "hook-guardian folder was not recreated as a directory"
  fi
  assert_file_mode "${elsewhere}" 700
  if [[ -e "${elsewhere}/targets.yaml" ]]; then
    _fail "manifest was written through the symlink"
  fi
  assert_contains "${err}" "defenseclaw_boundary" "boundary marker"
  assert_contains "${err}" "moved_aside" "moved aside"
}

t_rt_missing_config_is_degraded_not_fatal() {
  _rt_skip_unless_darwin || return 0
  local dir result rc err
  dir="$(mktest_tmp)"
  _rt_fixture "${dir}"
  rm -f "${dir}/support/etc/config.yaml"
  result="$(_rt_run "${dir}")"
  rc="${result%%$'\t'*}"; err="${result#*$'\t'}"
  assert_status "${rc}" 0 "missing config exit"
  assert_contains "${err}" 'defenseclaw_degraded' "degraded marker"
  assert_contains "${err}" 'config missing' "degraded reason"
}

t_rt_missing_library_is_degraded_not_fatal() {
  _rt_skip_unless_darwin || return 0
  local dir result rc err
  dir="$(mktest_tmp)"
  _rt_fixture "${dir}"
  rm -f "${dir}/support/lib/installer_lib.sh"
  result="$(_rt_run "${dir}")"
  rc="${result%%$'\t'*}"; err="${result#*$'\t'}"
  assert_status "${rc}" 0 "missing library exit"
  assert_contains "${err}" 'installer library missing' "degraded reason"
}

t_rt_dscl_read_failure_keeps_previous_manifest() {
  _rt_skip_unless_darwin || return 0
  local dir result rc err previous
  dir="$(mktest_tmp)"
  _rt_fixture "${dir}"
  mkdir -p "${dir}/support/hook-guardian"
  previous=$'version: 1\ntargets:\n  - user: "alice"\n    connector: "claudecode"\n'
  printf '%s' "${previous}" > "${dir}/support/hook-guardian/targets.yaml"
  printf 'root 0\nalice 501\n' > "${dir}/dscl/list"
  touch "${dir}/dscl/readfail"
  result="$(_rt_run "${dir}")"
  rc="${result%%$'\t'*}"; err="${result#*$'\t'}"
  assert_status "${rc}" 0 "dscl read failure exit"
  assert_eq "$(cat "${dir}/support/hook-guardian/targets.yaml")" "${previous%$'\n'}" "previous manifest kept"
  assert_contains "${err}" 'defenseclaw_degraded' "degraded marker"
  assert_not_contains "${err}" 'home_missing' "a failed read is not a missing home"
}

t_rt_filtered_user_skip_once_per_streak() {
  _rt_skip_unless_darwin || return 0
  local dir result err
  dir="$(mktest_tmp)"
  _rt_fixture "${dir}"
  printf 'root 0\nalice 501\n' > "${dir}/dscl/list"
  printf '/Volumes/External/alice' > "${dir}/dscl/home/alice"
  result="$(_rt_run "${dir}")"; err="${result#*$'\t'}"
  assert_contains "${err}" 'defenseclaw_skip path="/Volumes/External/alice" reason="home_outside_users" unit="user:alice"' "first skip"
  result="$(_rt_run "${dir}")"; err="${result#*$'\t'}"
  assert_not_contains "${err}" 'defenseclaw_skip' "second run is quiet"
  printf 'root 0\n' > "${dir}/dscl/list"
  _rt_run "${dir}" >/dev/null
  printf 'root 0\nalice 501\n' > "${dir}/dscl/list"
  result="$(_rt_run "${dir}")"; err="${result#*$'\t'}"
  assert_contains "${err}" 'reason="home_outside_users" unit="user:alice"' "new streak logs again"
  assert_file_mode "${dir}/support/hook-guardian/.enumerator-skips" 600
}

run_case "rt_marker prints the Go resilience format" t_rt_marker_matches_go_format
run_case "dscl failure keeps the previous manifest" t_rt_dscl_failure_keeps_previous_manifest
run_case "dscl read failure keeps the previous manifest" t_rt_dscl_read_failure_keeps_previous_manifest
run_case "unchanged targets.yaml is re-stamped" t_rt_unchanged_manifest_is_restamped
run_case "symlinked hook-guardian folder is never followed" t_rt_symlinked_manifest_dir_is_never_followed
run_case "missing config is degraded, not exit 1" t_rt_missing_config_is_degraded_not_fatal
run_case "missing library is degraded, not exit 1" t_rt_missing_library_is_degraded_not_fatal
run_case "filtered user is skipped once per streak" t_rt_filtered_user_skip_once_per_streak
