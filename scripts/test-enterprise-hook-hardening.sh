#!/usr/bin/env bash

set -euo pipefail

fail() {
    printf 'enterprise hook hardening test failed: %s\n' "$*" >&2
    exit 1
}

file_mode() {
    if [ "$(uname -s)" = "Darwin" ]; then
        stat -f '%Lp' "$1"
    else
        stat -c '%a' "$1"
    fi
}

file_mtime() {
    if [ "$(uname -s)" = "Darwin" ]; then
        stat -f '%m' "$1"
    else
        stat -c '%Y' "$1"
    fi
}

file_hash() {
    shasum -a 256 "$1" | awk '{print $1}'
}

file_owner_uid() {
    if [ "$(uname -s)" = "Darwin" ]; then
        stat -f '%u' "$1"
    else
        stat -c '%u' "$1"
    fi
}

protected_file_owner_uid() {
    if [ "$(uname -s)" = "Darwin" ]; then
        sudo -n stat -f '%u' "$1"
    else
        sudo -n stat -c '%u' "$1"
    fi
}

wait_for_file() {
    local path="$1"
    local attempt=0
    while [ "$attempt" -lt 100 ]; do
        [ -f "$path" ] && return 0
        sleep 0.1
        attempt=$((attempt + 1))
    done
    return 1
}

[ "$#" -eq 2 ] || fail "usage: $0 <defenseclaw-gateway-binary> <codex|claudecode>"

connector="$2"

case "$connector" in
    codex)
        agent_version='codex-cli 0.142.0'
        hook_name='codex-hook.sh'
        native_config_rel='.codex/config.toml'
        native_config_seed='model = "gpt-5"'
        hook_request_path='/api/v1/codex/hook'
        hook_payload='{"hook_event_name":"PreToolUse","tool_name":"shell","tool_input":{"command":"printf enterprise-ci"}}'
        ;;
    claudecode)
        agent_version='2.1.187 (Claude Code)'
        hook_name='claude-code-hook.sh'
        native_config_rel='.claude/settings.json'
        native_config_seed='{}'
        hook_request_path='/api/v1/claude-code/hook'
        hook_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"printf enterprise-ci"}}'
        ;;
    *)
        fail "unsupported connector: $connector"
        ;;
esac

[ "$(id -u)" -ne 0 ] || fail "run as a non-root test user"
[ -n "${HOME:-}" ] && [ "$HOME" != '/' ] && [ -d "$HOME" ] && [ ! -L "$HOME" ] || fail "HOME must be a real non-root directory"

source_binary="$(cd "$(dirname "$1")" && pwd -P)/$(basename "$1")"
[ -f "$source_binary" ] && [ ! -L "$source_binary" ] && [ -x "$source_binary" ] || fail "binary must be a regular executable: $source_binary"

sudo -n true || fail "passwordless sudo is required"

case "$(uname -s)" in
    Darwin)
        admin_group='wheel'
        trusted_root='/Library'
        ;;
    Linux)
        admin_group='root'
        trusted_root='/var/lib'
        ;;
    *) fail "unsupported operating system: $(uname -s)" ;;
esac

run_id="$$"
root_prefix="${trusted_root}/defenseclaw-enterprise-ci-${connector}-${run_id}"
target_home="${HOME}/.defenseclaw-enterprise-ci-${connector}-${run_id}"
root_binary="${root_prefix}/bin/defenseclaw-gateway"
service_data="${root_prefix}/runtime"
auth_dir="${root_prefix}/hook-guardian-state"
config_path="${root_prefix}/config.yaml"
manifest_path="${root_prefix}/targets.yaml"
user_data="${target_home}/.defenseclaw"
hook_dir="${user_data}/hooks"
hook_script="${hook_dir}/${hook_name}"
user_token="${hook_dir}/.hook-${connector}.token"
service_token="${service_data}/hooks/.hook-${connector}.token"
native_config="${target_home}/${native_config_rel}"
auth_record="${auth_dir}/protected_targets.json"
server_ready="${target_home}/fake-gateway.ready"
server_result="${target_home}/fake-gateway-result.json"
fake_server_pid=''

cleanup() {
    local status=$?
    trap - EXIT
    if [ -n "$fake_server_pid" ] && kill -0 "$fake_server_pid" 2>/dev/null; then
        kill "$fake_server_pid" 2>/dev/null || true
        wait "$fake_server_pid" 2>/dev/null || true
    fi
    sudo -n rm -rf -- "$root_prefix" >/dev/null 2>&1 || true
    rm -rf -- "$target_home"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

rm -rf -- "$target_home"
install -d -m 0700 "$target_home" "$(dirname "$native_config")"
printf '%s\n' "$native_config_seed" >"$native_config"
chmod 0600 "$native_config"

TOKEN_PATH="$user_token" \
EXPECTED_PATH="$hook_request_path" \
SERVER_READY="$server_ready" \
SERVER_RESULT="$server_result" \
python3 - <<'PY' &
import json
import os
import pathlib
from http.server import BaseHTTPRequestHandler, HTTPServer

expected_path = os.environ["EXPECTED_PATH"]
result_path = os.environ["SERVER_RESULT"]
token_path = os.environ["TOKEN_PATH"]


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        try:
            parsed = json.loads(body)
            body_ok = isinstance(parsed, dict)
        except json.JSONDecodeError:
            body_ok = False
        expected_token = pathlib.Path(token_path).read_text(encoding="utf-8").rstrip("\n")
        auth_ok = self.headers.get("Authorization") == f"Bearer {expected_token}"
        path_ok = self.path == expected_path
        result = {
            "auth_ok": auth_ok,
            "path_ok": path_ok,
            "body_ok": body_ok,
            "path": self.path,
        }
        with open(result_path, "w", encoding="utf-8") as handle:
            json.dump(result, handle)
        self.send_response(200 if auth_ok and path_ok and body_ok else 401)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"action":"allow"}')

    def log_message(self, *_args):
        return


server = HTTPServer(("127.0.0.1", 0), Handler)
with open(os.environ["SERVER_READY"], "w", encoding="utf-8") as handle:
    handle.write(f"{server.server_port}\n")
server.handle_request()
server.server_close()
PY
fake_server_pid=$!
wait_for_file "$server_ready" || fail "fake gateway did not start"
api_port="$(cat "$server_ready")"
case "$api_port" in
    ''|*[!0-9]*) fail "fake gateway returned an invalid port: $api_port" ;;
esac

[ -d "$trusted_root" ] && [ ! -L "$trusted_root" ] || fail "$trusted_root must be a real directory"

sudo -n install -d -o root -g "$admin_group" -m 0755 \
    "$root_prefix" "${root_prefix}/bin" "$auth_dir"
sudo -n install -d -o root -g "$admin_group" -m 0700 "$service_data"
sudo -n install -o root -g "$admin_group" -m 0755 "$source_binary" "$root_binary"

config_tmp="${target_home}/config.yaml"
cat >"$config_tmp" <<EOF
config_version: 7
deployment_mode: managed_enterprise
data_dir: ${service_data}
audit_db: ${service_data}/audit.db
judge_bodies_db: ${service_data}/judge_bodies.db
plugin_dir: ${service_data}/plugins
policy_dir: ${service_data}/policies
gateway:
  api_bind: 127.0.0.1
  api_port: ${api_port}
guardrail:
  enabled: true
  mode: action
  hook_fail_mode: closed
  scanner_mode: both
application_protection:
  enabled: false
EOF
sudo -n install -o root -g "$admin_group" -m 0600 "$config_tmp" "$config_path"
rm -f "$config_tmp"

uid="$(id -u)"
gid="$(id -g)"
manifest_tmp="${target_home}/targets.yaml"
cat >"$manifest_tmp" <<EOF
version: 1
targets:
  - user_home: ${target_home}
    uid: ${uid}
    gid: ${gid}
    connector: ${connector}
    data_dir: ${user_data}
    agent_version: "${agent_version}"
EOF
sudo -n install -o root -g "$admin_group" -m 0600 "$manifest_tmp" "$manifest_path"
rm -f "$manifest_tmp"

run_reconcile() {
    sudo -n /usr/bin/env \
        DEFENSECLAW_CONFIG="$config_path" \
        DEFENSECLAW_HOME="$service_data" \
        DEFENSECLAW_DEPLOYMENT_MODE=managed_enterprise \
        DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR="$auth_dir" \
        "$root_binary" enterprise hooks reconcile \
        --manifest "$manifest_path" \
        --json
}

run_reconcile >"${target_home}/reconcile-initial.json"

[ -f "$hook_script" ] || fail "managed hook was not installed"
[ -f "$user_token" ] || fail "connector-scoped user token was not installed"
sudo -n test -f "$service_token" || fail "connector-scoped service token was not created"
[ -f "$auth_record" ] || fail "root-owned authorization record was not created"
[ "$(file_mode "$hook_script")" = '700' ] || fail "hook mode is not 0700"
[ "$(file_mode "$user_token")" = '600' ] || fail "user token mode is not 0600"
[ "$(file_mode "$native_config")" = '600' ] || fail "native config mode is not 0600"
[ "$(file_owner_uid "$hook_script")" = "$uid" ] || fail "hook owner does not match the target user"
[ "$(file_owner_uid "$user_token")" = "$uid" ] || fail "user token owner does not match the target user"
[ "$(file_owner_uid "$native_config")" = "$uid" ] || fail "native config owner does not match the target user"
[ ! -e "${hook_dir}/.token" ] || fail "legacy shared token was written"
[ "$(wc -l <"$user_token" | tr -d ' ')" = '1' ] || fail "scoped token is not one raw line"
! grep -q '^DEFENSECLAW_GATEWAY_TOKEN=' "$user_token" || fail "scoped token used legacy assignment format"
grep -Fq "$hook_script" "$native_config" || fail "native agent config does not reference the managed hook"
sudo -n cmp -s "$service_token" "$user_token" || fail "service and user scoped tokens differ"

python3 - "$auth_record" "$connector" "$target_home" <<'PY'
import json
import pathlib
import sys

record = json.loads(pathlib.Path(sys.argv[1]).read_text())
connector, user_home = sys.argv[2:]
targets = record.get("protected_targets", [])
if not any(
    target.get("ok") is True
    and target.get("connector") == connector
    and target.get("user_home") == user_home
    for target in targets
):
    raise SystemExit("authorization record does not contain the protected target")
PY

for protected_path in "$root_binary" "$config_path" "$manifest_path" "$service_token" "$auth_record"; do
    [ "$(protected_file_owner_uid "$protected_path")" = '0' ] || fail "protected path is not root-owned: $protected_path"
    [ ! -w "$protected_path" ] || fail "standard user can write protected path: $protected_path"
done
if rm -f "$root_binary" 2>/dev/null; then
    fail "standard user removed the root-owned binary"
fi
if (printf 'tamper\n' >>"$manifest_path") 2>/dev/null; then
    fail "standard user modified the root-owned manifest"
fi
if cat "$service_token" >/dev/null 2>&1; then
    fail "standard user read the root-owned service token"
fi

canonical_hook_hash="$(file_hash "$hook_script")"
printf '#!/bin/sh\nexit 0\n' >"$hook_script"
chmod 4777 "$hook_script"
printf 'attacker-controlled-token\n' >"$user_token"
printf '%s\n' "$native_config_seed" >"$native_config"
chmod 0777 "$native_config"

run_reconcile >"${target_home}/reconcile-regular-tamper.json"

[ "$(file_hash "$hook_script")" = "$canonical_hook_hash" ] || fail "regular-file hook tamper was not repaired"
[ "$(file_mode "$hook_script")" = '700' ] || fail "hook special/writable mode was not normalized"
[ "$(file_mode "$user_token")" = '600' ] || fail "token mode was not normalized"
[ "$(file_mode "$native_config")" = '600' ] || fail "native config mode was not normalized"
sudo -n cmp -s "$service_token" "$user_token" || fail "user token tamper was not repaired"
grep -Fq "$hook_script" "$native_config" || fail "native hook wiring tamper was not repaired"

hook_decoy="${target_home}/hook-decoy"
config_decoy="${target_home}/config-decoy"
printf 'hook decoy must remain unchanged\n' >"$hook_decoy"
printf 'config decoy must remain unchanged\n' >"$config_decoy"
hook_decoy_hash="$(file_hash "$hook_decoy")"
config_decoy_hash="$(file_hash "$config_decoy")"
rm -f "$hook_script" "$native_config"
ln -s "$hook_decoy" "$hook_script"
ln -s "$config_decoy" "$native_config"

run_reconcile >"${target_home}/reconcile-symlink-tamper.json"

[ ! -L "$hook_script" ] && [ -f "$hook_script" ] || fail "hook symlink was not replaced safely"
[ ! -L "$native_config" ] && [ -f "$native_config" ] || fail "native config symlink was not replaced safely"
[ "$(file_hash "$hook_script")" = "$canonical_hook_hash" ] || fail "canonical hook was not restored after symlink tamper"
[ "$(file_hash "$hook_decoy")" = "$hook_decoy_hash" ] || fail "hook symlink target was modified"
[ "$(file_hash "$config_decoy")" = "$config_decoy_hash" ] || fail "config symlink target was modified"
grep -Fq "$hook_script" "$native_config" || fail "native hook wiring was not restored after symlink tamper"

touch -t 200001010000 "$hook_script" "$user_token" "$native_config"
hook_mtime="$(file_mtime "$hook_script")"
token_mtime="$(file_mtime "$user_token")"
config_mtime="$(file_mtime "$native_config")"
run_reconcile >"${target_home}/reconcile-noop.json"
[ "$(file_mtime "$hook_script")" = "$hook_mtime" ] || fail "no-op reconcile rewrote the hook"
[ "$(file_mtime "$user_token")" = "$token_mtime" ] || fail "no-op reconcile rewrote the scoped token"
[ "$(file_mtime "$native_config")" = "$config_mtime" ] || fail "no-op reconcile rewrote the native config"

hook_stdout="${target_home}/hook.stdout"
hook_stderr="${target_home}/hook.stderr"
if ! printf '%s\n' "$hook_payload" | \
    HOME="$target_home" DEFENSECLAW_GATEWAY_TOKEN='attacker-inherited-token' \
    "$hook_script" >"$hook_stdout" 2>"$hook_stderr"; then
    cat "$hook_stderr" >&2
    fail "managed hook did not complete an allow request"
fi
wait_for_file "$server_result" || fail "managed hook did not reach the fake gateway"
wait "$fake_server_pid"
fake_server_pid=''
[ ! -s "$hook_stdout" ] || fail "allow response unexpectedly wrote agent output"
[ ! -s "$hook_stderr" ] || fail "allow response unexpectedly wrote an error"

python3 - "$server_result" <<'PY'
import json
import pathlib
import sys

result = json.loads(pathlib.Path(sys.argv[1]).read_text())
if not all(result.get(key) is True for key in ("auth_ok", "path_ok", "body_ok")):
    raise SystemExit(f"managed hook request failed validation: {result}")
PY

printf 'enterprise hook hardening passed: os=%s connector=%s\n' "$(uname -s)" "$connector"
