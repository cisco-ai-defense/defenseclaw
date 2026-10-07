#!/bin/sh
# Fleet readiness for the DefenseClaw Tetragon integration, without Ansible.
# It changes nothing on the hosts. Satellite remote execution can run the same
# commands on each host; this script is the ssh version.
#
# Usage: fleet-readiness.sh MODE HOSTFILE
#   MODE      consume, observe or enforce: the mode you want to move to
#   HOSTFILE  one ssh target per line; blank lines and lines starting with # are skipped
#
# Needs key-based ssh to an account that can run sudo without a prompt, and jq here.
# Exit 0 when every host is ready, 1 when a host is not ready, 2 for bad arguments
# or a host that could not be checked.
set -u

GW=/opt/defenseclaw/bin/defenseclaw-gateway
mode=${1:-}
hosts=${2:-}

case "$mode" in
consume | observe | enforce) ;;
*)
	echo "usage: $0 consume|observe|enforce HOSTFILE" >&2
	exit 2
	;;
esac
if [ ! -r "$hosts" ]; then
	echo "$0: cannot read the host file: $hosts" >&2
	exit 2
fi
if ! command -v jq >/dev/null 2>&1; then
	echo "$0: jq is required on this machine" >&2
	exit 2
fi

work=$(mktemp -d) || exit 2
trap 'rm -rf "$work"' EXIT HUP INT TERM

n=0
while IFS= read -r host; do
	case "$host" in
	'' | '#'*) continue ;;
	esac
	n=$((n + 1))
	# -n keeps ssh from reading the host list on standard input.
	ssh -n -o BatchMode=yes -o ConnectTimeout=10 "$host" \
		"sudo $GW enterprise linux tetragon verify --ready-for $mode --json" >"$work/$n.verify" 2>/dev/null
	vrc=$?
	jq -c . "$work/$n.verify" >"$work/$n.verify.json" 2>/dev/null || echo null >"$work/$n.verify.json"
	# The users are each user's burn-in toward enforce (verify reports them
	# for observe and enforce).
	jq -n -c --arg host "$host" --argjson rc "$vrc" --slurpfile verify "$work/$n.verify.json" '
		{
		  host: $host,
		  rc: $rc,
		  failing: [($verify[0].checks // [])[] | select(.status == "fail") | .id],
		  digest: ($verify[0].kernel_policy // ""),
		  users: [($verify[0].users // [])[] | {state: .state, ready: (.ready // false), reset: (.reset // false), monitor_only: (.monitor_only // false)}]
		}' >>"$work/rows.jsonl"
done <"$hosts"

if [ "$n" -eq 0 ]; then
	echo "$0: no hosts in $hosts" >&2
	exit 2
fi

jq -s -r --arg mode "$mode" '
	def unchecked: (.rc != 0 and .rc != 1);
	def ready: (.rc == 0);
	(map(select(unchecked)) | map(.host)) as $unchecked
	| (map(select(unchecked | not) | select(ready | not))) as $notready
	| (map(.users[]?)) as $users
	| (map(select(unchecked | not) | .digest) | unique) as $digests
	| (
	    (.[] | if unchecked then "\(.host): could not be checked (exit \(.rc))"
	           elif ready then "\(.host): ready for \($mode)"
	           else "\(.host): not ready for \($mode): \(if (.failing | length) > 0 then (.failing | join(", ")) else "see tetragon verify" end)" end),
	    "",
	    "Mode checked: \($mode)",
	    "Hosts ready: \(map(select(ready)) | length) of \(length)",
	    "Hosts not ready: \(if ($notready | length) > 0 then ($notready | map(.host) | join(", ")) else "none" end)",
	    "Hosts not checked: \(if ($unchecked | length) > 0 then ($unchecked | join(", ")) else "none" end)",
	    "Users enforcing: \($users | map(select(.state == "enforcing")) | length)",
	    "Users ready for enforce: \($users | map(select(.ready and .state != "enforcing")) | length)",
	    "Users in burn-in: \($users | map(select((.ready or .reset or .monitor_only) | not)) | length)",
	    "Users reset by a hit: \($users | map(select(.reset and (.ready | not) and (.monitor_only | not))) | length)",
	    "Users monitor-only (connector in observe mode): \($users | map(select(.monitor_only)) | length)",
	    "Kernel controls digests: \(if ($digests | length) > 0 then ($digests | join(", ")) else "none" end)\(if ($digests | length) > 1 then " (more than one means hosts run different builds)" else "" end)"
	  )
' "$work/rows.jsonl"

if jq -s -e 'any(.[]; .rc != 0 and .rc != 1)' "$work/rows.jsonl" >/dev/null; then
	exit 2
fi
if jq -s -e 'any(.[]; .rc == 1)' "$work/rows.jsonl" >/dev/null; then
	exit 1
fi
exit 0
