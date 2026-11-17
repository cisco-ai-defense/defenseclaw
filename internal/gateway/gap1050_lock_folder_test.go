// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"slices"
	"strings"
	"testing"
)

// rel-1-0-10:GAP-1050. After a dynamic eval or source (code the walk cannot
// read, which may change the folder) every write to a target built at run
// time was held as a possible authorized_keys write, so a benign lock script
// (a lock folder made with mktemp, its pid file written and the folder
// removed) blocked with persistence.ssh_authorized_keys_command though it
// names no SSH path. A target whose last element is fixed text naming
// another file names that file wherever the shell is, as a static relative
// name already did: such a call keeps its CMD-EVAL reading and nothing more.
// A target that may still name an authorized-keys or SSH control file (the
// name in any case or with a trailing dot, a pattern, a dynamic or quoted
// last element, "..") blocks in every tier as before.
func TestGAP1050LockFolderAfterDynamicEvalIsNoKeysWrite(t *testing.T) {
	const keys = "persistence.ssh_authorized_keys_command"
	eval := `eval "$(declare -f probe | sed '1s/probe/probe_orig/')"` + "\n"
	benign := map[string]string{
		"eval lock": eval + `LOCK_DIR="$(mktemp -d /tmp/lockdemo.XXXXXX)/.lock"
mkdir "$LOCK_DIR"
printf '%s\n' "$$" > "$LOCK_DIR/pid"
printf '%s\n' B > "$LOCK_DIR/started"
rm -rf "$LOCK_DIR"`,
		"eval lock in function": eval + `take() {
  printf '%s\n' "$1" > "$LOCK_DIR/proc-start"
}
if ! mkdir "$LOCK_DIR" 2>/dev/null; then take "$$"; fi`,
		"source lock": `source <(sed -n '/^lock()/,/^}/p' scripts/lock.sh)
printf '%s\n' "$$" >> "${LOCK_DIR}"/owner.log`,
		"cd dynamic lock": `cd "$WORK"
printf '%s\n' "$$" > "$LOCK_DIR/pid"`,
	}
	controls := map[string]string{
		"keys":           eval + `printf k >> "$D/authorized_keys"`,
		"keys2":          eval + `printf k >> "$D/authorized_keys2"`,
		"keys case":      eval + `printf k >> "$D/Authorized_Keys"`,
		"keys dot":       eval + `printf k >> "$D/authorized_keys."`,
		"keys quoted":    eval + `printf k >> "$D/authorized_k"'eys'`,
		"keys pattern":   eval + `printf k >> "$D"/authorized_k*`,
		"ssh config":     eval + `printf k > "$D/config"`,
		"dotdot":         eval + `printf k > "$D/x/.."`,
		"dynamic last":   eval + `printf k > "$D/$F"`,
		"cd dynamic":     `cd "$D"` + "\n" + `printf k > "$F"`,
		"cd keys":        `cd "$D"` + "\n" + `printf k > "$F/authorized_keys"`,
		"eval static ok": eval + `printf k >> ~/.ssh/authorized_keys`,
	}
	env := boundedLaneEnv(t)
	for _, tier := range boundedTestTiers {
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		for name, command := range benign {
			action, findings := boundedDecideClaudeCode(t, api, env, boundedShellCommand(command))
			if slices.ContainsFunc(findings, func(f string) bool { return strings.HasPrefix(f, keys+":") }) {
				t.Errorf("%s %s: %s with %v, want no SSH authorized keys finding", tier.name, name, action, findings)
			}
			if tier.posture != "strict" && action == "block" {
				t.Errorf("%s %s: block %v, want at most the eval alert", tier.name, name, findings)
			}
		}
		for name, command := range controls {
			if action, findings := boundedDecideClaudeCode(t, api, env, boundedShellCommand(command)); action != "block" {
				t.Errorf("%s control %s: %s %v, want block", tier.name, name, action, findings)
			}
		}
	}
}
