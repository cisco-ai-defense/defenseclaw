// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestToolArgumentSpellingsWithOneValue pins GAP-0696: a shell call that
// names one argument under two spellings with the same value (command and
// cmd, Command or script; cwd and workdir) is the one call it names. A
// benign one is allowed, a dangerous one is blocked by its own rule, and
// neither takes the conflict finding. Two different values stay a conflict
// (GAP-0678, GAP-0694).
func TestToolArgumentSpellingsWithOneValue(t *testing.T) {
	wipe := conflictingKeysQuote("rm -rf ~/")
	for _, c := range []struct {
		name, connector, tool, args string
		block, conflict             bool
		rule                        string
	}{
		{"command+cmd", "claudecode", "Bash", `{"command":"ls -la","cmd":"ls -la"}`, false, false, ""},
		{"command+Command", "claudecode", "Bash", `{"command":"ls -la","Command":"ls -la"}`, false, false, ""},
		{"command+script", "claudecode", "Bash", `{"command":"ls -la","script":"ls -la"}`, false, false, ""},
		{"cwd+workdir", "claudecode", "Bash", `{"command":"ls -la","cwd":"{PROJ}","workdir":"{PROJ}"}`, false, false, ""},
		{"command+cmd escaped", "claudecode", "Bash", `{"command":"ls -la","cmd":"\u006cs -la"}`, false, false, ""},
		{"codex command+cmd", "codex", "Bash", `{"command":"ls -la","cmd":"ls -la"}`, false, false, ""},
		{"opencode command+cmd", "opencode", "shell", `{"command":"ls -la","cmd":"ls -la"}`, false, false, ""},
		{"same value dangerous", "claudecode", "Bash", `{"command":` + wipe + `,"cmd":` + wipe + `}`, true, false, "CMD-RM-RF"},
		{"same value dangerous Command", "claudecode", "Bash", `{"command":` + wipe + `,"Command":` + wipe + `}`, true, false, "CMD-RM-RF"},
		{"different values", "claudecode", "Bash", `{"command":"ls -la","cmd":"true"}`, true, true, ""},
		{"different values dangerous", "claudecode", "Bash", `{"command":"true","Command":` + wipe + `}`, true, true, "CMD-RM-RF"},
		{"different cwd", "claudecode", "Bash", `{"command":"ls -la","cwd":"{PROJ}","workdir":"/tmp"}`, true, true, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			home, project := conflictingKeysHome(t)
			args := strings.ReplaceAll(c.args, "{PROJ}", project)
			resp := conflictingKeysHook(t, "action", c.connector, c.tool, home, project, args)
			raw, _ := json.Marshal(resp)
			if got := resp["action"] == "block"; got != c.block {
				t.Fatalf("blocked = %t, want %t: %.800s", got, c.block, raw)
			}
			if got := strings.Contains(string(raw), conflictingToolArgumentsRuleID); got != c.conflict {
				t.Fatalf("names %s = %t, want %t: %.800s", conflictingToolArgumentsRuleID, got, c.conflict, raw)
			}
			if c.rule != "" && !strings.Contains(string(raw), c.rule) {
				t.Fatalf("response does not name %s: %.800s", c.rule, raw)
			}
		})
	}
}
