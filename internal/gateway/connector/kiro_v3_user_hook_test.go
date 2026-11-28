// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// GAP-1932: the Kiro v3 removal pass claimed any hook command that contained
// kiro-hook.sh, so Setup's repair and Teardown removed a user's own hook of
// that name. It now claims what Setup wrote and DefenseClaw's script shape,
// as the other connectors do; a user's hook stays.
func TestGAP1932KiroV3KeepsAUsersKiroHookScript(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	script := filepath.Join(root, ".defenseclaw", "hooks", kiroHookScriptName)
	hookScript := kiroHookInvocationCommandFor("linux", script, KiroHookSurfaceV3, false)
	v3 := func(name, command string) map[string]interface{} {
		return map[string]interface{}{"name": name, "action": map[string]interface{}{"type": "command", "command": command}}
	}
	claimed := map[string]map[string]interface{}{
		"Setup's entry":                        v3("defenseclaw-pre-tool", hookScript),
		"renamed, current command":             v3("mine", hookScript),
		"renamed, unquoted pre-GAP-0382 form":  v3("mine", script+" --hook-surface v3"),
		"renamed, current command, no surface": v3("mine", script),
		"another data dir":                     v3("mine", "/home/other/.defenseclaw/hooks/kiro-hook.sh --hook-surface v3"),
		"edited data dir":                      v3("mine", "/home/other/.defenseclaw-old/hooks/kiro-hook.sh"),
		"Windows data dir":                     v3("mine", `C:\Users\other\.defenseclaw\hooks\kiro-hook.sh --hook-surface v3`),
		"a copy with the binding":              v3("mine", "/opt/old/kiro-hook.sh --hook-surface v3"),
		"native launcher":                      v3("mine", `"C:\Program Files\DefenseClaw\defenseclaw-hook.exe" hook --connector kiro`),
	}
	if runtime.GOOS == "windows" {
		// A Windows bridge Setup wrote, for a launcher DefenseClaw installs.
		claimed["Windows bridge"] = v3("mine", kiroWindowsOwnedHookCommands()[0])
	}
	kept := map[string]map[string]interface{}{
		"Windows path outside .defenseclaw":  v3("user", `C:\Users\me\hooks\kiro-hook.sh`),
		"POSIX path with an argument":        v3("user", "/home/me/bin/kiro-hook.sh --flag"),
		"a longer name and a second command": v3("user", "my-kiro-hook.sh; echo"),
		"a bare name":                        v3("user", "kiro-hook.sh"),
		"a shell wrapper":                    v3("user", `bash C:\Users\me\.defenseclaw\hooks\kiro-hook.sh`),
		"POSIX path outside .defenseclaw":    v3("user", "/home/me/bin/kiro-hook.sh"),
	}
	for name, item := range claimed {
		if !kiroOwnedV3Hook(item, hookScript) {
			t.Errorf("%s: the Kiro v3 removal pass kept DefenseClaw's entry %v", name, item)
		}
	}
	for name, item := range kept {
		if kiroOwnedV3Hook(item, hookScript) {
			t.Errorf("%s: the Kiro v3 removal pass claimed the user's hook %v", name, item)
		}
	}
}
