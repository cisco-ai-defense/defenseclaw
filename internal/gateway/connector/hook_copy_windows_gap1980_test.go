// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// GAP-1980: on a Windows host Copilot's Setup registers the PowerShell
// adapter, and copilotBoundEventOwnsCommand then read only the powershell and
// command keys, so a bash-key copy of copilot-hook.sh named by a Windows path
// was kept and the event refused. The doctor reports that copy, so Setup now
// claims it under the adapter too.
func TestGAP1980CopilotAdapterClaimsABashKeyCopy(t *testing.T) {
	const binding = " --event preToolUse"
	adapter := `& 'C:\Users\fx1980me\.defenseclaw\hooks\copilot-hook.ps1'`
	if !isCopilotPowerShellAdapterCommand(adapter) {
		t.Fatalf("fixture: %q is not the PowerShell adapter", adapter)
	}
	claimed := gap1923Claimed(t, "copilot-hook.sh", binding)
	for _, name := range gap1923Names(claimed) {
		if !copilotBoundEventOwnsCommand("bash", claimed[name], adapter) {
			t.Errorf("%s: the adapter repair kept the bash-key copy %q", name, claimed[name])
		}
	}
	kept := gap1923Kept("copilot-hook.sh", binding)
	for _, name := range gap1923Names(kept) {
		if copilotBoundEventOwnsCommand("bash", kept[name], adapter) {
			t.Errorf("%s: the adapter repair claimed the user's bash command %q", name, kept[name])
		}
	}
	// The other keys keep the adapter's own rules.
	if copilotBoundEventOwnsCommand("powershell", claimed["drive, forward slashes"], adapter) {
		t.Error("a copilot-hook.sh copy under the powershell key is not the adapter's")
	}
}

// GAP-1981: on a Windows host the hooks dir is a backslash path, so Setup's
// hooks-dir claim (GAP-1957) never matched a handler named by a drive path in
// it. The doctor reported "2 DefenseClaw handlers", Setup kept the second and
// failed its final check. The claim and the doctor's Windows leg now read the
// path as Windows does.
func TestGAP1981ClaudeCodeHooksDirClaimReadsAWindowsPath(t *testing.T) {
	dataDir := `C:\Users\fx1981me\.defenseclaw`
	if runtime.GOOS == "windows" {
		dataDir = filepath.Join(testenv.PrivateTempDir(t), "fx1981me", ".defenseclaw")
	}
	hooksDir := filepath.Join(dataDir, "hooks")
	if runtime.GOOS != "windows" {
		hooksDir = dataDir + `\hooks`
	}
	forward := strings.ReplaceAll(hooksDir, `\`, "/")
	claimed := map[string]string{
		"forward slashes": forward + "/claude-code-hook.old.sh --event PreToolUse",
		"backslashes":     hooksDir + `\claude-code-hook.sh.bak --event PreToolUse`,
		"other case":      strings.ToUpper(forward) + "/CLAUDE-CODE-HOOK.OLD.SH --event PreToolUse",
		"single-quoted":   "'" + hooksDir + `\claude-code-hook.old.sh' --event PreToolUse`,
	}
	kept := map[string]string{
		"sibling dir":     forward + "-old/claude-code-hook.old.sh --event PreToolUse",
		"dir name prefix": forward + "X/claude-code-hook.old.sh --event PreToolUse",
		"user hook":       `C:/Users/fx1981me/bin/review.sh --event PreToolUse`,
	}
	for _, name := range gap1923Names(claimed) {
		handler := map[string]interface{}{"type": "command", "command": claimed[name]}
		if !isOwnedHookHandler(handler, hooksDir) {
			t.Errorf("%s: Setup kept the handler %q in its own hooks dir", name, claimed[name])
		}
		remaining, err := removeOwnedClaudeCodeHooks([]interface{}{
			map[string]interface{}{"matcher": "*", "hooks": []interface{}{handler}},
		}, hooksDir, nil)
		if err != nil || len(remaining) != 0 {
			t.Errorf("%s: Claude Code's removal kept %q: %v %v", name, claimed[name], remaining, err)
		}
	}
	for _, name := range gap1923Names(kept) {
		if isOwnedHookHandler(map[string]interface{}{"type": "command", "command": kept[name]}, hooksDir) {
			t.Errorf("%s: Setup claimed %q outside its hooks dir", name, kept[name])
		}
	}
	// The doctor reports the forward-slash form, which Setup now removes.
	document := map[string]interface{}{"hooks": map[string]interface{}{"PreToolUse": []interface{}{
		map[string]interface{}{"matcher": "*", "hooks": []interface{}{
			map[string]interface{}{"type": "command", "command": claimed["forward slashes"]},
		}},
	}}}
	if reported, ok := hookDocumentEditedEntry(document, "claudecode", dataDir, "claude-code-hook.sh"); !ok || reported != claimed["forward slashes"] {
		t.Errorf("the doctor reported %q (%v), want the handler Setup removes %q", reported, ok, claimed["forward slashes"])
	}
}
