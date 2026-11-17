// Scratch code-close probes, round 2 (S7 lane s7-probe1, test-only branch
// s7/ccprobes-1). Old-API behaviour probes through the gateway hook route:
// red at the pre-fix sha, green at rel. A control that does not hold on a
// tree skips the probe (never a false red). Self-contained: no helper from
// zz_ccprobes1_test.go, so this file alone is overlaid on a pre-fix tree.

package gateway

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// ccp1bNetExecDefender is the NetExec -x call of the gw8 red (same text as
// netExecDefenderCommand, kept here so the probe needs no other test file).
const ccp1bNetExecDefender = `nxc smb 192.0.2.10 -u fixture-user -H REDACTED_SECRET_0001 --exec-method smbexec -x 'powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true; Set-MpPreference -DisableIOAVProtection $true; Set-MpPreference -DisableScriptScanning $true"'`

// rel-1-0-10:GAP-0329 (P1 security, Windows only): the Codex hook route on
// native Windows keeps tamper.windows_defender_multi_control_disable for the
// NetExec -x PowerShell call in every pack (default/permissive alert HIGH,
// strict block CRITICAL). Pre-fix the PowerShell parse was authoritative, the
// hook picked the PowerShell dialect and the Defender finding was lost. The
// dialect choice runs on Windows only, so the probe runs there only.
func TestCCP1GAP0329CodexHookKeepsDefenderTamperOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("the Windows hook dialect selection runs on native Windows only")
	}
	for _, profile := range []struct{ name, action, severity string }{
		{"default", "alert", "HIGH"},
		{"permissive", "alert", "HIGH"},
		{"strict", "block", "CRITICAL"},
	} {
		profile := profile
		t.Run(profile.name, func(t *testing.T) {
			const connector = "codex"
			installToolCallCorpusProfileConnector(t, connector, profile.name)
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = connector
			cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), profile.name)
			response := (&APIServer{scannerCfg: cfg}).evaluateCodexHook(t.Context(), codexHookRequest{
				HookEventName: "PreToolUse",
				ToolName:      "shell",
				CWD:           "/repo",
				ToolInput:     map[string]interface{}{"command": ccp1bNetExecDefender},
			})
			if response.Action != profile.action || response.Severity != profile.severity ||
				!findingStringHasRuleID(response.Findings, "tamper.windows_defender_multi_control_disable") {
				t.Errorf("codex/%s: action %q severity %q findings %v, want %s/%s with the Defender tamper rule",
					profile.name, response.Action, response.Severity, response.Findings, profile.action, profile.severity)
			}
		})
	}
}

// rel-1-0-10:GAP-0654 (P2 security): an awk program with a regular
// expression literal (holding a double quote) after + - * % ^ < > or ) and
// then a system() call reaches the rule in every cell, as the direct command
// does. Pre-fix the tokenizer read the slash as division, so the quote opened
// a fake string that hid the system() call and the managed cells allowed it.
func TestCCP1GAP0654AwkRegexAfterOperatorReachesTheRule(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX managed hook fixture")
	}
	rows := map[string]string{
		"A42": `awk 'BEGIN{ y = 1 + /"/; system("touch keylink"); y = 1 + /"/ }'`,
		"A43": `awk 'BEGIN{ if (1) /"/; system("touch keylink"); if (1) /"/ }'`,
		"A44": `awk 'BEGIN{ y = 1 < /"/; system("touch keylink"); y = 1 < /"/ }'`,
		"A45": `awk 'BEGIN{ y = 2 * /"/; system("touch keylink"); y = 2 * /"/ }'`,
		"B39": `awk 'BEGIN{ y = 1 - /"/; system("touch keylink"); y = 1 - /"/ }'`,
		"B41": `awk 'BEGIN{ print > "/dev/null"; y = 3 % /"/; system("touch keylink"); y = 3 % /"/ }'`,
		"B42": `awk 'BEGIN{ y = 3 ^ /"/; system("touch keylink"); y = 3 ^ /"/ }'`,
		"B43": `awk 'BEGIN{ y = 3 > /"/; system("touch keylink"); y = 3 > /"/ }'`,
	}
	const direct = "touch keylink"
	for _, pack := range []string{"default", "permissive", "strict"} {
		t.Run(pack, func(t *testing.T) {
			f := awkPackFixture(t, pack)
			commands := []string{direct}
			for _, id := range []string{"A42", "A43", "A44", "A45", "B39", "B41", "B42", "B43"} {
				commands = append(commands, rows[id])
			}
			got := awkVerdicts(t, f, commands)
			for _, call := range got[direct] {
				if call.verdict != "block" {
					t.Skipf("control: the direct command %s is %s on this tree, want block", call.name, call.verdict)
				}
			}
			for _, id := range []string{"A42", "A43", "A44", "A45", "B39", "B41", "B42", "B43"} {
				for _, call := range got[rows[id]] {
					if call.verdict != "block" {
						t.Errorf("%s %s cell=%s managed=%v: %s, want block as the direct command",
							pack, id, call.connector, call.managed, call.verdict)
					}
				}
			}
		})
	}
}
