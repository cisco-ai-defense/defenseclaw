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
