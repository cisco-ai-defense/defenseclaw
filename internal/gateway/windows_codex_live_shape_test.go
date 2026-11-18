// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// The Windows Codex live shape (cert lane L72, Codex 0.169 in native
// PowerShell, per-user install): the hook POSTs a PreToolUse for the tool Bash
// with the PowerShell text in tool_input.command and a Windows cwd, to a
// gateway on a Windows host whose Codex runs shell calls in PowerShell. The
// earlier by-name tests fed other spellings than the ones the live replay
// typed (rel-1-0-10:GAP-0329, GAP-0155, GAP-0161), so these cases send the
// live shape over the hook handler to a gateway that loads the shipped packs
// as an install writes them (the embedded vendor files, not the source tree).

// windowsLiveShapePacks writes the embedded vendor guardrail packs, as the
// native install seeds them, and returns their folder.
func windowsLiveShapePacks(t *testing.T) string {
	t.Helper()
	return guardrailPoliciesRootFrom(t, filepath.Join(t.TempDir(), "no-source-tree"))
}

type windowsLiveShapeVerdict struct {
	Action   string   `json:"action"`
	Severity string   `json:"severity"`
	RuleIDs  []string `json:"rule_ids"`
}

// postWindowsCodexLiveShape sends command as the Windows Codex hook does and
// returns the gateway's answer.
func postWindowsCodexLiveShape(t *testing.T, packDir, command string) windowsLiveShapeVerdict {
	t.Helper()
	installToolCallCorpusPackDirConnector(t, "codex", packDir)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "codex"
	cfg.Guardrail.RulePackDir = packDir
	previousHost, previousShell := windowsHookHost, codexShellRunsPowerShell
	windowsHookHost = func() bool { return true }
	codexShellRunsPowerShell = true
	defer func() { windowsHookHost, codexShellRunsPowerShell = previousHost, previousShell }()
	body, err := json.Marshal(map[string]any{
		"session_id":      "windows-live-shape",
		"turn_id":         "turn-1",
		"hook_event_name": "PreToolUse",
		"cwd":             `C:\Users\fixture\work`,
		"model":           "fixture-model",
		"tool_name":       "Bash",
		"tool_use_id":     "call-1",
		"tool_input":      map[string]any{"command": command},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/codex/hook", strings.NewReader(string(body)))
	setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
	recorder := httptest.NewRecorder()
	(&APIServer{scannerCfg: cfg, health: NewSidecarHealth()}).handleAgentHook("codex").ServeHTTP(recorder, req)
	var got windowsLiveShapeVerdict
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("hook answer %.300q: %v", recorder.Body.String(), err)
	}
	return got
}

// powerShellEncoded is the -EncodedCommand value of script (UTF-16LE, base64).
func powerShellEncoded(script string) string {
	units := utf16.Encode([]rune(script))
	raw := make([]byte, 2*len(units))
	for i, unit := range units {
		binary.LittleEndian.PutUint16(raw[2*i:], unit)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func toolCallCorpusCaseByID(t *testing.T, id string) toolCallCorpusCase {
	t.Helper()
	for _, test := range readJSONL[toolCallCorpusCase](t, "toolcall", "corpus.jsonl") {
		if test.ID == id {
			return test
		}
	}
	t.Fatalf("no corpus case %s", id)
	return toolCallCorpusCase{}
}

// foldDefenderStatements turns the NetExec fixture's body of one
// Set-MpPreference call per control into ONE call with every switch, the
// spelling the L72 replay typed (rel-1-0-10:GAP-0329). It returns the folded
// NetExec command and the folded body.
func foldDefenderStatements(t *testing.T) (netExec, direct string) {
	t.Helper()
	start := strings.Index(netExecDefenderCommand, "Set-MpPreference")
	end := strings.LastIndex(netExecDefenderCommand, `"`)
	if start < 0 || end <= start {
		t.Fatal("NetExec fixture has no Set-MpPreference body")
	}
	body := netExecDefenderCommand[start:end]
	direct = strings.ReplaceAll(body, "; Set-MpPreference", "")
	if strings.Count(direct, "Set-MpPreference") != 1 || strings.Count(direct, " -Disable") != 3 {
		t.Fatalf("folded body has the wrong shape: %d calls", strings.Count(direct, "Set-MpPreference"))
	}
	return strings.Replace(netExecDefenderCommand, body, direct, 1), direct
}

// TestWindowsCodexLiveShapeDefenderMultiControlInOneCall: one Set-MpPreference
// call that disables three controls is the multi-control disable, directly and
// as a NetExec -x body, in every shipped pack (rel-1-0-10:GAP-0329). The
// one-pair grammar of the call left it partial and outside both proofs.
func TestWindowsCodexLiveShapeDefenderMultiControlInOneCall(t *testing.T) {
	root := windowsLiveShapePacks(t)
	netExec, direct := foldDefenderStatements(t)
	for _, pack := range []struct{ name, action, severity string }{
		{"default", "alert", "HIGH"},
		{"permissive", "alert", "HIGH"},
		{"strict", "block", "CRITICAL"},
	} {
		for _, test := range []struct {
			name, command string
			rules         []string
		}{
			{"netexec", netExec, []string{"tamper.windows_defender_multi_control_disable", "credential.directory_ticket_request"}},
			{"direct", direct, []string{"tamper.windows_defender_multi_control_disable"}},
		} {
			t.Run(pack.name+"/"+test.name, func(t *testing.T) {
				got := postWindowsCodexLiveShape(t, filepath.Join(root, pack.name), test.command)
				for _, rule := range test.rules {
					if !slices.Contains(got.RuleIDs, rule) {
						t.Errorf("no %s: %+v", rule, got)
					}
				}
				if got.Action != pack.action || got.Severity != pack.severity {
					t.Errorf("got %s/%s, want %s/%s (%v)", got.Action, got.Severity, pack.action, pack.severity, got.RuleIDs)
				}
			})
		}
		// Below the rule's bar, the same call stays outside it: two controls,
		// and a control bound twice (PowerShell refuses the call).
		words := strings.Fields(direct)
		for name, command := range map[string]string{
			"two controls":         strings.Join(words[:5], " "),
			"one control twice":    strings.Join(append(append([]string(nil), words[:5]...), words[1], words[2]), " "),
			"netexec two controls": strings.Replace(netExec, direct, strings.Join(words[:5], " "), 1),
		} {
			t.Run(pack.name+"/"+name, func(t *testing.T) {
				if got := postWindowsCodexLiveShape(t, filepath.Join(root, pack.name), command); slices.Contains(got.RuleIDs, "tamper.windows_defender_multi_control_disable") {
					t.Errorf("multi-control on %s: %+v", name, got)
				}
			})
		}
	}
}

// TestWindowsCodexLiveShapePaddedHostSwitch: a launcher whose switch word
// carries blanks (" -EncodedCommand", "-ec ", " -Command") runs the same
// script as the unpadded word, because pwsh 7 and Windows PowerShell 5.1 trim
// each host argument before they match it; it gets the unpadded verdict in
// every shipped pack (rel-1-0-10:GAP-0155). psparse had moved padded words
// outside its Static table, and nothing on the live path reads a NotStatic host
// payload, so the hidden script was allowed.
func TestWindowsCodexLiveShapePaddedHostSwitch(t *testing.T) {
	root := windowsLiveShapePacks(t)
	cradle := toolCallCorpusCaseByID(t, "powershell-download-execute").Command
	encoded := powerShellEncoded(cradle)
	for _, pack := range toolCallCorpusProfiles {
		packDir := filepath.Join(root, pack)
		for _, test := range []struct{ name, plain, padded string }{
			{"encoded leading blank", "powershell -EncodedCommand " + encoded, `powershell " -EncodedCommand" ` + encoded},
			{"encoded trailing blank", "powershell -ec " + encoded, `powershell "-ec " ` + encoded},
			{"command leading blank", `powershell -Command "` + cradle + `"`, `powershell " -Command" "` + cradle + `"`},
			{"padded option before the switch", `pwsh -nop -enc ` + encoded, `pwsh " -nop" -enc ` + encoded},
		} {
			t.Run(pack+"/"+test.name, func(t *testing.T) {
				plain := postWindowsCodexLiveShape(t, packDir, test.plain)
				if !slices.Contains(plain.RuleIDs, "CMD-WIN-IWR-IEX") {
					t.Fatalf("the unpadded launcher has no CMD-WIN-IWR-IEX: %+v", plain)
				}
				padded := postWindowsCodexLiveShape(t, packDir, test.padded)
				if padded.Action != plain.Action || padded.Severity != plain.Severity ||
					!slices.Contains(padded.RuleIDs, "CMD-WIN-IWR-IEX") {
					t.Errorf("padded %+v, unpadded %+v", padded, plain)
				}
			})
		}
	}
}

// TestWindowsCodexLiveShapeClaimedRules: each claimed Windows rule of
// rel-1-0-10:GAP-0161 fires on its own attack fixture sent as the Windows Codex
// hook sends a shell call, in the packs its fixture names, and the benign
// single-control maintenance fixture stays allowed (a lone
// Set-MpPreference -Disable* switch is maintenance by the rule's design: the
// multi-control rule needs three controls).
func TestWindowsCodexLiveShapeClaimedRules(t *testing.T) {
	root := windowsLiveShapePacks(t)
	cases := readJSONL[toolCallCorpusCase](t, "toolcall", "corpus.jsonl")
	checked := map[string]bool{}
	for _, pack := range toolCallCorpusProfiles {
		packDir := filepath.Join(root, pack)
		for _, test := range cases {
			if !test.IsAttack || test.Command == "" || len(test.OSOverrides) != 0 ||
				!slices.Contains(windowsNativeFixtureRules, test.RuleID) ||
				test.Dialect == actionfacts.DialectPOSIX ||
				test.ProfilePosture == toolCallCorpusStrictOnlyPosture && pack != "strict" {
				continue
			}
			route := test.ExpectRoute
			if profileRoute := test.ProfileRoutes[pack]; profileRoute != "" {
				route = profileRoute
			}
			if route == "none" || windowsFixtureNotNativeInPowerShell[test.ID] {
				continue
			}
			command := test.Command
			if windowsFixtureViaCmd[test.ID] {
				command = "cmd /c " + command
			}
			checked[test.RuleID] = true
			t.Run(pack+"/"+test.ID, func(t *testing.T) {
				got := postWindowsCodexLiveShape(t, packDir, command)
				if !slices.Contains(got.RuleIDs, test.RuleID) {
					t.Errorf("no %s as a Windows Codex shell call: %+v", test.RuleID, got)
				}
			})
		}
		t.Run(pack+"/single-control maintenance", func(t *testing.T) {
			benign := toolCallCorpusCaseByID(t, "windows-defender-single-control-maintenance")
			if benign.IsAttack {
				t.Fatal("the maintenance fixture is labelled an attack")
			}
			if got := postWindowsCodexLiveShape(t, packDir, benign.Command); got.Action != "allow" ||
				slices.Contains(got.RuleIDs, "tamper.windows_defender_multi_control_disable") {
				t.Errorf("single-control maintenance: %+v", got)
			}
		})
	}
	for _, rule := range windowsNativeFixtureRules {
		if rule == "exfil.literal_sensitive_json_upload" {
			continue // a PS-version-dependent native argv (windowsFixtureNotNativeInPowerShell)
		}
		if !checked[rule] {
			t.Errorf("no attack fixture of %s was sent", rule)
		}
	}
}
