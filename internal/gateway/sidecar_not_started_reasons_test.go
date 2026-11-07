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
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// GAP-0620: a connector the start skips (here Codex, whose agent the last
// discovery did not find, so its version is unknown) was only missing from the
// roster, and `defenseclaw setup codex` failed with "roster: active=claudecode;
// expected=claudecode,codex". Health now carries the reason for each skipped
// connector, which setup prints.
func TestRunGuardrailMultiPublishesWhyAConnectorDidNotStart(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("per-user Codex setup on Windows needs protected executable evidence")
	}
	dataDir := testenv.PrivateTempDir(t)
	agentHome := testenv.PrivateTempDir(t)
	codexConfig := filepath.Join(agentHome, ".codex", "config.toml")
	claudeSettings := filepath.Join(agentHome, ".claude", "settings.json")
	for _, path := range []string{codexConfig, claudeSettings} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(codexConfig, []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(claudeSettings, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// The discovery the CLI wrote found Claude Code only.
	if err := os.WriteFile(filepath.Join(dataDir, "agent_discovery.json"),
		[]byte(`{"agents":{"claudecode":{"version":"2.1.307 (Claude Code)"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	prevCodex, prevClaude := connector.CodexConfigPathOverride, connector.ClaudeCodeSettingsPathOverride
	connector.CodexConfigPathOverride, connector.ClaudeCodeSettingsPathOverride = codexConfig, claudeSettings
	t.Cleanup(func() {
		connector.CodexConfigPathOverride, connector.ClaudeCodeSettingsPathOverride = prevCodex, prevClaude
	})
	cfg := &config.Config{
		DataDir: dataDir,
		Gateway: config.GatewayConfig{APIPort: 18973},
		Guardrail: config.GuardrailConfig{
			Enabled: true,
			Mode:    "action",
			Connectors: map[string]config.PerConnectorGuardrailConfig{
				"codex":      {},
				"claudecode": {},
			},
		},
	}
	s := &Sidecar{cfg: cfg, health: NewSidecarHealth(), router: routerWithDefaultRulePack(t)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.runGuardrailMulti(ctx) }()
	deadline := time.Now().Add(time.Minute)
	for s.health.Snapshot().Guardrail.State != StateRunning {
		select {
		case err := <-done:
			cancel()
			t.Fatalf("the guardrail stopped: %v", err)
		case <-time.After(10 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatal("the guardrail did not run within a minute")
		}
	}
	snap := s.health.Snapshot()
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Logf("guardrail exit after cancel: %v", err)
	}
	if running, _ := snap.Guardrail.Details["connectors"].([]string); !reflect.DeepEqual(running, []string{"claudecode"}) {
		t.Fatalf("running = %v, want only claudecode", running)
	}
	reasons, _ := snap.Guardrail.Details[GuardrailNotStartedReasons].(map[string]string)
	if reason := reasons["codex"]; !strings.Contains(reason, "connector codex") || !strings.Contains(reason, "version") {
		t.Fatalf("%s = %v; want the reason Codex did not start", GuardrailNotStartedReasons, reasons)
	}
	if _, ok := reasons["claudecode"]; ok {
		t.Fatalf("%s names a running connector: %v", GuardrailNotStartedReasons, reasons)
	}
}

func TestNoteNotStartedBoundsTheReason(t *testing.T) {
	var transaction multiConnectorSetupTransaction
	transaction.noteNotStarted(" Codex ", errors.New(strings.Repeat("é", notStartedReasonMaxBytes)))
	reason := transaction.notStartedReasonsFor([]string{"codex"})["codex"]
	if len(reason) > notStartedReasonMaxBytes+64 || !strings.HasSuffix(reason, "[truncated; the gateway log has the rest]") {
		t.Fatalf("reason is %d bytes: %q", len(reason), reason[len(reason)-60:])
	}
	if !strings.HasPrefix(reason, "é") || strings.ContainsRune(reason, '�') {
		t.Fatal("the truncated reason is not valid UTF-8 text")
	}
}

// carrierReason is a Windows custody refusal the way the connector renders it:
// the cause, every carrier outermost first, and one icacls step per carrier.
func carrierReason(count, folderLen int) (reason, fix string) {
	var carriers, steps []string
	for i := 1; i <= count; i++ {
		carrier := `C:\Users\lane` + strings.Repeat(`\`+strings.Repeat("x", folderLen/count), i)
		carriers = append(carriers, carrier)
		steps = append(steps, "icacls '"+carrier+"' /remove:g 'H\\other'")
	}
	fix = strings.Join(steps, "; ")
	cause := "safefile: private path DACL is unsafe to repair: " + carriers[count-1] + " (H\\other has write access there)"
	return cause + "; every folder or file to fix, outermost first: " + strings.Join(carriers, ", ") + "; fix: " + fix, fix
}

func TestNoteNotStartedKeepsTheWholeRepairOfALongReason(t *testing.T) {
	for _, count := range []int{2, 3, 4, 6} {
		reason, fix := carrierReason(count, 180)
		var transaction multiConnectorSetupTransaction
		transaction.noteNotStarted("opencode", errors.New(reason))
		got := transaction.notStartedReasonsFor([]string{"opencode"})["opencode"]
		if !strings.HasSuffix(got, "; fix: "+fix) {
			t.Fatalf("%d carriers: the recorded reason does not end with the whole repair: %q", count, got)
		}
		if !utf8.ValidString(got) {
			t.Fatalf("%d carriers: the recorded reason is not valid UTF-8", count)
		}
	}
}

func TestNoteNotStartedKeepsAManualRepairWhole(t *testing.T) {
	steps := "replace the link " + strings.Repeat("/Users/lane/very/long/path/", 20) + "with a real folder"
	reason := "validate plugin directory custody: " + strings.Repeat("x", 1100) + "; by hand: " + steps
	var transaction multiConnectorSetupTransaction
	transaction.noteNotStarted("opencode", errors.New(reason))
	got := transaction.notStartedReasonsFor([]string{"opencode"})["opencode"]
	if !strings.HasSuffix(got, "; by hand: "+steps) || len(got) >= len(reason) {
		t.Fatalf("the manual repair is not whole after the cause was bounded: %q", got)
	}
}

func TestNoteNotStartedLeavesOutARepairTooLongForTheField(t *testing.T) {
	reason := "validate plugin directory custody: refused; fix: icacls '" + strings.Repeat("p", notStartedRepairMaxBytes) + "'"
	var transaction multiConnectorSetupTransaction
	transaction.noteNotStarted("opencode", errors.New(reason))
	got := transaction.notStartedReasonsFor([]string{"opencode"})["opencode"]
	if strings.Contains(got, "icacls") || strings.Contains(got, "ppp") || !strings.Contains(got, "; repair omitted: ") || !strings.Contains(got, "gateway log has it whole") {
		t.Fatalf("a repair past the limit is shown cut or not said to be left out: %q", got)
	}
}

func TestNoteNotStartedLeavesAShortReasonAlone(t *testing.T) {
	reason, _ := carrierReason(2, 60)
	if len(reason) > notStartedReasonMaxBytes {
		t.Fatalf("test reason is %d bytes, want a short one", len(reason))
	}
	if got := boundNotStartedReason(reason); got != reason {
		t.Fatalf("a short reason changed: %q", got)
	}
}
