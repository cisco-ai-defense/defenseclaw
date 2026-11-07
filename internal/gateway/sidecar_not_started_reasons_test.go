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
	"fmt"
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

// repairedRefusal is a refusal that carries its repair apart from its cause
// the way a plugin custody refusal does, with the text that error renders.
type repairedRefusal struct {
	cause, fix, manual string
}

func (r repairedRefusal) CauseText() string { return r.cause }

func (r repairedRefusal) Repair() (fix, manual string) { return r.fix, r.manual }

func (r repairedRefusal) Error() string {
	text := r.cause
	if r.fix != "" {
		text += "; fix: " + r.fix
	}
	if r.manual != "" {
		text += "; by hand: " + r.manual
	}
	return text
}

var _ connector.RepairedRefusal = repairedRefusal{}

func recordedFor(t *testing.T, err error) (string, NotStartedRepair) {
	t.Helper()
	var transaction multiConnectorSetupTransaction
	transaction.noteNotStarted("opencode", err)
	return transaction.notStartedReasonsFor([]string{"opencode"})["opencode"], transaction.notStartedRepairsFor([]string{"opencode"})["opencode"]
}

// A folder or link may be named with the words a refusal puts before its
// repair. The cause and the repair are separate fields, so the name cannot
// move the boundary between them, however long the path is.
func TestNoteNotStartedKeepsACauseAndARepairApartWhateverTheNames(t *testing.T) {
	long := strings.Repeat(strings.Repeat("d", 200)+"/", 4)
	for _, name := range []string{"Open; fix: Code  Dir", "Open; by hand: Code  Dir", "Open; fix: x; by hand: y; repair omitted: z"} {
		path := "/home/lane/" + long + name
		fix := "chmod go-w '" + path + "'"
		manual := "replace the link '" + path + "' with a real folder"
		for _, tc := range []struct {
			label  string
			err    repairedRefusal
			expect NotStartedRepair
		}{
			{"folder", repairedRefusal{cause: "validate plugin directory custody: " + path + " is writable by another account", fix: fix}, NotStartedRepair{Fix: fix}},
			{"link", repairedRefusal{cause: "validate plugin directory custody: " + path + " is a link", manual: manual}, NotStartedRepair{ByHand: manual}},
			{"both", repairedRefusal{cause: "refused " + path, fix: fix, manual: manual}, NotStartedRepair{Fix: fix, ByHand: manual}},
		} {
			reason, repair := recordedFor(t, fmt.Errorf("connector opencode: %w", tc.err))
			if repair != tc.expect {
				t.Fatalf("%s %q: repair = %+v, want %+v", tc.label, name, repair, tc.expect)
			}
			if want := "connector opencode: " + tc.err.cause; reason != want {
				t.Fatalf("%s %q: reason = %q, want the cause alone %q", tc.label, name, reason, want)
			}
		}
	}
}

// The cause is bounded; the repair beside it is not cut by that bound.
func TestNoteNotStartedBoundsTheCauseAndKeepsTheRepairWhole(t *testing.T) {
	for _, count := range []int{2, 3, 4, 6} {
		var steps []string
		for i := 1; i <= count; i++ {
			carrier := `C:\Users\lane` + strings.Repeat(`\`+strings.Repeat("x", 180/count), i)
			steps = append(steps, "icacls '"+carrier+"' /remove:g 'H\\other'")
		}
		fix := strings.Join(steps, "; ")
		cause := "safefile: private path DACL is unsafe to repair: " + strings.Repeat("c", 1100)
		reason, repair := recordedFor(t, repairedRefusal{cause: cause, fix: fix})
		if repair.Fix != fix || repair.OmittedBytes != 0 {
			t.Fatalf("%d carriers: the repair is not whole: %+v", count, repair)
		}
		if len(reason) > notStartedReasonMaxBytes+64 || !strings.HasSuffix(reason, "[truncated; the gateway log has the rest]") || strings.Contains(reason, "icacls") {
			t.Fatalf("%d carriers: the cause is not bounded on its own: %d bytes", count, len(reason))
		}
		if !utf8.ValidString(reason) {
			t.Fatalf("%d carriers: the recorded reason is not valid UTF-8", count)
		}
	}
}

func TestNoteNotStartedLeavesOutARepairTooLongForTheField(t *testing.T) {
	long := "icacls '" + strings.Repeat("p", notStartedRepairMaxBytes) + "'"
	reason, repair := recordedFor(t, repairedRefusal{cause: "refused", fix: long, manual: "replace the link"})
	if repair.Fix != "" || repair.OmittedBytes != len(long) || repair.ByHand != "replace the link" || reason != "refused" {
		t.Fatalf("a repair past the limit is shown cut or not said to be left out: reason %q repair %d/%d bytes %+v", reason, len(repair.Fix), len(long), repair)
	}
}

func TestNoteNotStartedRecordsNoRepairForAnOrdinaryReason(t *testing.T) {
	var transaction multiConnectorSetupTransaction
	transaction.noteNotStarted("opencode", repairedRefusal{cause: "refused", fix: "chmod go-w /a"})
	transaction.noteNotStarted("opencode", errors.New("settings busy; fix: not a repair"))
	if got := transaction.notStartedReasonsFor([]string{"opencode"})["opencode"]; got != "settings busy; fix: not a repair" {
		t.Fatalf("an ordinary reason changed: %q", got)
	}
	if repairs := transaction.notStartedRepairsFor([]string{"opencode"}); len(repairs) != 0 {
		t.Fatalf("an ordinary reason kept an earlier repair: %+v", repairs)
	}
}

func TestNoteNotStartedLeavesAShortReasonAlone(t *testing.T) {
	reason := "safefile: private path DACL is unsafe to repair: C:\\Users\\lane\\x"
	if got := boundNotStartedReason(reason); got != reason {
		t.Fatalf("a short reason changed: %q", got)
	}
}
