// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// GAP-0249: an agent that updated in place (npm i -g @openai/codex) no longer
// matches the executable evidence setup sealed. The gateway must not trust the
// new bytes, but the refusal is of that connector alone: failing the refresh
// of an active connector took the whole gateway down, so the hooks of every
// other connector of the account lost their checks. Only that connector is
// not started, its registration is kept for the setup that admits the new
// executable, and the reason names that step.
func TestChangedAgentExecutableOfAnActiveConnectorStopsOnlyThatConnector(t *testing.T) {
	const codexPath = `C:\Users\dcw\AppData\Roaming\npm\node_modules\@openai\codex\codex.exe`
	for _, tc := range []struct {
		name    string
		err     error
		skipped bool
	}{
		{"codex self-update (live shape)", fmt.Errorf(
			"inspect effective Codex managed requirements: selected Codex executable digest does not match protected evidence: %s (%w)",
			codexPath, connector.ErrCodexExecutableChanged), true},
		{"codex evidence bound to an older version", fmt.Errorf(
			"inspect effective Codex managed requirements: selected Codex executable evidence is bound to a different agent version (%w)",
			connector.ErrCodexExecutableChanged), true},
		{"changed executable joined with a failed rollback", errors.Join(
			errors.New("restore hooks.json"),
			fmt.Errorf("selected Codex executable digest does not match protected evidence (%w)", connector.ErrCodexExecutableChanged)), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := multiBootSidecar(t)
			s.cfg.DataDir = testenv.PrivateTempDir(t)
			s.health = NewSidecarHealth()
			t.Setenv("PATH", testenv.PrivateTempDir(t))
			lock := stageAdmissionFixture(t, s.cfg.DataDir)
			if err := connector.SaveHookContractLockEntry(s.cfg.DataDir, lock); err != nil {
				t.Fatal(err)
			}
			if err := connector.SaveActiveConnectors(s.cfg.DataDir, []string{"claudecode", "codex"}); err != nil {
				t.Fatal(err)
			}
			changed := &bootStubConnector{stubConnector: stubConnector{name: "claudecode"}, setupErr: tc.err}
			peer := &bootStubConnector{stubConnector: stubConnector{name: "codex"}}
			got, err := s.setupConnectorsIsolatedTransaction(
				context.Background(), []connector.Connector{changed, peer},
				"tok", "127.0.0.1:0", "127.0.0.1:0", guardrail.NewRulePackCache(),
			)
			if !tc.skipped {
				if err == nil || !strings.Contains(err.Error(), "connector claudecode refresh failed") {
					t.Fatalf("error = %v, want the refresh of the active connector to fail", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("a changed agent executable stopped the start for every connector: %v", err)
			}
			if want := []string{"codex"}; !reflect.DeepEqual(got.succeeded, want) {
				t.Fatalf("survivors = %v, want %v (not started: %v)", got.succeeded, want, got.notStartedReasons)
			}
			if want := []string{"claudecode"}; !reflect.DeepEqual(got.keptRegistrations, want) {
				t.Fatalf("kept registrations = %v, want %v", got.keptRegistrations, want)
			}
			if reason := got.notStartedReasons["claudecode"]; !strings.Contains(reason, "run: defenseclaw setup codex --yes") {
				t.Errorf("reason does not name the setup step: %q", reason)
			}
			if changed.setupCalls != 1 || changed.teardownCalls != 0 {
				t.Errorf("changed connector setup=%d teardown=%d, want 1/0 (keep the earlier hooks)", changed.setupCalls, changed.teardownCalls)
			}
		})
	}
}
