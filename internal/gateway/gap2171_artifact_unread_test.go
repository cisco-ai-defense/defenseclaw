// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// rel-1-0-10:GAP-2171: the artifact check reads a script a tool call runs
// within promotedArtifactReadLimit and with promotedArtifactMaxReaders
// readers. A script it could not read in time (every reader busy, a slow
// read, the hook budget ended) was dropped without a finding, so the raise
// it gives on a quiet gateway (a block for a destructive script) was lost on
// a busy or loaded one. A script left unread in time now gets the answer of
// an unread script (appendArtifactUnreadFindings): the evaluation-limit
// block in the strict tier, a visible alert in the others. A readable
// script's verdict is unchanged, and a benign script left unread is an
// alert, never a block.

// gap2171Script writes a script the artifact check reads and returns the
// facts of the call that runs it.
func gap2171Script(t *testing.T, name, body string) actionfacts.Facts {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	return actionfacts.Analyze(actionfacts.Input{
		Tool: "shell", Command: fmt.Sprintf("bash %q", path), CWD: dir,
	})
}

func gap2171Destructive() string { return "#!/bin/sh\nrm -rf" + " /\n" }

const gap2171Benign = "#!/bin/sh\nprintf '%s\\n' build-complete\n"

// gap2171HoldReaders takes every artifact reader until release is called.
func gap2171HoldReaders(t *testing.T) (release func()) {
	t.Helper()
	for range promotedArtifactMaxReaders {
		select {
		case promotedArtifactReadSlots <- struct{}{}:
		case <-time.After(5 * time.Second):
			t.Fatal("artifact readers never came free")
		}
	}
	var once sync.Once
	release = func() {
		once.Do(func() {
			for range promotedArtifactMaxReaders {
				<-promotedArtifactReadSlots
			}
		})
	}
	t.Cleanup(release)
	return release
}

func TestGAP2171BusyReadersNeverDropTheRaise(t *testing.T) {
	requireNativePOSIXArtifactHost(t)
	const connectorName = "gap2171-artifact-unread"
	installDefaultProfileConnector(t, connectorName)
	req := agentHookRequest{ConnectorName: connectorName}
	destructive := gap2171Script(t, "cleanup.sh", gap2171Destructive())
	benign := gap2171Script(t, "build.sh", gap2171Benign)

	t.Run("quiet: the script's own raise", func(t *testing.T) {
		findings := promotedArtifactFindings(t.Context(), req, destructive, true, nil)
		if f := findingWithID(findings, "CMD-RM-RF"); f == nil || !f.contributesToEnforcement() {
			t.Fatalf("quiet read lost the block: %v", FindingStrings(findings))
		}
		if findingWithID(findings, artifactUnreadRuleID) != nil {
			t.Fatalf("a script read in time is reported unread: %v", FindingStrings(findings))
		}
		if got := promotedArtifactFindings(t.Context(), req, benign, true, nil); len(got) != 0 {
			t.Fatalf("benign twin: %v", FindingStrings(got))
		}
	})

	t.Run("a reader comes free within the limit: the script's own raise", func(t *testing.T) {
		release := gap2171HoldReaders(t)
		timer := time.AfterFunc(50*time.Millisecond, release)
		defer timer.Stop()
		findings := promotedArtifactFindings(t.Context(), req, destructive, true, nil)
		if f := findingWithID(findings, "CMD-RM-RF"); f == nil || !f.contributesToEnforcement() {
			t.Fatalf("a short wait for a reader dropped the block: %v", FindingStrings(findings))
		}
	})

	t.Run("no reader within the limit: reported unread", func(t *testing.T) {
		gap2171HoldReaders(t)
		for _, tc := range []struct {
			name  string
			facts actionfacts.Facts
		}{{"destructive", destructive}, {"benign twin", benign}} {
			findings := promotedArtifactFindings(t.Context(), req, tc.facts, true, nil)
			unread := findingWithID(findings, artifactUnreadRuleID)
			if unread == nil {
				t.Fatalf("%s: unread script dropped without a finding: %v", tc.name, FindingStrings(findings))
			}
			if unread.contributesToEnforcement() || !unread.contributesToAlertOnly() {
				t.Fatalf("%s: unread script must alert, never block, outside strict: %+v", tc.name, *unread)
			}
		}
	})

	t.Run("hook budget ended: reported unread", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		findings := promotedArtifactFindings(ctx, req, destructive, true, nil)
		if findingWithID(findings, artifactUnreadRuleID) == nil {
			t.Fatalf("expired budget dropped the script without a finding: %v", FindingStrings(findings))
		}
	})

	t.Run("strict tier: evaluation-limit block", func(t *testing.T) {
		gap2171HoldReaders(t)
		ctx := withShareBodyStrict(t.Context(), func() bool { return true })
		findings := promotedArtifactFindings(ctx, req, destructive, true, nil)
		limit := findingWithID(findings, "ACTION-COMPOUND-LIMIT")
		if limit == nil || !limit.contributesToEnforcement() || limit.Evidence != artifactUnreadReason {
			t.Fatalf("strict unread script: %v", FindingStrings(findings))
		}
		if findingWithID(findings, artifactUnreadRuleID) != nil {
			t.Fatalf("strict unread script carries the alert as well: %v", FindingStrings(findings))
		}
	})
}

// The hook answer at shipped defaults: a destructive script is blocked when
// read, and an unread one (destructive or benign) is an alert, never an
// allow without a word and never a block.
func TestGAP2171UnreadScriptHookAnswer(t *testing.T) {
	requireNativePOSIXArtifactHost(t)
	const connectorName = "claudecode"
	installDefaultProfileConnector(t, connectorName)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connectorName
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "default")
	api := &APIServer{scannerCfg: cfg}
	profile := api.hookProfileForConnector(connectorName)
	answer := func(facts actionfacts.Facts) agentHookResponse {
		capture := &toolChainHookCapture{}
		capture.recordTrustedAction(facts, nil)
		req := agentHookRequest{
			ConnectorName: connectorName, HookEventName: "PreToolUse",
			SuppressCorrelationEmit: true, toolChain: capture,
		}
		original := agentHookResponse{
			Action: guardrailActionAllow, RawAction: guardrailActionAllow,
			Severity: "NONE", Mode: "action",
		}
		return api.safeApplyExperimentalArtifactPromotion(t.Context(), profile, req, original, 0)
	}
	destructive := gap2171Script(t, "cleanup.sh", gap2171Destructive())
	benign := gap2171Script(t, "build.sh", gap2171Benign)
	if got := answer(destructive); got.Action != guardrailActionBlock {
		t.Fatalf("read destructive script: %+v, want block", got)
	}
	if got := answer(benign); got.Action != guardrailActionAllow {
		t.Fatalf("read benign twin: %+v, want allow", got)
	}
	gap2171HoldReaders(t)
	for _, tc := range []struct {
		name  string
		facts actionfacts.Facts
	}{{"destructive", destructive}, {"benign twin", benign}} {
		got := answer(tc.facts)
		if got.Action != guardrailActionAlert || !findingStringHasRuleID(got.Findings, artifactUnreadRuleID) {
			t.Fatalf("%s unread: %+v, want an alert naming %s", tc.name, got, artifactUnreadRuleID)
		}
	}
}

// Concurrent hook calls share the readers. Every call that runs a
// destructive script keeps its block or says the script went unread; none
// returns nothing. On a loaded box (CPU burners) the parent dropped raises.
func TestGAP2171ConcurrentArtifactScansNeverDropTheRaise(t *testing.T) {
	requireNativePOSIXArtifactHost(t)
	const connectorName = "gap2171-artifact-concurrent"
	installDefaultProfileConnector(t, connectorName)
	req := agentHookRequest{ConnectorName: connectorName}
	destructive := gap2171Script(t, "cleanup.sh", gap2171Destructive())
	const workers, rounds = 32, 4
	var mu sync.Mutex
	kept, unread, dropped := 0, 0, 0
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range rounds {
				ctx, cancel := context.WithTimeout(context.Background(), promotedArtifactHookBudget)
				findings := promotedArtifactFindings(ctx, req, destructive, true, nil)
				cancel()
				mu.Lock()
				switch {
				case findingWithID(findings, "CMD-RM-RF") != nil:
					kept++
				case findingWithID(findings, artifactUnreadRuleID) != nil:
					unread++
				default:
					dropped++
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	t.Logf("GAP2171 kept=%d unread=%d dropped=%d", kept, unread, dropped)
	if dropped != 0 {
		t.Fatalf("%d of %d concurrent scans dropped the raise without a finding (kept %d, unread %d)",
			dropped, workers*rounds, kept, unread)
	}
}
