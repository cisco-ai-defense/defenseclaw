// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// gap0674ChainAnswers is every answer the chain reads from a call's private
// record, as the record is and as the hook places it.
type gap0674ChainAnswers struct {
	Caps                     bounded.CapSet
	Has, Content, Unplaced   bool
	Exact, Proof             string
	ExactOK, ProofOK         bool
	Projection, WithReadRule guardrail.ToolChainProjection
	Placed, PlacedFixtureCWD *gap0674ChainAnswers
}

func gap0674Answers(facts actionfacts.Facts, place bool) gap0674ChainAnswers {
	var a gap0674ChainAnswers
	a.Caps = facts.CredentialPathReadCaps(context.Background())
	a.Has = facts.HasCredentialPathReads()
	a.Content = credentialFileContentRead(facts)
	a.Unplaced = hasUnplacedRelativePath(facts)
	a.Exact, a.ExactOK = exactSecretReadChainDigest(facts)
	a.Proof, a.ProofOK = credentialFileReadProofDigest(facts)
	projectTrustedActionChainSteps(&a.Projection, facts, nil)
	projectTrustedActionChainSteps(&a.WithReadRule, facts, []RuleFinding{{RuleID: "PATH-ENV-FILE", Severity: "HIGH"}})
	if place {
		placed := gap0674Answers(placeSecretReadPaths(facts, "/reported/work"), false)
		fixture := gap0674Answers(placeSecretReadPaths(facts, "/reported/test/fixtures"), false)
		a.Placed, a.PlacedFixtureCWD = &placed, &fixture
	}
	return a
}

// TestGAP0674RecordKeptPastTheResolveIsThin: the facts a hook call keeps for
// its chain after the dispatch (the record the GAP-0674 replay found 110
// calls holding) keep a handful of a deep search's 300 reads, with the
// chain's answers of the whole record.
func TestGAP0674RecordKeptPastTheResolveIsThin(t *testing.T) {
	installDefaultProfileConnector(t, "claudecode")
	root := t.TempDir()
	for j := range 300 {
		dir := filepath.Join(root, "tree", strings.Repeat("x", 60), fmt.Sprintf("s%03d", j))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("KEY=1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	input := actionfacts.Input{Tool: "Bash", Command: "grep -r KEY tree", CWD: root, ActiveHome: root, DialectHint: actionfacts.DialectPOSIX}
	capture := &toolChainHookCapture{reportedCWD: root}
	dispatchTrustedAction(t.Context(), trustedActionRequest{Input: input, Connector: "claudecode", EnforcementCapable: true, record: capture.recordTrustedAction})
	if !capture.recorded {
		t.Fatal("the dispatch recorded no facts")
	}
	whole := actionfacts.Analyze(input)
	if n := len(whole.CredentialPathReads()); n < 300 {
		t.Fatalf("the whole record has %d reads, want the 300 files", n)
	}
	if n := len(capture.facts.CredentialPathReads()); n > 12 {
		t.Errorf("the facts kept for the chain hold %d reads of the search, want at most 12", n)
	}
	if got, want := gap0674Answers(capture.facts, false), gap0674Answers(placeSecretReadPaths(whole, root), false); !reflect.DeepEqual(got, want) {
		t.Errorf("the chain's answers differ\n got %+v\nwant %+v", got, want)
	}
}
