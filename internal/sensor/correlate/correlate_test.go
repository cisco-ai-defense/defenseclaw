// Copyright 2026 Cisco Systems, Inc. and its affiliates
// Copyright (c) 2026 Mike Storm. All rights reserved.
//
// Derived from ShadowClaw -- Universal Shadow AI Detector, by Mike Storm,
// Distinguished Engineer, CCIE Security 13847. Reimplemented in Go and
// absorbed into the DefenseClaw gateway; see NOTICE for the modifications.
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

package correlate

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"strings"
)

func freshSnapshot(signals ...inventory.AISignal) Snapshot {
	return Snapshot{Signals: signals, ScanTime: time.Now(), Complete: true}
}

func modelSignal(id string) inventory.AISignal {
	return inventory.AISignal{
		SignalID: "sig-model", Category: inventory.SignalLocalModel,
		State: inventory.AIStateSeen, Model: &inventory.LocalModelInfo{ID: id, Status: "installed"},
	}
}

// TestUnobservedIsNeverEvidenceOrExoneration is the rule the whole design rests
// on. Each of these inputs must produce the same verdict as switching
// correlation off, and must say why.
func TestUnobservedIsNeverEvidenceOrExoneration(t *testing.T) {
	t.Parallel()
	observation := Observation{ModelHint: "qwen3", ExeName: "ollama", PID: 42}
	for _, test := range []struct {
		name     string
		snapshot Snapshot
		wantIn   string
	}{
		{"no snapshot at all", Snapshot{}, "no discovery snapshot"},
		{
			"snapshot with no scan time",
			Snapshot{Signals: []inventory.AISignal{modelSignal("other")}, Complete: true},
			"no scan time",
		},
		{
			"stale snapshot",
			Snapshot{
				Signals:  []inventory.AISignal{modelSignal("other")},
				ScanTime: time.Now().Add(-2 * MaxSnapshotAge), Complete: true,
			},
			"stale",
		},
		{
			"incomplete scan cannot conclude absence",
			Snapshot{
				Signals:  []inventory.AISignal{modelSignal("other")},
				ScanTime: time.Now(), Complete: false,
			},
			"incomplete",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := New(test.snapshot).LocalModel(observation)
			if got.Verdict != VerdictUnobserved {
				t.Fatalf("verdict = %s, want %s", got.Verdict, VerdictUnobserved)
			}
			if got.Reason == "" {
				t.Fatal("unobserved verdict carried no reason; the blindness must be recorded")
			}
			if !contains(got.Reason, test.wantIn) {
				t.Fatalf("reason = %q, want it to mention %q", got.Reason, test.wantIn)
			}
			if got.Tag() != "correlation:unobserved" {
				t.Fatalf("Tag() = %q", got.Tag())
			}
		})
	}
}

func TestAccountedForByModelIdentity(t *testing.T) {
	t.Parallel()
	got := New(freshSnapshot(modelSignal("Qwen3-0.6B-GGUF"))).
		LocalModel(Observation{ModelHint: "qwen3-0.6b-gguf"})
	if got.Verdict != VerdictAccounted {
		t.Fatalf("verdict = %s, want %s (%s)", got.Verdict, VerdictAccounted, got.Reason)
	}
	if len(got.MatchedSignalIDs) != 1 || got.MatchedSignalIDs[0] != "sig-model" {
		t.Fatalf("MatchedSignalIDs = %v", got.MatchedSignalIDs)
	}
}

// TestPidMatchIsAvailableInProcess covers a join the file-based boundary could
// not make: the same process, not merely the same product.
func TestPidMatchIsAvailableInProcess(t *testing.T) {
	t.Parallel()
	signal := inventory.AISignal{
		SignalID: "sig-endpoint", Category: inventory.SignalLocalAIEndpoint,
		State: inventory.AIStateSeen, Runtime: &inventory.ProcessRuntime{PID: 4242, Comm: "ollama"},
	}
	got := New(freshSnapshot(signal)).LocalModel(Observation{PID: 4242})
	if got.Verdict != VerdictAccounted {
		t.Fatalf("verdict = %s, want accounted (%s)", got.Verdict, got.Reason)
	}
}

// TestDisagreementEscalatesRatherThanStayingNeutral pins the reading that
// matters: a complete scan that explains nothing is the interesting case.
func TestDisagreementEscalatesRatherThanStayingNeutral(t *testing.T) {
	t.Parallel()
	got := New(freshSnapshot(modelSignal("some-other-model"))).
		LocalModel(Observation{ModelHint: "qwen3", ExeName: "llama-server"})
	if got.Verdict != VerdictUnaccounted {
		t.Fatalf("verdict = %s, want %s (%s)", got.Verdict, VerdictUnaccounted, got.Reason)
	}
}

// TestGoneSignalsDoNotAccountForLiveProcesses pins that a removed model cannot
// excuse a running one.
func TestGoneSignalsDoNotAccountForLiveProcesses(t *testing.T) {
	t.Parallel()
	gone := modelSignal("qwen3")
	gone.State = inventory.AIStateGone
	got := New(freshSnapshot(gone)).LocalModel(Observation{ModelHint: "qwen3"})
	if got.Verdict != VerdictUnaccounted {
		t.Fatalf("a gone signal accounted for a live process: %s (%s)", got.Verdict, got.Reason)
	}
}

// TestConnectorJoinAttributesAChainToANamedConnector covers the correlation
// that was impossible across the old product boundary.
func TestConnectorJoinAttributesAChainToANamedConnector(t *testing.T) {
	t.Parallel()
	signal := inventory.AISignal{
		SignalID: "sig-connector", Category: inventory.SignalSupportedConnector,
		State: inventory.AIStateSeen, Product: "Claude Code",
		SupportedConnector: "claudecode", Basenames: []string{"claude"},
	}
	got := New(freshSnapshot(signal)).Connector(Observation{AgentName: "claude"})
	if got.Verdict != VerdictAccounted {
		t.Fatalf("verdict = %s, want accounted (%s)", got.Verdict, got.Reason)
	}
	if len(got.Categories) != 1 || got.Categories[0] != inventory.SignalSupportedConnector {
		t.Fatalf("Categories = %v", got.Categories)
	}
}

// TestProviderDomainJoinPromotesAHostFactToAProcessFact covers the other
// correlation the boundary made impossible: provider_domain is host-wide DNS
// with no pid.
func TestProviderDomainJoinPromotesAHostFactToAProcessFact(t *testing.T) {
	t.Parallel()
	signal := inventory.AISignal{
		SignalID: "sig-domain", Category: inventory.SignalProviderDomain,
		State: inventory.AIStateSeen, Basenames: []string{"anthropic.com"},
	}
	correlator := New(freshSnapshot(signal))
	if got := correlator.ProviderDomain(Observation{ProviderDomain: "api.anthropic.com."}); got.Verdict != VerdictAccounted {
		t.Fatalf("subdomain did not match the inventoried domain: %s (%s)", got.Verdict, got.Reason)
	}
	if got := correlator.ProviderDomain(Observation{ProviderDomain: "notanthropic.com"}); got.Verdict != VerdictUnaccounted {
		t.Fatalf("a suffix-only lookalike matched: %s", got.Verdict)
	}
}

func TestMCPJoin(t *testing.T) {
	t.Parallel()
	signal := inventory.AISignal{
		SignalID: "sig-mcp", Category: inventory.SignalMCPServer,
		State: inventory.AIStateSeen, Name: "filesystem",
	}
	correlator := New(freshSnapshot(signal))
	if got := correlator.MCPServer(Observation{MCPName: "filesystem"}); got.Verdict != VerdictAccounted {
		t.Fatalf("declared MCP server was not accounted for: %s", got.Verdict)
	}
	if got := correlator.MCPServer(Observation{MCPName: "shell"}); got.Verdict != VerdictUnaccounted {
		t.Fatalf("an undeclared MCP server was not flagged: %s", got.Verdict)
	}
}

// TestNoSignalsInMatchableCategoriesIsUnobservedNotAbsence pins the difference
// between "discovery looked and found nothing" and "discovery does not collect
// this category at all".
func TestNoSignalsInMatchableCategoriesIsUnobservedNotAbsence(t *testing.T) {
	t.Parallel()
	unrelated := inventory.AISignal{
		SignalID: "sig-skill", Category: inventory.SignalSkill, State: inventory.AIStateSeen,
	}
	got := New(freshSnapshot(unrelated)).LocalModel(Observation{ModelHint: "qwen3"})
	if got.Verdict != VerdictUnobserved {
		t.Fatalf("verdict = %s, want unobserved (%s)", got.Verdict, got.Reason)
	}
}

func contains(haystack, needle string) bool {
	return len(needle) == 0 || len(haystack) >= len(needle) &&
		(haystack == needle || strings.Contains(haystack, needle))
}

// TestFutureDatedSnapshotIsUnobservedNotFresh closes a staleness check that
// only looked one way.
//
// age is negative when the scan time is ahead of now, so a simple "older
// than the maximum" comparison passes for an arbitrarily future snapshot. A
// complete snapshot that matches nothing yields unaccounted, which escalates,
// so a skewed clock inflated severity rather than merely confusing it.
func TestFutureDatedSnapshotIsUnobservedNotFresh(t *testing.T) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	observation := Observation{PID: 4242, ExeName: "python3"}

	for _, test := range []struct {
		name     string
		scanTime time.Time
		want     Verdict
	}{
		{"fresh", now.Add(-time.Minute), VerdictUnaccounted},
		{"a little skew is tolerated", now.Add(5 * time.Second), VerdictUnaccounted},
		{"stale", now.Add(-time.Hour), VerdictUnobserved},
		{"an hour in the future", now.Add(time.Hour), VerdictUnobserved},
		{"a year in the future", now.Add(365 * 24 * time.Hour), VerdictUnobserved},
	} {
		t.Run(test.name, func(t *testing.T) {
			correlator := New(Snapshot{
				Signals:  []inventory.AISignal{modelSignal("some-other-model")},
				ScanTime: test.scanTime,
				Complete: true,
			})
			correlator.now = func() time.Time { return now }
			if got := correlator.LocalModel(observation).Verdict; got != test.want {
				t.Fatalf("verdict = %v, want %v", got, test.want)
			}
		})
	}
}
