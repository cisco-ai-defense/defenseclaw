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

package sensor

import (
	"net"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/sensor/catalog"
	"github.com/defenseclaw/defenseclaw/internal/sensor/netprobe"
	"github.com/defenseclaw/defenseclaw/internal/sensor/procprobe"
	"github.com/defenseclaw/defenseclaw/internal/sensor/scoring"
)

func signalIDs(signals []scoring.Signal) []string {
	ids := make([]string, 0, len(signals))
	for _, signal := range signals {
		ids = append(ids, signal.ID)
	}
	return ids
}

func hasSignal(signals []scoring.Signal, id string) bool {
	for _, signal := range signals {
		if signal.ID == id {
			return true
		}
	}
	return false
}

// TestPlaneAOnlyHeartbeatsInAScriptableRuntime pins the reason the runtime
// allow-list exists: a compiled application burning CPU is a compiled
// application burning CPU, and scoring every busy process makes the signal
// worthless.
func TestPlaneAOnlyHeartbeatsInAScriptableRuntime(t *testing.T) {
	t.Parallel()
	const window = 30 * time.Second
	busy := 20 * time.Second

	agent := planeA(procprobe.Process{Name: "python3", RSSBytes: 2 << 30}, busy, window)
	if !hasSignal(agent, "inference_heartbeat") {
		t.Errorf("a busy python3 produced %v, want an inference heartbeat", signalIDs(agent))
	}
	if !hasSignal(agent, "model_resident_memory") {
		t.Errorf("a 2 GiB python3 produced %v, want model_resident_memory", signalIDs(agent))
	}

	compiled := planeA(procprobe.Process{Name: "ffmpeg", RSSBytes: 4 << 30}, busy, window)
	if len(compiled) != 0 {
		t.Errorf("a busy ffmpeg produced %v, want nothing", signalIDs(compiled))
	}
}

func TestPlaneAIdleRuntimeDoesNotHeartbeat(t *testing.T) {
	t.Parallel()
	signals := planeA(procprobe.Process{Name: "node"}, 100*time.Millisecond, 30*time.Second)
	if hasSignal(signals, "inference_heartbeat") {
		t.Errorf("an idle node produced %v", signalIDs(signals))
	}
}

func TestPlaneARecognisesALocalModelRuntimeRegardlessOfLoad(t *testing.T) {
	t.Parallel()
	signals := planeA(procprobe.Process{Name: "ollama"}, 0, 30*time.Second)
	if !hasSignal(signals, "local_model_runtime") {
		t.Fatalf("an idle ollama produced %v, want local_model_runtime", signalIDs(signals))
	}
}

func testCatalog() *catalog.Catalog {
	return catalog.FromSignatures([]inventory.AISignature{
		{ID: "anthropic", Name: "Anthropic", Vendor: "Anthropic", DomainPatterns: []string{"anthropic.com"}},
	})
}

func namedResolver(hostname string) func(netprobe.Connection) (string, float64, string) {
	return func(netprobe.Connection) (string, float64, string) {
		return hostname, ConfidenceDNSAnswer, "dns_answer"
	}
}

func unnamedResolver() func(netprobe.Connection) (string, float64, string) {
	return func(netprobe.Connection) (string, float64, string) { return "", 0, "" }
}

func publicConn(port int) netprobe.Connection {
	return netprobe.Connection{
		RemoteIP: net.ParseIP("104.18.0.1"), RemotePort: port, State: netprobe.StateEstablished,
	}
}

func TestPlaneBScoresProviderEgress(t *testing.T) {
	t.Parallel()
	result := planeB([]netprobe.Connection{publicConn(443)}, testCatalog(),
		namedResolver("api.anthropic.com"), nil)
	if !hasSignal(result.signals, "shadow_ai_egress") {
		t.Fatalf("signals = %v, want shadow_ai_egress", signalIDs(result.signals))
	}
	if len(result.providers) != 1 || result.providers[0].Category != string(catalog.CategoryFrontier) {
		t.Fatalf("providers = %+v", result.providers)
	}
}

// TestPlaneBGatewayBypassNeedsAGatewayToExist pins that going around something
// is a different fact from reaching a provider on a host with no gateway.
func TestPlaneBGatewayBypassNeedsAGatewayToExist(t *testing.T) {
	t.Parallel()
	noGateway := planeB([]netprobe.Connection{publicConn(443)}, testCatalog(),
		namedResolver("api.anthropic.com"), nil)
	if hasSignal(noGateway.signals, "gateway_bypass") {
		t.Error("a host with no approved gateway reported a bypass")
	}
	withGateway := planeB([]netprobe.Connection{publicConn(443)}, testCatalog(),
		namedResolver("api.anthropic.com"), map[string]bool{"ai-gw.corp.example": true})
	if !hasSignal(withGateway.signals, "gateway_bypass") {
		t.Errorf("signals = %v, want gateway_bypass", signalIDs(withGateway.signals))
	}
}

func TestPlaneBSanctionedEgressIsInventoryNotAlarm(t *testing.T) {
	t.Parallel()
	result := planeB([]netprobe.Connection{publicConn(443)}, testCatalog(),
		namedResolver("ai-gw.corp.example"), map[string]bool{"ai-gw.corp.example": true})
	if !hasSignal(result.signals, "sanctioned_ai_egress") {
		t.Fatalf("signals = %v, want sanctioned_ai_egress", signalIDs(result.signals))
	}
	if hasSignal(result.signals, "gateway_bypass") {
		t.Error("using the approved gateway was scored as a bypass")
	}
	if scoring.SeverityFor(scoring.Total(result.signals)) != scoring.SeverityLow {
		t.Errorf("approved-path use scored %d, want the low band",
			scoring.Total(result.signals))
	}
}

// TestPlaneBLoopbackIsNeverEgress pins that talking to a local model server is
// the local-inference signal, not an egress finding.
func TestPlaneBLoopbackIsNeverEgress(t *testing.T) {
	t.Parallel()
	result := planeB([]netprobe.Connection{{
		RemoteIP: net.ParseIP("127.0.0.1"), RemotePort: 11434, State: netprobe.StateEstablished,
	}}, testCatalog(), namedResolver("api.anthropic.com"), nil)
	if hasSignal(result.signals, "shadow_ai_egress") {
		t.Errorf("a loopback connection was scored as egress: %v", signalIDs(result.signals))
	}
	if !hasSignal(result.signals, "local_inference_client") {
		t.Errorf("signals = %v, want local_inference_client", signalIDs(result.signals))
	}
}

// TestPlaneBListeningPortCatchesARenamedServer covers the case the process
// catalog cannot: a model server whose binary has been renamed.
func TestPlaneBListeningPortCatchesARenamedServer(t *testing.T) {
	t.Parallel()
	result := planeB([]netprobe.Connection{{
		LocalPort: 11434, State: netprobe.StateListen,
	}}, testCatalog(), unnamedResolver(), nil)
	if !hasSignal(result.signals, "local_model_server_port") {
		t.Fatalf("signals = %v, want local_model_server_port", signalIDs(result.signals))
	}
	if result.listeningModelPort != "ollama" {
		t.Errorf("listeningModelPort = %q", result.listeningModelPort)
	}
}

func TestPlaneBPrivatePeersAreNotEgress(t *testing.T) {
	t.Parallel()
	result := planeB([]netprobe.Connection{{
		RemoteIP: net.ParseIP("10.1.2.3"), RemotePort: 443, State: netprobe.StateEstablished,
	}}, testCatalog(), namedResolver("api.anthropic.com"), nil)
	if len(result.signals) != 0 || result.unattributedPublicPeers != 0 {
		t.Fatalf("an RFC1918 peer produced %v / %d unattributed",
			signalIDs(result.signals), result.unattributedPublicPeers)
	}
}

// TestUnattributedEgressNeedsRepetition pins the escalation: a single unnamed
// peer cannot clear the reporting floor, and persistence can.
func TestUnattributedEgressNeedsRepetition(t *testing.T) {
	t.Parallel()
	single, ok := unattributedEgressSignal(1)
	if !ok || single.Weight >= scoring.DefaultMinRiskToReport {
		t.Fatalf("one unnamed peer = %+v; it must not clear the floor alone", single)
	}
	persistent, ok := unattributedEgressSignal(scoring.UnattributedEgressRepeatThreshold)
	if !ok || persistent.Weight < scoring.DefaultMinRiskToReport {
		t.Fatalf("persistent unnamed egress = %+v; it must clear the floor", persistent)
	}
	if _, ok := unattributedEgressSignal(0); ok {
		t.Error("zero unnamed peers produced a signal")
	}
}

// TestUnknownProviderEgressSurfacesUncatalogedEndpoints pins that an
// AI-looking host the catalog has never seen is more interesting, not less.
func TestUnknownProviderEgressSurfacesUncatalogedEndpoints(t *testing.T) {
	t.Parallel()
	result := planeB([]netprobe.Connection{publicConn(443)}, testCatalog(),
		namedResolver("llm-gateway.shadow.example"), nil)
	if !hasSignal(result.signals, "unknown_provider_egress") {
		t.Fatalf("signals = %v, want unknown_provider_egress", signalIDs(result.signals))
	}
	if scoring.Total(result.signals) < scoring.DefaultMinRiskToReport {
		t.Errorf("an uncataloged inference host scored %d, below the floor",
			scoring.Total(result.signals))
	}
}

// TestOrdinaryEgressIsIgnored pins that the sensor is not a general network
// monitor: a named host that is neither a provider nor inference-shaped
// produces nothing.
func TestOrdinaryEgressIsIgnored(t *testing.T) {
	t.Parallel()
	result := planeB([]netprobe.Connection{publicConn(443)}, testCatalog(),
		namedResolver("www.example.com"), nil)
	if len(result.signals) != 0 {
		t.Fatalf("ordinary egress produced %v", signalIDs(result.signals))
	}
}

func TestConfidenceScalesProviderWeight(t *testing.T) {
	t.Parallel()
	direct := planeB([]netprobe.Connection{publicConn(443)}, testCatalog(),
		namedResolver("api.anthropic.com"), nil)
	inferred := planeB([]netprobe.Connection{publicConn(443)}, testCatalog(),
		func(netprobe.Connection) (string, float64, string) {
			return "api.anthropic.com", ConfidenceReverseDNS, "reverse_dns"
		}, nil)
	if scoring.Total(inferred.signals) >= scoring.Total(direct.signals) {
		t.Fatalf("a PTR guess scored %d, not below the sniffed answer's %d",
			scoring.Total(inferred.signals), scoring.Total(direct.signals))
	}
}
