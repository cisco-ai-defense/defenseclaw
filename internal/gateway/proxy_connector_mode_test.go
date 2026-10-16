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
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// markerBlockInspector returns an inspector that blocks every prompt, as a
// CRITICAL rule-pack marker does.
func markerBlockInspector() *mockInspector {
	insp := newMockInspector()
	insp.setVerdict("prompt", &ScanVerdict{
		Action:   "block",
		Severity: "CRITICAL",
		Reason:   "matched: R102-MARKER",
		Findings: []string{"R102-MARKER"},
	})
	return insp
}

func markerChatBody(t *testing.T) []byte {
	return mustJSON(t, map[string]interface{}{
		"model":    "gpt-4",
		"messages": []map[string]interface{}{{"role": "user", "content": "say r102-marker"}},
	})
}

// TestProxyEnforcesThePerConnectorMode pins GAP-0421: `guardrail mode action
// --connector openclaw` (and `setup openclaw --mode action`) write
// guardrail.connectors.openclaw.mode, which guardrail status reports, so the
// proxy must block on it although the global mode stays observe. Before the
// fix the proxy read only guardrail.mode and alerted.
func TestProxyEnforcesThePerConnectorMode(t *testing.T) {
	t.Run("connector action over global observe blocks", func(t *testing.T) {
		prov := &mockProvider{}
		proxy := newTestProxy(t, prov, markerBlockInspector(), "observe")
		cfg := *proxy.cfg
		cfg.Connector = "openclaw"
		cfg.Connectors = map[string]config.PerConnectorGuardrailConfig{
			"openclaw": {Mode: "action", BlockMessage: "r102 per-connector block message"},
		}
		proxy.ApplyGuardrailConfig(&cfg)

		rec := postChat(t, proxy, markerChatBody(t))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (a blocked response is still 200)", rec.Code)
		}
		var resp ChatResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.ID != "chatcmpl-blocked" {
			t.Fatalf("response ID = %q, want chatcmpl-blocked: the per-connector action mode was not enforced", resp.ID)
		}
		if prov.getLastReq() != nil {
			t.Fatal("the blocked prompt was forwarded to the provider")
		}
		if !strings.Contains(rec.Body.String(), "r102 per-connector block message") {
			t.Fatalf("block response does not carry the connector's block message: %s", rec.Body.String())
		}
	})

	t.Run("connector observe over global action alerts", func(t *testing.T) {
		prov := &mockProvider{}
		proxy := newTestProxy(t, prov, markerBlockInspector(), "action")
		cfg := *proxy.cfg
		cfg.Connector = "openclaw"
		cfg.Connectors = map[string]config.PerConnectorGuardrailConfig{"openclaw": {Mode: "observe"}}
		proxy.ApplyGuardrailConfig(&cfg)

		rec := postChat(t, proxy, markerChatBody(t))
		if prov.getLastReq() == nil {
			t.Fatalf("an observe connector's prompt was not forwarded (status %d): %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("no connector entry keeps the global mode", func(t *testing.T) {
		prov := &mockProvider{}
		proxy := newTestProxy(t, prov, markerBlockInspector(), "observe")
		cfg := *proxy.cfg
		cfg.Connector = "openclaw"
		cfg.Mode = "action"
		proxy.ApplyGuardrailConfig(&cfg)

		postChat(t, proxy, markerChatBody(t))
		if prov.getLastReq() != nil {
			t.Fatal("global action mode no longer blocks a connector without its own mode")
		}
	})
}

// TestNewGuardrailProxyStartsInThePerConnectorMode covers the boot path: a
// gateway (re)started with the connector in action must not start the proxy
// in the global observe mode (GAP-0421: a restart did not help either).
func TestNewGuardrailProxyStartsInThePerConnectorMode(t *testing.T) {
	cfg := &config.GuardrailConfig{
		ScannerMode:  "local",
		Mode:         "observe",
		BlockMessage: "global",
		Connector:    "openclaw",
		Connectors: map[string]config.PerConnectorGuardrailConfig{
			"openclaw": {Mode: "action", BlockMessage: "openclaw"},
		},
	}
	proxy, err := NewGuardrailProxy(cfg, &config.CiscoAIDefenseConfig{}, nil, NewSidecarHealth(), nil,
		t.TempDir(), "resolved-inline-token", nil, nil, config.LLMConfig{}, nil)
	if err != nil {
		t.Fatalf("NewGuardrailProxy: %v", err)
	}
	if proxy.mode != "action" || proxy.blockMessage != "openclaw" {
		t.Fatalf("proxy starts with mode=%q block message=%q, want action and the connector's message", proxy.mode, proxy.blockMessage)
	}

	t.Run("Secure Client keeps the global mode", func(t *testing.T) {
		prev := ManagedEnterpriseActive()
		SetManagedEnterpriseActive(true)
		t.Cleanup(func() { SetManagedEnterpriseActive(prev) })
		if mode, msg := proxyPosture(cfg, "openclaw"); mode != "observe" || msg != "global" {
			t.Fatalf("proxyPosture under Secure Client = %q/%q, want observe/global", mode, msg)
		}
	})
}
