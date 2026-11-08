// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// The Cowork row keeps its state to a single word and carries the reason in
// separate fields, in every state the gateway decides on, so a script that
// reads the state is not handed a sentence. The state words are the
// connector ones plus refused.
func TestOwnStatusCoworkRowStateIsOneWordWithSeparateReason(t *testing.T) {
	proven := &managedPolicyView{connectors: map[string]managedPolicyViewConnector{"claudecode": {}, "opencode": {}}}
	unproven := &managedPolicyView{connectors: map[string]managedPolicyViewConnector{"claudecode": {shared: true}}}
	for _, tc := range []struct {
		name      string
		view      *managedPolicyView
		configure func(*config.Config)
		state     string
		code      string
	}{
		{"claude code protected", proven, nil, "protected", "cowork_hooks"},
		{"claude code policy unproven", unproven, nil, "not confirmed", "claude_code_unverified"},
		{"claude code not configured", proven, func(cfg *config.Config) {
			delete(cfg.Guardrail.Connectors, "claudecode")
		}, "not protected", "claude_code_off"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := ownReasonsAPI(t, ownReasonsScenario{view: tc.view, configure: tc.configure})
			raw, err := json.Marshal(api.ownStatusAnswer(context.Background(), "uid", "5001", "alice", ""))
			if err != nil {
				t.Fatal(err)
			}
			var out struct {
				Cowork struct {
					Protected  bool   `json:"protected"`
					State      string `json:"state"`
					ReasonCode string `json:"reason_code"`
					Reason     string `json:"reason"`
				} `json:"cowork"`
			}
			if err := json.Unmarshal(raw, &out); err != nil {
				t.Fatal(err)
			}
			if out.Cowork.State != tc.state || out.Cowork.ReasonCode != tc.code || out.Cowork.Reason == "" ||
				out.Cowork.Protected != (tc.state == "protected") {
				t.Fatalf("cowork row = %+v, want state %q, code %q and a reason: %s", out.Cowork, tc.state, tc.code, raw)
			}
		})
	}
}
