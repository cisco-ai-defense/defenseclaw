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
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0593: a proxied prompt whose evaluation record could not be written
// follows the hook routes' failed-audit tier rule.
func TestPromptAuditFailedClosedFollowsPolicyTier(t *testing.T) {
	writeErr := errors.New("audit: persist runtime record: database or disk is full")
	contextFor := func(edit func(*config.Config)) context.Context {
		cfg := &config.Config{}
		cfg.Guardrail.Connector = "openclaw"
		if edit != nil {
			edit(cfg)
		}
		return withPinnedGeneration(context.Background(), &Generation{N: 1, Config: cfg})
	}
	proxy := &GuardrailProxy{cfg: &config.GuardrailConfig{Connector: "openclaw"}}
	allow := func() *ScanVerdict { return &ScanVerdict{Action: "allow", Severity: "NONE"} }

	cases := []struct {
		name   string
		edit   func(*config.Config)
		mode   string
		err    error
		closed bool
	}{
		{name: "record written", mode: "action", closed: false},
		{name: "default tier allows", mode: "action", err: writeErr, closed: false},
		{name: "permissive tier allows", edit: func(c *config.Config) { c.Guardrail.RulePack = "permissive" }, mode: "action", err: writeErr, closed: false},
		{name: "strict tier blocks", edit: func(c *config.Config) { c.Guardrail.RulePack = "strict" }, mode: "action", err: writeErr, closed: true},
		{name: "strict tier blocks in observe mode", edit: func(c *config.Config) { c.Guardrail.RulePack = "strict" }, mode: "observe", err: writeErr, closed: true},
		{name: "managed blocks", edit: func(c *config.Config) {
			c.DeploymentMode = managed.DeploymentModeManagedEnterprise
			c.Enterprise.Profile = managed.ProfileStandalone
		}, mode: "action", err: writeErr, closed: true},
		{name: "Secure Client keeps the verdict", edit: func(c *config.Config) {
			c.DeploymentMode = managed.DeploymentModeManagedEnterprise
			c.Enterprise.Profile = managed.ProfileSecureClient
		}, mode: "action", err: writeErr, closed: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verdict := allow()
			got := proxy.promptAuditFailedClosed(contextFor(tc.edit), verdict, tc.mode, tc.err)
			if got != tc.closed {
				t.Fatalf("promptAuditFailedClosed = %t, want %t", got, tc.closed)
			}
			if tc.closed && (verdict.Action != "block" || verdict.Reason != proxyAuditFailedClosedReason) {
				t.Fatalf("closed verdict = %+v, want the audit block", verdict)
			}
			if !tc.closed && verdict.Action != "allow" {
				t.Fatalf("open verdict = %+v, want the allow kept", verdict)
			}
		})
	}

	t.Run("an enforced block is kept as it is", func(t *testing.T) {
		verdict := &ScanVerdict{Action: "block", Severity: "CRITICAL", Reason: "matched: rule"}
		ctx := contextFor(func(c *config.Config) { c.Guardrail.RulePack = "strict" })
		if proxy.promptAuditFailedClosed(ctx, verdict, "action", writeErr) {
			t.Fatal("an enforced block was reported as a new audit block")
		}
		if verdict.Reason != "matched: rule" || verdict.Severity != "CRITICAL" {
			t.Fatalf("block changed: %+v", verdict)
		}
	})
}
