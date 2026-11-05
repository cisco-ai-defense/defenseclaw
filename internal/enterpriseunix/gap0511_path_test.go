// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
)

// A path event for the applied config is a healthy no-op. A later managed
// connector change updates the running gateway without replacing it.
func TestGAP0511PathEnsureNoopAndManagedConnectorChange(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			path := machinePolicyConfig(t, h, "claudecode", "opencode")
			base, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			const before = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			const after = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
			runner := &policyDigestRunner{fakeRunner: h.runner, digest: before}
			h.env.Runner = runner
			gateway := unitOf(goos, "gateway")
			h.env.HealthGet = func(context.Context) (int, []byte, error) {
				if !h.healthy || !h.services.isActive(gateway) {
					return 0, nil, errors.New("gateway unavailable")
				}
				digest := before
				if strings.Contains(h.read(h.env.Layout.ConfigPath), "opencode: {enabled: false}") {
					digest = after
				}
				state, _ := configwrite.ReadGenerationState(h.env.P(h.env.Layout.ConfigPath))
				return 200, []byte(fmt.Sprintf(`{"api":{"state":"running"},"policy":{"effective_digest":%q,"config_generation":%d},"inspection":{"local":"active","ai_defense":"disabled"}}`, digest, state.Generation)), nil
			}
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: path}))
			unchanged := h.run(Options{Action: ActionEnsure, Reason: ApplyTriggerReason})
			requireOK(t, unchanged)
			if !unchanged.Noop || unchanged.NoopReason != "up_to_date" || !h.services.isActive(gateway) {
				t.Fatalf("unchanged path ensure: noop=%t reason=%q gateway_active=%t", unchanged.Noop, unchanged.NoopReason, h.services.isActive(gateway))
			}
			changed := strings.Replace(string(base), "opencode: {}", "opencode: {enabled: false}", 1)
			if err := os.WriteFile(h.env.P(h.env.Layout.ConfigPath), []byte(changed), 0o640); err != nil {
				t.Fatal(err)
			}
			runner.digest = after
			from := len(h.services.calls)
			requireOK(t, h.run(Options{Action: ActionEnsure, Reason: ApplyTriggerReason}))
			for _, call := range h.services.calls[from:] {
				if call == "stop "+gateway || call == "start "+gateway || call == "restart "+gateway {
					t.Fatalf("connector change replaced the gateway: %v", h.services.calls[from:])
				}
			}
			record, err := h.env.loadDeployment()
			if err != nil || record == nil || record.ConfigSHA256 != sha256Bytes([]byte(changed)) {
				t.Fatalf("connector change not applied: record=%+v err=%v", record, err)
			}
		})
	}
}
