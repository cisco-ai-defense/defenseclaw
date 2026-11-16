// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-1321 (balanced defaults): the native runner answers a per-user
// Antigravity registration that lost its event as antigravity-hook.sh does:
// a possible tool call runs with a warning when this account's config opens
// an outage (the default and permissive tiers); strict availability, a
// closed tier, the install window and a managed hook deny it. The gateway is
// never asked.
func TestPerUserAntigravityUnboundToolCallFollowsTheTier(t *testing.T) {
	toolCall := `{"conversationId":"c1","toolCall":{"name":"run_command","args":{"CommandLine":"echo ok"}}}`
	for _, tc := range []struct {
		name, tier, want string
		strict, lock     bool
		managed, open    bool
	}{
		{name: "default tier", tier: "open", open: true, want: "defenseclaw setup antigravity"},
		{name: "closed tier", tier: "closed", want: "defenseclaw setup antigravity"},
		{name: "no tier reader", want: "defenseclaw setup antigravity"},
		{name: "strict availability", tier: "open", strict: true, want: "defenseclaw setup antigravity"},
		{name: "install window", tier: "open", lock: true, want: "defenseclaw setup antigravity"},
		{name: "managed", tier: "open", managed: true, want: "administrator"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := ok(`{"action":"allow"}`)
			result := run(t, "antigravity", rt, func(opts *Options) {
				opts.Event = ""
				opts.FailMode = "closed"
				opts.StrictAvailability = tc.strict
				opts.Stdin = strings.NewReader(toolCall)
				if tc.tier != "" {
					tier := tc.tier
					opts.OutageFailModeNow = func() string { return tier }
				}
				if tc.lock {
					if err := os.Mkdir(filepath.Join(opts.Home, installLockName), 0o700); err != nil {
						t.Fatal(err)
					}
				}
				if tc.managed {
					managedCodex(opts)
				}
			})
			if rt.requests != 0 || result.code != 0 {
				t.Fatalf("code=%d requests=%d stderr=%q, want exit 0 and no gateway request", result.code, rt.requests, result.stderr)
			}
			decision := `"decision":"deny"`
			if tc.open {
				decision = `"decision":"allow"`
				if !strings.Contains(result.stderr, "runs unchecked (fail mode open)") {
					t.Fatalf("stderr=%q, want the fail-open warning", result.stderr)
				}
			}
			if !strings.Contains(result.stdout, decision) || !strings.Contains(result.stdout, tc.want) {
				t.Fatalf("stdout=%q stderr=%q, want %s naming %q", result.stdout, result.stderr, decision, tc.want)
			}
		})
	}
}
