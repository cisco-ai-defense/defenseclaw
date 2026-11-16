// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Under Secure Client a managed hook's local availability gaps (a payload
// over the cap, a missing or empty token) follow the configured fail mode:
// open lets the event through uninspected and records it as degraded, closed
// and strict availability block and record a boundary. Every other managed
// hook stays closed whatever the fail mode.
func TestSecureClientAvailabilityGapsFollowFailMode(t *testing.T) {
	big := `{"hook_event_name":"PreToolUse","tool_input":"` + strings.Repeat("x", int(defaultMaxBody)) + `"}`
	gaps := []struct {
		name   string
		reason string
		mutate func(t *testing.T, opts *Options)
	}{
		{
			name:   "oversized",
			reason: managedHookOversizedReason,
			mutate: func(t *testing.T, opts *Options) {
				token := "authenticated-token"
				opts.AuthenticatedManagedToken = &token
				opts.Stdin = strings.NewReader(big)
			},
		},
		{
			name:   "empty authenticated token",
			reason: managedRuntimeTokenEmptyReason,
			mutate: func(t *testing.T, opts *Options) {
				empty := "  "
				opts.AuthenticatedManagedToken = &empty
			},
		},
		{
			name:   "missing token",
			reason: missingGatewayTokenReason,
			mutate: func(t *testing.T, opts *Options) {
				if err := os.Remove(filepath.Join(opts.HookDir, ".token")); err != nil {
					t.Fatal(err)
				}
				opts.Token = ""
			},
		},
	}
	for _, gap := range gaps {
		for _, tc := range []struct {
			name         string
			secureClient bool
			standalone   bool
			failMode     string
			strict       bool
			allowed      bool
		}{
			{name: "secure client open", secureClient: true, failMode: "open", allowed: true},
			{name: "secure client closed", secureClient: true, failMode: "closed"},
			{name: "secure client strict", secureClient: true, failMode: "open", strict: true},
			{name: "managed open", failMode: "open"},
			// A standalone hook is not a Secure Client hook (secureClientHook)
			// even when the host also reports Secure Client.
			{name: "standalone with secure client open", secureClient: true, standalone: true, failMode: "open"},
		} {
			t.Run(gap.name+"/"+tc.name, func(t *testing.T) {
				records := captureManagedHookDecisions(t)
				r := run(t, "claudecode", ok(`{"action":"allow"}`), func(opts *Options) {
					opts.ManagedEnterprise = true
					opts.SecureClient = tc.secureClient
					opts.ManagedStandalone = tc.standalone
					opts.FailMode = tc.failMode
					opts.StrictAvailability = tc.strict
					gap.mutate(t, opts)
				})
				if r.rt.requests != 0 {
					t.Fatalf("gateway called %d times, want 0", r.rt.requests)
				}
				if tc.allowed {
					if r.code != 0 {
						t.Fatalf("code = %d, want an allow; stderr=%q", r.code, r.stderr)
					}
					requireOneManagedRecord(t, *records, managed.MarkerDegraded, `decision="allow"`)
					return
				}
				if r.code == 0 && r.stdout == "" {
					t.Fatalf("code = 0 with no block output, want a block; stderr=%q", r.stderr)
				}
				if tc.standalone {
					// A standalone hook may stop at its own peer check first;
					// it blocks either way.
					return
				}
				for _, record := range *records {
					if record.marker == managed.MarkerBoundary &&
						strings.Contains(record.line, `decision="block"`) &&
						strings.Contains(record.line, gap.reason) {
						return
					}
				}
				t.Fatalf("no boundary block record for %q in %+v", gap.reason, *records)
			})
		}
	}
}
