// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// rel-1-0-10 GAP-2038: previous/data is the release a rollback returns to
// only for `defenseclaw rollback`. A Windows downgrade (install.ps1
// Convert-HooksForOlderRelease: `defenseclaw upgrade --version` or -Version
// to an older release) and the restore of a failed upgrade
// (Convert-HooksForRestore) run prepare-rollback with no data swap, so
// previous/ still holds the slot of an earlier upgrade. A user had
// route-only on in 1.0.10, upgraded to 1.0.11 (previous/data = 1.0.10's data
// with its applied route record), then downgraded to 1.0.9: prepare-rollback
// skipped Codex and Claude Code because previous/data held a record, the
// render stayed, and 1.0.9 has no route-only listener, so the agent got 401
// on every call (GAP-0602). A target before 1.0.10, or one not given, always
// gets the user's settings back, whatever previous/data holds.
func TestGAP2038DowngradeBelow1010PutsBackTheRenderWhenPreviousHoldsARecord(t *testing.T) {
	for _, tc := range []struct {
		name string
		conn connector.Connector
		path func(gap2021Home) string
		base string
		own  string
	}{
		{"codex", connector.NewCodexConnector(), func(h gap2021Home) string { return h.codexPath }, gap2021CodexWithProvider, "model_provider = 'bedrock-luna'"},
		{"claudecode", connector.NewClaudeCodeConnector(), func(h gap2021Home) string { return h.claudePath }, gap2021ClaudeWithBaseURL, `"ANTHROPIC_BASE_URL": "https://llm-proxy.example.internal/anthropic"`},
	} {
		for _, target := range []string{"1.0.9", ""} {
			t.Run(tc.name+"/to="+target, func(t *testing.T) {
				h := newGAP2021Home(t)
				path := tc.path(h)
				h.write(t, path, tc.base)
				// 1.0.10 with route-only on for the connector.
				h.setUp(t, tc.conn, path, gap2021Route(tc.conn.Name()))
				// Upgrade to 1.0.11: previous/data = the 1.0.10 data, record applied.
				h.upgrade(t)
				if !connector.RollbackTargetRestoresRouteOnly(h.dataDir, tc.conn.Name()) {
					t.Fatal("fixture: previous/data holds no applied route record")
				}
				if err := tc.conn.Setup(context.Background(), h.opts(gap2021Route(tc.conn.Name()))); err != nil {
					t.Fatalf("setup on the newer install: %v", err)
				}
				// The Windows downgrade: no swap, previous/ unchanged.
				restore := withConnectorState(t, h.dataDir, tc.conn.Name())
				out, stderr, code := runConnectorCmd(t, "prepare-rollback", "--data-dir", h.dataDir, "--to-version", target)
				restore()
				if code != 0 {
					t.Fatalf("prepare-rollback --to-version %q: exit=%d stdout=%q stderr=%q", target, code, out, stderr)
				}
				got := h.read(t, path)
				if bytes.Contains(got, []byte("/r/"+tc.conn.Name())) || bytes.Contains(got, []byte("defenseclaw_route")) || bytes.Contains(got, []byte("X-DC-Route-Auth")) {
					t.Fatalf("downgrade to %q (no route-only listener) left the route-only render in place:\n%s", target, got)
				}
				if !bytes.Contains(got, []byte(tc.own)) {
					t.Fatalf("downgrade to %q did not put back the user's own %s:\n%s", target, tc.own, got)
				}
				if !bytes.Contains([]byte(out), []byte(tc.conn.Name())) {
					t.Fatalf("prepare-rollback did not say it put back the %s settings: %q", tc.conn.Name(), out)
				}
			})
		}
	}
}

// The record check still decides a target of 1.0.10 or later: a connector
// that release routed keeps its render (GAP-2021).
func TestGAP2038DowngradeTo1010KeepsTheRenderTheTargetRoutes(t *testing.T) {
	h := newGAP2021Home(t)
	h.write(t, h.codexPath, gap2021CodexWithProvider)
	h.setUp(t, connector.NewCodexConnector(), h.codexPath, gap2021Route("codex"))
	h.upgrade(t)
	if err := connector.NewCodexConnector().Setup(context.Background(), h.opts(gap2021Route("codex"))); err != nil {
		t.Fatalf("setup on the newer install: %v", err)
	}
	restore := withConnectorState(t, h.dataDir, "codex")
	out, stderr, code := runConnectorCmd(t, "prepare-rollback", "--data-dir", h.dataDir, "--to-version", "1.0.10")
	restore()
	if code != 0 {
		t.Fatalf("prepare-rollback: exit=%d stdout=%q stderr=%q", code, out, stderr)
	}
	if got := h.read(t, h.codexPath); !bytes.Contains(got, []byte("defenseclaw_route")) {
		t.Fatalf("a target that routes Codex lost its render:\n%s", got)
	}
}
