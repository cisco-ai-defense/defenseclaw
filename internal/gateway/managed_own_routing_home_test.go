// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-1103: routing is on for the computer, but an account with no home
// directory (a directory account that sets none, HOME=/var/empty) has nowhere
// for its agent route settings, so own-status must not list its connectors as
// routed.
func TestOwnStatusRoutingNamesAnAccountWithNoHome(t *testing.T) {
	proven := &managedPolicyView{connectors: map[string]managedPolicyViewConnector{"claudecode": {}, "opencode": {}}}
	api := ownReasonsAPI(t, ownReasonsScenario{view: proven, configure: func(cfg *config.Config) {
		cfg.Routing.Enabled = true
		cfg.Routing.RouteOnly = config.RoutingRouteOnlyConfig{Connectors: []string{"claudecode", "codex"}}
	}})
	routing := func(ctx context.Context) map[string]any {
		t.Helper()
		got, _ := api.ownStatusAnswer(ctx, "uid", "5001", "alice", "")["routing"].(map[string]any)
		if got == nil || got["enabled"] != true {
			t.Fatalf("routing member = %v", got)
		}
		return got
	}
	withHome := func(home string) context.Context {
		return withManagedHookPeer(context.Background(), managedHookPeer{UID: 5001, Name: "alice", Home: home})
	}
	if got := routing(withHome(t.TempDir())); len(got["route_only"].([]string)) != 2 || got["route_only_unavailable"] != nil {
		t.Fatalf("an account with a home is routed: %v", got)
	}
	for _, home := range []string{"", "/var/empty", " /dev/null ", filepath.Join(t.TempDir(), "never-created")} {
		got := routing(withHome(home))
		if got["route_only"] != nil || got["route_only_unavailable"] != ownNoHomeReason {
			t.Fatalf("home %q: %v", home, got)
		}
	}
	// A caller that is not a hook socket peer (tests, the Windows pipe) is not judged by a home it does not have.
	if got := routing(context.Background()); got["route_only"] == nil || got["route_only_unavailable"] != nil {
		t.Fatalf("no peer: %v", got)
	}
}
