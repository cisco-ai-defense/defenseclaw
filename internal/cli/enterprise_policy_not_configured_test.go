// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// `policy show|verify --connector cursor` on a host whose managed config does
// not enable Cursor reported "Cursor's configured machine hook is missing; this
// is a protection failure", while the unfiltered report has no Cursor row: a
// connector that is not configured has nothing to check or repair (GAP-1688).
func TestEnterprisePolicyNamedConnectorThatIsNotConfigured(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("this publishes the Linux machine-policy tree, which only Linux and macOS write")
	}
	ctx := withEnterprisePolicyTree(t)
	ctx.connectors = []string{"claudecode", "codex"}
	standaloneEnterprisePolicyOptions = func() (enterprisePolicyContext, error) { return ctx, nil }
	if _, err := enterprisepolicy.Publish(ctx.opts, ctx.connectors); err != nil {
		t.Fatal(err)
	}
	enterprisePolicyConnector = "cursor"
	for _, run := range []struct {
		name string
		fn   func() (string, error)
	}{
		{"show", func() (string, error) { return runPolicyCommand(t, runEnterprisePolicyShow) }},
		{"verify", func() (string, error) { return runPolicyCommand(t, runEnterprisePolicyVerify) }},
	} {
		enterprisePolicyJSON = true
		out, err := run.fn()
		if err != nil {
			t.Fatalf("%s --connector cursor: %v\n%s", run.name, err, out)
		}
		var report enterprisePolicyReport
		if err := json.Unmarshal([]byte(out), &report); err != nil {
			t.Fatalf("%s --json: %v\n%s", run.name, err, out)
		}
		if !report.Complete || len(report.Result.States) != 1 {
			t.Fatalf("%s: %+v", run.name, report)
		}
		state := report.Result.States[0]
		if state.Connector != "cursor" || state.Route != enterprisepolicy.RouteNotConfigured || len(state.Conflicts) != 0 {
			t.Fatalf("%s: cursor row %+v", run.name, state)
		}
		enterprisePolicyJSON = false
		out, err = run.fn()
		if err != nil || !strings.Contains(out, "not enabled in the managed config") || strings.Contains(out, "protection failure") {
			t.Fatalf("%s text: %v\n%s", run.name, err, out)
		}
	}
	// A configured connector is still checked.
	enterprisePolicyConnector, enterprisePolicyJSON = "codex", true
	out, err := runPolicyCommand(t, runEnterprisePolicyVerify)
	if err != nil || !strings.Contains(out, `"route": "machine_policy"`) {
		t.Fatalf("verify --connector codex: %v\n%s", err, out)
	}
}
