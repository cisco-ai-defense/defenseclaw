// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// REVIEW-s13-p1-merge F1: a standard account on a managed Windows computer
// (no per-user CLI there) reads its own routing through the installed binary;
// every routing write gets the managed answer and reaches no gateway.
func TestManagedWindowsRoutingServesOwnReadsOnly(t *testing.T) {
	var asked []string
	status, body := http.StatusOK, `{"profile":"dev","recent":[]}`
	old := managedWindowsRoutingRead
	managedWindowsRoutingRead = func(_ context.Context, path string) (int, []byte, error) {
		asked = append(asked, path)
		return status, []byte(body), nil
	}
	t.Cleanup(func() { managedWindowsRoutingRead = old })

	run := func(args ...string) (string, error) {
		root := &cobra.Command{Use: "defenseclaw"}
		var out strings.Builder
		root.SetOut(&out)
		root.SetErr(io.Discard)
		addManagedWindowsRoutingCommand(root, "standalone")
		root.SetArgs(args)
		err := root.Execute()
		return out.String(), err
	}

	for _, tc := range []struct {
		args []string
		path string
	}{
		{[]string{"routing", "status"}, "/api/v1/routing/effective?recent=5"},
		{[]string{"routing", "budgets", "list", "--json"}, "/api/v1/routing/budgets"},
		{[]string{"routing", "explain", "req-1"}, "/api/v1/routing/explain/req-1"},
	} {
		asked = nil
		out, err := run(tc.args...)
		if err != nil || len(asked) != 1 || asked[0] != tc.path || !strings.Contains(out, `"profile": "dev"`) {
			t.Fatalf("%v: err %v asked %v out %q", tc.args, err, asked, out)
		}
	}

	for _, args := range [][]string{{"routing"}, {"routing", "enable"}, {"routing", "budgets", "add", "b1"}, {"routing", "test", "hi"}} {
		asked = nil
		root := &cobra.Command{Use: "defenseclaw"}
		root.SetOut(io.Discard)
		root.SetErr(io.Discard)
		addManagedWindowsRoutingCommand(root, "standalone")
		root.SetArgs(args)
		err := root.Execute()
		if err == nil || !strings.Contains(err.Error(), "set by your administrator") || !strings.Contains(err.Error(), "Nothing was changed.") {
			t.Fatalf("%v: %v", args, err)
		}
		if rc := executeResult(root, err); rc != 3 {
			t.Fatalf("%v exit code %d, want 3", args, rc)
		}
		if len(asked) != 0 {
			t.Fatalf("%v reached the gateway: %v", args, asked)
		}
	}

	status, body = http.StatusForbidden, `{"error":"routing reads are for administrators here"}`
	_, err := run("routing", "status")
	var refused *routingReadError
	if !errors.As(err, &refused) || refused.status != http.StatusForbidden || !strings.Contains(err.Error(), "for administrators") {
		t.Fatalf("users_see none refusal: %v", err)
	}
}
