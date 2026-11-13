// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"io"
	"net/http"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// REVIEW-s13-p1-merge F1: a standard account on a managed computer (no
// per-user CLI there) reads its own routing through the installed binary;
// every routing write gets the managed answer and reaches no gateway.
func TestManagedRoutingServesOwnReadsOnly(t *testing.T) {
	var asked []string
	status, body := http.StatusOK, `{"profile":"dev","recent":[]}`
	old := managedRoutingRead
	managedRoutingRead = func(_ context.Context, path string) (int, []byte, error) {
		asked = append(asked, path)
		return status, []byte(body), nil
	}
	t.Cleanup(func() { managedRoutingRead = old })

	run := func(args ...string) (string, *cobra.Command, error) {
		root := &cobra.Command{Use: "defenseclaw"}
		var out strings.Builder
		root.SetOut(&out)
		root.SetErr(io.Discard)
		root.AddCommand(newManagedRoutingCmd())
		root.SetArgs(args)
		err := root.Execute()
		return out.String(), root, err
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
		out, _, err := run(tc.args...)
		if err != nil || len(asked) != 1 || asked[0] != tc.path || !strings.Contains(out, `"profile": "dev"`) {
			t.Fatalf("%v: err %v asked %v out %q", tc.args, err, asked, out)
		}
	}

	for _, args := range [][]string{{"routing"}, {"routing", "enable"}, {"routing", "budgets", "add", "b1"}, {"routing", "test", "hi"}} {
		asked = nil
		_, root, err := run(args...)
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
	_, _, err := run("routing", "status")
	var refused *routingReadError
	if !errors.As(err, &refused) || refused.status != http.StatusForbidden || !strings.Contains(err.Error(), "for administrators") {
		t.Fatalf("users_see none refusal: %v", err)
	}
}

// REVIEW-final F2: a refused routing write is reported by its command words
// (from the table) on every managed OS; reads, help and the bare group are not.
func TestManagedRoutingReportsRefusedWritesOnly(t *testing.T) {
	previous, previousRead := reportManagedCommandRefusal, managedRoutingRead
	var reported []string
	reportManagedCommandRefusal = func(command, reason string) { reported = append(reported, command+":"+reason) }
	managedRoutingRead = func(context.Context, string) (int, []byte, error) { return http.StatusOK, []byte(`{}`), nil }
	t.Cleanup(func() { reportManagedCommandRefusal, managedRoutingRead = previous, previousRead })

	// Windows: the routing tree is a real command of defenseclaw.exe.
	for _, args := range [][]string{
		{"routing", "enable"}, {"routing", "budgets", "remove", "team-cap"},
		{"routing", "budgets", "add", "b1", "--limit-usd", "5"}, {"routing", "rules", "add", "--action", "deny"},
		{"routing"}, {"routing", "budgets"}, {"routing", "test", "hi"}, {"routing", "status"},
		{"routing", "models", "list"},
	} {
		root := &cobra.Command{Use: "defenseclaw"}
		root.SetOut(io.Discard)
		root.SetErr(io.Discard)
		root.AddCommand(newManagedRoutingCmd())
		root.SetArgs(args)
		err := root.Execute()
		reads := len(args) == 2 && args[1] == "status"
		if reads != (err == nil) {
			t.Fatalf("%v: %v", args, err)
		}
		if !reads && executeResult(root, err) != 3 {
			t.Fatalf("%v: exit %d, want the managed answer (3)", args, executeResult(root, err))
		}
	}
	// Linux and macOS: the launcher refuses the writes before the tree runs.
	for _, args := range [][]string{{"routing", "pricing", "set", "m"}, {"routing", "setup", "--help"}, {"routing", "rules", "list"}} {
		root := &cobra.Command{Use: "defenseclaw"}
		root.SetErr(io.Discard)
		if code := executeLauncherInTest(t, root, args); code != 2 {
			t.Fatalf("%v: exit %d, want the launcher refusal", args, code)
		}
	}
	if got, want := strings.Join(reported, ","), "routing enable:,routing budgets remove:,routing budgets add:,routing rules add:,routing pricing set:"; got != want {
		t.Fatalf("reported %q, want %q", got, want)
	}
}

// REVIEW-final F1: the launcher keeps the routing reads in the tree it runs.
func TestLauncherRunsTheRoutingReads(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("the launcher is a Linux and macOS command")
	}
	previous := managedRoutingRead
	var asked []string
	managedRoutingRead = func(_ context.Context, path string) (int, []byte, error) {
		asked = append(asked, path)
		return http.StatusOK, []byte(`{"profile":"dev"}`), nil
	}
	t.Cleanup(func() { managedRoutingRead = previous })
	for _, tc := range []struct {
		args []string
		path string
	}{
		{[]string{"routing", "status"}, "/api/v1/routing/effective?recent=5"},
		{[]string{"routing", "budgets", "list"}, "/api/v1/routing/budgets"},
		{[]string{"routing", "explain", "req-1"}, "/api/v1/routing/explain/req-1"},
	} {
		var ran []string
		asked = nil
		root := launcherTestRoot(&ran)
		var out strings.Builder
		root.SetOut(&out)
		root.SetErr(io.Discard)
		if code := executeLauncherInTest(t, root, tc.args); code != 0 || len(asked) != 1 || asked[0] != tc.path || !strings.Contains(out.String(), `"profile": "dev"`) {
			t.Fatalf("%v: exit %d asked %v out %q", tc.args, code, asked, out.String())
		}
	}
	var ran []string
	root := launcherTestRoot(&ran)
	var out strings.Builder
	root.SetOut(&out)
	root.SetErr(io.Discard)
	asked = nil
	if code := executeLauncherInTest(t, root, []string{"routing", "status", "--help"}); code != 0 || !strings.Contains(out.String(), "recent decisions") || len(asked) != 0 {
		t.Fatalf("routing status --help: exit %d out %q asked %v", code, out.String(), asked)
	}
}

// The launcher (Linux, macOS) runs the three reads and nothing else of routing.
func TestLauncherOffersOnlyTheRoutingReads(t *testing.T) {
	for _, args := range [][]string{{"routing", "status"}, {"routing", "budgets", "list"}, {"routing", "explain", "x"}} {
		if !launcherOffers(args) {
			t.Errorf("the launcher refuses %v", args)
		}
	}
	for _, args := range [][]string{{"routing"}, {"routing", "enable"}, {"routing", "budgets", "add", "b"}, {"routing", "test", "hi"}} {
		if launcherOffers(args) {
			t.Errorf("the launcher runs %v", args)
		}
	}
}
