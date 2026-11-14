//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// rel-1-0-10 GAP-0568: the worker writes a machine-policy connector's route
// render into the account's own agent file, verifies it, and takes it back.
func TestMachinePolicyRouteRenderVerifyRestore(t *testing.T) {
	registry := connector.NewDefaultRegistry()
	for _, tc := range []struct {
		name, file, marker string
	}{
		{"codex", filepath.Join(".codex", "config.toml"), "defenseclaw_route"},
		{"claudecode", filepath.Join(".claude", "settings.json"), connector.RouteOnlyHeader},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			route := &connector.RouteOnlySetup{BaseURL: "http://127.0.0.1:18970/r/" + tc.name, Token: "dcr1-test-route-" + tc.name}
			opts := enterprisehooks.InstallOptions{ConnectorName: tc.name, UserHome: home, OwnerUID: os.Getuid(), OwnerGID: os.Getgid()}
			if err := verifyMachinePolicyRouteOnly(registry, withRoute(opts, route)); err == nil {
				t.Fatal("verify passes with no render")
			}
			if drift := applyMachinePolicyRouteOnly(registry, withRoute(opts, route)); drift != "" {
				t.Fatalf("render: %s", drift)
			}
			raw, err := os.ReadFile(filepath.Join(home, tc.file))
			if err != nil || !strings.Contains(string(raw), tc.marker) || !strings.Contains(string(raw), route.Token) || !strings.Contains(string(raw), "/r/"+tc.name) {
				t.Fatalf("render missing from the account file: %v %s", err, raw)
			}
			if err := verifyMachinePolicyRouteOnly(registry, withRoute(opts, route)); err != nil {
				t.Fatalf("verify after render: %v", err)
			}
			rotated := *route
			rotated.Token = "dcr1-test-route-rotated"
			if err := verifyMachinePolicyRouteOnly(registry, withRoute(opts, &rotated)); err == nil || !strings.Contains(err.Error(), "route_config_drift") {
				t.Fatalf("a stale credential is not drift: %v", err)
			}
			if drift := applyMachinePolicyRouteOnly(registry, withRoute(opts, nil)); drift != "" {
				t.Fatalf("restore: %s", drift)
			}
			raw, _ = os.ReadFile(filepath.Join(home, tc.file))
			if strings.Contains(string(raw), route.Token) || strings.Contains(string(raw), "/r/"+tc.name) {
				t.Fatalf("restore left the render: %s", raw)
			}
			if err := verifyMachinePolicyRouteOnly(registry, withRoute(opts, nil)); err != nil {
				t.Fatalf("verify after restore with routing off: %v", err)
			}
		})
	}
}

func TestMachinePolicyRouteRestoreTouchesNothingUnrendered(t *testing.T) {
	home := t.TempDir()
	opts := enterprisehooks.InstallOptions{ConnectorName: "claudecode", UserHome: home}
	if drift := applyMachinePolicyRouteOnly(connector.NewDefaultRegistry(), opts); drift != "" {
		t.Fatalf("restore with nothing rendered: %s", drift)
	}
	if _, err := os.Stat(filepath.Join(home, ".claude")); !os.IsNotExist(err) {
		t.Fatalf("a restore with nothing rendered created the agent folder: %v", err)
	}
}

func withRoute(opts enterprisehooks.InstallOptions, route *connector.RouteOnlySetup) enterprisehooks.InstallOptions {
	opts.RouteOnly = route
	return opts
}

func TestRollbackTargetLacksRouteOnly(t *testing.T) {
	for target, want := range map[string]bool{"1.0.9": true, "1.0.0": true, "0.8.10": true, "": true, "junk": true, "1.0.10": false, "1.0.11": false, "1.1.0": false, "2.0.0": false, "v1.0.9": true} {
		if got := rollbackTargetLacksRouteOnly(target); got != want {
			t.Fatalf("%q: %v, want %v", target, got, want)
		}
	}
}

// A departed machine route binding is taken back as the account; a failed
// or not-yet-resolvable restore keeps the binding, a gone account drops it.
func TestRestoreDepartedMachineRoutes(t *testing.T) {
	home := t.TempDir()
	uid, gid := os.Getuid(), os.Getgid()
	prevRunner := enterpriseHookWorkerRunner
	t.Cleanup(func() { enterpriseHookWorkerRunner = prevRunner })
	var asked []enterpriseHookWorkerTarget
	fail := false
	enterpriseHookWorkerRunner = func(_ context.Context, _ enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		resp := enterpriseHookWorkerResponse{Version: enterpriseHookWorkerProtocolVersion}
		for _, target := range request.Targets {
			asked = append(asked, target)
			result := enterpriseHookWorkerTargetResult{Index: target.Index, OK: !fail, Error: map[bool]string{true: "boom"}[fail]}
			if !fail {
				result.Result = &enterprisehooks.InstallResult{Connector: target.Options.ConnectorName, UserHome: target.Options.UserHome}
			}
			resp.Targets = append(resp.Targets, result)
		}
		return resp, nil
	}
	key := enterpriseHookProtectedTargetKey(enterpriseHookReconcileRow{User: "alice", Connector: "claudecode"})
	other := enterpriseHookProtectedTargetKey(enterpriseHookReconcileRow{User: "alice", Connector: "cursor"})
	previous := enterpriseHookUnixBindings{Bindings: map[string]enterpriseHookUnixBinding{key: {UID: uid, Home: home}, other: {UID: uid, Home: home}}}
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{"alice": {Name: "alice", UID: uid, GID: gid, Home: home}}}
	next := enterpriseHookUnixBindings{Bindings: map[string]enterpriseHookUnixBinding{}}
	restoreDepartedEnterpriseHookMachineRoutes(context.Background(), previous, next, resolver)
	if len(asked) != 1 || asked[0].Mode != enterpriseHookWorkerModeRestoreMachineRoute || asked[0].Options.ConnectorName != "claudecode" {
		t.Fatalf("restore jobs = %+v", asked)
	}
	if _, kept := next.Bindings[key]; kept {
		t.Fatal("a restored binding must be dropped")
	}
	fail, asked = true, nil
	restoreDepartedEnterpriseHookMachineRoutes(context.Background(), previous, next, resolver)
	if _, kept := next.Bindings[key]; !kept {
		t.Fatal("a failed restore must keep the binding for the next pass")
	}
	delete(next.Bindings, key)
	fail = false
	transient := standaloneTestResolver{accounts: resolver.accounts, transient: map[string]bool{"alice": true}}
	restoreDepartedEnterpriseHookMachineRoutes(context.Background(), previous, next, transient)
	if _, kept := next.Bindings[key]; !kept {
		t.Fatal("an account the directory cannot answer for now must keep its binding")
	}
	delete(next.Bindings, key)
	asked = nil
	restoreDepartedEnterpriseHookMachineRoutes(context.Background(), previous, next, standaloneTestResolver{})
	if _, kept := next.Bindings[key]; kept || len(asked) != 0 {
		t.Fatalf("a gone account: kept=%v asked=%d", kept, len(asked))
	}
}
