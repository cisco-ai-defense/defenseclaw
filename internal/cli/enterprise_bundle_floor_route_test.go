// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterpriseunix"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// routeFloorDevice is a standalone managed Linux or macOS device with no
// bundle floor, two enrolled accounts with a route-only render each
// (alice: Claude Code, bob: Codex), and per-user workers that run the real
// restore in this process, one at a time (each real worker is its own
// process with its own home). failUID makes that account restore fail.
type routeFloorDevice struct {
	mu         sync.Mutex
	descriptor string
	routed     []string
	cfgErr     error
	homes      map[string]string
	asked      []enterpriseHookWorkerTarget
	failUID    map[int]bool
}

func newRouteFloorDevice(t *testing.T) *routeFloorDevice {
	t.Helper()
	root, layout, _ := anchorsInstallDevice(t)
	descriptor := filepath.Join(root, layout.DescriptorPath)
	if err := os.MkdirAll(filepath.Dir(descriptor), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(descriptor, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	d := &routeFloorDevice{descriptor: descriptor, homes: map[string]string{"alice": t.TempDir(), "bob": t.TempDir()}, failUID: map[int]bool{}}
	registry := connector.NewDefaultRegistry()
	for user, name := range map[string]string{"alice": "claudecode", "bob": "codex"} {
		route := &connector.RouteOnlySetup{BaseURL: "http://127.0.0.1:18970/r/" + name, Token: "dcr1-test-route-" + user}
		if drift := applyMachinePolicyRouteOnly(registry, withRoute(enterprisehooks.InstallOptions{ConnectorName: name, UserHome: d.homes[user]}, route)); drift != "" {
			t.Fatalf("render %s: %s", user, drift)
		}
	}
	uids := map[string]int{"alice": 4242, "bob": 4243}
	bindings := enterpriseHookUnixBindings{Bindings: map[string]enterpriseHookUnixBinding{
		enterpriseHookProtectedTargetKey(enterpriseHookReconcileRow{User: "alice", Connector: "claudecode"}): {UID: uids["alice"], Home: d.homes["alice"]},
		enterpriseHookProtectedTargetKey(enterpriseHookReconcileRow{User: "alice", Connector: "cursor"}):     {UID: uids["alice"], Home: d.homes["alice"]},
		enterpriseHookProtectedTargetKey(enterpriseHookReconcileRow{User: "bob", Connector: "codex"}):        {UID: uids["bob"], Home: d.homes["bob"]},
	}}
	accounts := map[string]unixidentity.Account{}
	for user, uid := range uids {
		accounts[user] = unixidentity.Account{Name: user, UID: uid, GID: uid, Home: d.homes[user]}
	}
	prevConfig, prevBindings, prevResolver, prevRunner := floorCheckInstalledConfig, floorCheckRouteBindings, floorCheckRouteResolver, enterpriseHookWorkerRunner
	t.Cleanup(func() {
		floorCheckInstalledConfig, floorCheckRouteBindings, floorCheckRouteResolver, enterpriseHookWorkerRunner = prevConfig, prevBindings, prevResolver, prevRunner
	})
	floorCheckInstalledConfig = func(*enterpriseunix.Env) (*config.Config, error) {
		if d.cfgErr != nil {
			return nil, d.cfgErr
		}
		cfg := &config.Config{DeploymentMode: "managed_enterprise"}
		cfg.Enterprise.Profile = "standalone"
		cfg.Routing.Enabled = len(d.routed) > 0
		cfg.Routing.RouteOnly = config.RoutingRouteOnlyConfig{Connectors: d.routed}
		return cfg, nil
	}
	floorCheckRouteBindings = func(*enterpriseunix.Env) enterpriseHookUnixBindings { return bindings }
	floorCheckRouteResolver = func() unixidentity.Resolver { return standaloneTestResolver{accounts: accounts} }
	enterpriseHookWorkerRunner = func(_ context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		d.mu.Lock()
		defer d.mu.Unlock()
		resp := enterpriseHookWorkerResponse{Version: enterpriseHookWorkerProtocolVersion}
		for _, target := range request.Targets {
			d.asked = append(d.asked, target)
			result := enterpriseHookWorkerTargetResult{Index: target.Index}
			drift := "settings.json is read-only"
			if !d.failUID[account.UID] {
				drift = applyMachinePolicyRouteOnly(registry, enterprisehooks.InstallOptions{ConnectorName: target.Options.ConnectorName, UserHome: target.Options.UserHome})
			}
			if result.OK = drift == ""; result.OK {
				result.Result = &enterprisehooks.InstallResult{Connector: target.Options.ConnectorName, UserHome: target.Options.UserHome}
			} else {
				result.Error = drift
			}
			resp.Targets = append(resp.Targets, result)
		}
		return resp, nil
	}
	return d
}

func (d *routeFloorDevice) floorCheck(version string) error {
	cmd := newEnterpriseBundleFloorCheckCommand()
	cmd.SetArgs([]string{"--product-version", version})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	return cmd.Execute()
}

// rendered reports whether the account file still holds its route render.
func (d *routeFloorDevice) rendered(t *testing.T, user string) bool {
	t.Helper()
	file := map[string]string{"alice": filepath.Join(".claude", "settings.json"), "bob": filepath.Join(".codex", "config.toml")}[user]
	raw, err := os.ReadFile(filepath.Join(d.homes[user], file))
	if err != nil {
		t.Fatalf("read %s file: %v", user, err)
	}
	return strings.Contains(string(raw), "dcr1-test-route-"+user)
}

func refusedWithFloorExit(t *testing.T, err error, code string) string {
	t.Helper()
	var coded *exitCodeError
	if !errors.As(err, &coded) || coded.ExitCode() != bundleFloorRefusedExit || !strings.Contains(err.Error(), code) {
		t.Fatalf("floor-check = %v; want exit %d with %s", err, bundleFloorRefusedExit, code)
	}
	return err.Error()
}

// rel-1-0-10 GAP-0647: the older package preinstall runs this floor-check
// before any file is replaced. While routing is on it refuses a release
// before 1.0.10 and names the routing-off step; the guardian would write the
// settings again, so nothing is taken back yet.
func TestFloorCheckRefusesADowngradeBelowRouteOnlyWhileRoutingIsOn(t *testing.T) {
	d := newRouteFloorDevice(t)
	d.routed = []string{"claudecode", "codex"}
	for _, version := range []string{"1.0.9", "1.0.4", "0.8.10"} {
		msg := refusedWithFloorExit(t, d.floorCheck(version), "route_only_downgrade_refused")
		for _, want := range []string{"claudecode, codex", "DefenseClaw " + version, "routing.route_only.connectors", "ensure --config", "enterprise bundle apply"} {
			if !strings.Contains(msg, want) {
				t.Fatalf("refusal %q does not name %q", msg, want)
			}
		}
		// The macOS pkg preinstall drops these from the message it records.
		if strings.ContainsAny(msg, "\"\\|&`\n") {
			t.Fatalf("refusal carries a character the pkg preinstall strips: %q", msg)
		}
	}
	if len(d.asked) != 0 || !d.rendered(t, "alice") || !d.rendered(t, "bob") {
		t.Fatalf("a refused downgrade touched the accounts: asked=%d", len(d.asked))
	}
	// An upgrade or a reinstall of a route-only release keeps every render.
	for _, version := range []string{"1.0.10", "1.0.10-rc.1", "1.0.11", "1.1.0"} {
		if err := d.floorCheck(version); err != nil {
			t.Fatalf("floor-check %s with routing on = %v; want pass", version, err)
		}
	}
	if len(d.asked) != 0 || !d.rendered(t, "alice") || !d.rendered(t, "bob") {
		t.Fatalf("an upgrade took renders back: asked=%d", len(d.asked))
	}
}

// With routing off, the downgrade takes back every route render still left,
// as each account, before the older files land; a second run changes
// nothing, and an account it could not reach refuses the downgrade.
func TestFloorCheckTakesBackRouteRendersBeforeADowngradeWithRoutingOff(t *testing.T) {
	d := newRouteFloorDevice(t)
	d.failUID[4243] = true
	msg := refusedWithFloorExit(t, d.floorCheck("1.0.9"), "route_only_restore_incomplete")
	if !strings.Contains(msg, "bob codex") || strings.Contains(msg, "alice") || !strings.Contains(msg, "1 enrolled account") {
		t.Fatalf("refusal names the wrong accounts: %q", msg)
	}
	if d.rendered(t, "alice") || !d.rendered(t, "bob") {
		t.Fatal("alice must be taken back and the failed bob render kept")
	}
	for _, target := range d.asked {
		if target.Mode != enterpriseHookWorkerModeRestoreMachineRoute || target.Options.ConnectorName == "cursor" {
			t.Fatalf("unexpected worker target %+v", target)
		}
	}
	delete(d.failUID, 4243)
	for range 2 {
		if err := d.floorCheck("1.0.9"); err != nil {
			t.Fatalf("floor-check with routing off = %v", err)
		}
	}
	if d.rendered(t, "alice") || d.rendered(t, "bob") {
		t.Fatal("a route render is left after the downgrade check")
	}
}

// No deployment (an uninstall, also --keep-state, removed the descriptor and
// took the settings back; the kept floor checker answers with config.yaml
// still routing) or no deployed config: nothing to check. A config that
// cannot be read leaves only the take-back.
func TestFloorCheckRouteOnlyWithoutADeployedConfig(t *testing.T) {
	d := newRouteFloorDevice(t)
	d.routed = []string{"claudecode"}
	if err := os.Remove(d.descriptor); err != nil {
		t.Fatal(err)
	}
	if err := d.floorCheck("1.0.9"); err != nil || len(d.asked) != 0 {
		t.Fatalf("after an uninstall: err=%v asked=%d", err, len(d.asked))
	}
	if err := os.WriteFile(d.descriptor, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	d.routed = nil
	d.cfgErr = fs.ErrNotExist
	if err := d.floorCheck("1.0.9"); err != nil || len(d.asked) != 0 || !d.rendered(t, "alice") {
		t.Fatalf("no deployment: err=%v asked=%d", err, len(d.asked))
	}
	// A config that exists but cannot be read may still route: the guardian
	// keeps the routing it loaded, so the downgrade is refused and no
	// render is taken back (T-UPGRADE review F3).
	d.cfgErr = errors.New("config_invalid")
	if err := d.floorCheck("1.0.9"); err == nil || !strings.Contains(err.Error(), "route_only_downgrade_refused") || len(d.asked) != 0 || !d.rendered(t, "alice") {
		t.Fatalf("unreadable config: err=%v asked=%d, want a refusal with the renders kept", err, len(d.asked))
	}
}
