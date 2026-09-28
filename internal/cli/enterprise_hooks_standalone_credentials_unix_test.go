// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package cli

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// The standalone guardian renders every per-user target over the hook
// socket with credentials bound to the target's uid, never the
// connector-scoped credential every user of the connector would share (the
// fixture fails the test if that minter runs).
func TestStandaloneReconcileRendersPerUserCredentialsOverTheHookSocket(t *testing.T) {
	uid, gid := os.Getuid(), os.Getgid()
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f := newStandaloneFixture(t, resolver)
	alice := f.home(t, "alice", 0o700)
	resolver.accounts["alice"] = unixidentity.Account{Name: "alice", UID: uid, GID: gid, Home: alice}
	f.writeManifest(t,
		enterprisehooks.ManifestTarget{User: "alice", Connector: "codex"},
		enterprisehooks.ManifestTarget{User: "alice", Connector: "openhands"},
	)
	run, err := runEnterpriseHookReconcileOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	requireLedgerOrStateTrust(t, run.StateErr)
	if run.Failures != 0 {
		t.Fatalf("rows = %+v", run.Rows)
	}
	identity := strconv.Itoa(uid)
	targets := f.workerTargets()
	for _, name := range []string{"codex", "openhands"} {
		target, ok := targets[name+"@"+alice]
		if !ok {
			t.Fatalf("%s: no worker target", name)
		}
		options := target.Options
		if options.APIToken != "hook-"+name+"-"+identity || options.OTLPPathToken != "otlp-"+name+"-"+identity {
			t.Fatalf("%s: credentials are not bound to uid %s: %q %q", name, identity, options.APIToken, options.OTLPPathToken)
		}
		if options.HookCredentialIdentity != identity {
			t.Fatalf("%s: credential identity = %q, want %q", name, options.HookCredentialIdentity, identity)
		}
		if options.ManagedHookSocket != "/run/defenseclaw-hook/hook.sock" || options.ManagedServiceUID != 995 {
			t.Fatalf("%s: transport = %q/%d, want the hook socket", name, options.ManagedHookSocket, options.ManagedServiceUID)
		}
	}
}

// Without the hook socket there is no transport a per-user hook may use:
// the row fails instead of being rendered for loopback TCP.
func TestStandaloneReconcileFailsPerUserTargetsWithoutTheHookSocket(t *testing.T) {
	uid, gid := os.Getuid(), os.Getgid()
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f := newStandaloneFixture(t, resolver)
	alice := f.home(t, "alice", 0o700)
	resolver.accounts["alice"] = unixidentity.Account{Name: "alice", UID: uid, GID: gid, Home: alice}
	f.writeManifest(t, enterprisehooks.ManifestTarget{User: "alice", Connector: "codex"})
	enterpriseHookStandaloneHookTransport = func() (string, int, error) {
		return "", 0, errors.New("enterprise hooks: the runtime descriptor names no hook socket; per-user hooks have no TCP fallback")
	}
	run, err := runEnterpriseHookReconcileOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	requireLedgerOrStateTrust(t, run.StateErr)
	if run.Failures != 1 || run.Rows[0].OK || !strings.Contains(run.Rows[0].Error, "no hook socket") {
		t.Fatalf("rows = %+v failures=%d", run.Rows, run.Failures)
	}
	if len(f.requests) != 0 {
		t.Fatalf("a worker was asked to render hooks without the hook socket: %+v", f.requests)
	}
}

// The single-target install renders what the reconcile renders: the hook
// socket and the target's own credentials, replacing whatever its caller
// resolved.
func TestStandaloneSingleTargetInstallUsesTheHookSocketAndPerUserCredentials(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("the single-target install refuses uid 0")
	}
	uid, gid := os.Getuid(), os.Getgid()
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f := newStandaloneFixture(t, resolver)
	alice := f.home(t, "alice", 0o700)
	resolver.accounts["alice"] = unixidentity.Account{Name: "alice", UID: uid, GID: gid, Home: alice}
	opts := enterprisehooks.InstallOptions{
		ConnectorName: "codex", UserHome: alice, OwnerUID: uid, OwnerGID: gid,
		APIToken: "connector-scoped", OTLPPathToken: "connector-scoped",
	}
	if _, err := enterpriseHookInstallTarget(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	identity := strconv.Itoa(uid)
	target := f.workerTargets()["codex@"+alice]
	if target.Options.APIToken != "hook-codex-"+identity || target.Options.OTLPPathToken != "otlp-codex-"+identity ||
		target.Options.HookCredentialIdentity != identity || target.Options.ManagedHookSocket != "/run/defenseclaw-hook/hook.sock" {
		t.Fatalf("single-target install options = %+v", target.Options)
	}

	enterpriseHookStandaloneHookTransport = func() (string, int, error) { return "", 0, errors.New("no hook socket") }
	before := len(f.requests)
	if _, err := enterpriseHookInstallTarget(context.Background(), opts); err == nil {
		t.Fatal("a single-target install without the hook socket must fail")
	}
	if len(f.requests) != before {
		t.Fatal("a worker was asked to render hooks without the hook socket")
	}
}
