// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookexec

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/daemon"
)

func TestGAP0712MovedStoreNamesTheAccountPIDHome(t *testing.T) {
	account := t.TempDir()
	installHome := filepath.Join(account, ".defenseclaw")
	store := t.TempDir()
	if err := os.Mkdir(installHome, 0o700); err != nil {
		t.Fatal(err)
	}
	oldAccountHome, oldHolder, oldClass := perUserAccountHome, perUserPortHolder, perUserListenerClass
	t.Cleanup(func() {
		perUserAccountHome, perUserPortHolder, perUserListenerClass = oldAccountHome, oldHolder, oldClass
	})
	perUserAccountHome = func() string { return account }
	perUserPortHolder = func(string, int) (daemon.PortHolder, error) {
		return daemon.PortHolder{PID: 1234, UID: 0}, nil
	}
	perUserListenerClass = func(_ string, _ int, home string, _ daemon.PortHolder, _ error, _ bool) daemon.PerUserListenerClass {
		if home == installHome {
			return daemon.PerUserListenerOwnGatewayRunAsRoot
		}
		return daemon.PerUserListenerForeign
	}
	opts := Options{Home: store, HookDir: filepath.Join(store, "hooks"), APIAddr: "127.0.0.1:19100"}
	reason := perUserRootGatewayReason(opts)
	if !strings.Contains(reason, daemon.RootGatewayListenerReason) ||
		!strings.Contains(reason, "DEFENSECLAW_HOME='"+installHome+"'") ||
		strings.Contains(reason, "DEFENSECLAW_HOME='"+store+"'") {
		t.Fatalf("moved-store diagnosis = %q, want the account PID home", reason)
	}
	perUserListenerClass = func(string, int, string, daemon.PortHolder, error, bool) daemon.PerUserListenerClass {
		return daemon.PerUserListenerForeign
	}
	if reason := perUserRootGatewayReason(opts); reason != "" {
		t.Fatalf("unmatched listener diagnosis = %q, want no root claim", reason)
	}
}

func TestGAP0712ShellNamesVerifiedRootGatewayHome(t *testing.T) {
	installHome := t.TempDir()
	reason := daemon.RootGatewayListenerReason + " " + daemon.RootGatewayListenerRemedy(installHome)
	check := func(marker, managed, want string) {
		t.Helper()
		cmd := exec.Command("bash", "-c", `. "$1"
API_ADDR=127.0.0.1:19100
RESPONSE="$DC_MARKER"
DEFENSECLAW_MANAGED_HOOK="$DC_MANAGED"
defenseclaw_api_listener_unproven() { return 0; }
defenseclaw_gateway_unreachable_reason`, "bash", filepath.Join("..", "hooks", "_hardening.sh"))
		cmd.Env = append(os.Environ(), "DC_MARKER="+marker, "DC_MANAGED="+managed)
		out, err := cmd.CombinedOutput()
		if err != nil || string(out) != want {
			t.Fatalf("shell diagnosis = %q, err=%v, want %q", out, err, want)
		}
	}
	check("DCPOSTROOT1:"+reason, "0", reason)
	check("", "0", "127.0.0.1:19100 is not proven to be this account's gateway; no token or payload was sent to it. Another account may hold the port. Run `defenseclaw setup gateway --api-port <free-port>` to choose a free port")
	check("DCPOSTROOT1:"+reason, "1", "gateway unreachable")
}

func TestGAP0712ShellPostCarriesVerifiedRootReason(t *testing.T) {
	bin := t.TempDir()
	store := t.TempDir()
	hooks := filepath.Join(store, "hooks")
	if err := os.Mkdir(hooks, 0o700); err != nil {
		t.Fatal(err)
	}
	gateway := filepath.Join(bin, "defenseclaw-gateway")
	post := filepath.Join(bin, "defenseclaw-hook-post")
	if err := os.WriteFile(gateway, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(post, []byte("#!/bin/sh\nprintf '%s' \"$DC_NATIVE_MARKER\"\nexit 8\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	reason := daemon.RootGatewayListenerReason + " " + daemon.RootGatewayListenerRemedy(store)
	script := `. "$1"
API_ADDR=127.0.0.1:19100
HOOK_DIR="$DC_HOOK_DIR"
defenseclaw_gateway_binary() { _DC_GATEWAY_BINARY="$DC_GATEWAY"; }
defenseclaw_api_listener_unproven() { return 0; }
RESPONSE=$(defenseclaw_gateway_post "http://${API_ADDR}/api/v1/claude-code/hook" 2 '{}' -H 'Content-Type: application/json') || :
defenseclaw_gateway_unreachable_reason`
	cmd := exec.Command("bash", "-c", script, "bash", filepath.Join("..", "hooks", "_hardening.sh"))
	cmd.Env = append(os.Environ(), "DC_HOOK_DIR="+hooks, "DC_GATEWAY="+gateway, "DC_NATIVE_MARKER=DCPOSTROOT1:"+reason)
	out, err := cmd.CombinedOutput()
	if err != nil || string(out) != reason {
		t.Fatalf("shell post diagnosis = %q, err=%v, want %q", out, err, reason)
	}
}

func TestGAP0712CustomInstallUsesItsRecordedConfigHome(t *testing.T) {
	installHome := t.TempDir()
	store := t.TempDir()
	hooks := filepath.Join(store, "hooks")
	if err := os.Mkdir(hooks, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(installHome, "config.yaml")
	if err := os.WriteFile(configPath, []byte("config_version: 9\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hooks, ".config-record"), []byte(configPath+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldHolder, oldClass := perUserPortHolder, perUserListenerClass
	t.Cleanup(func() {
		perUserPortHolder, perUserListenerClass = oldHolder, oldClass
	})
	perUserPortHolder = func(string, int) (daemon.PortHolder, error) {
		return daemon.PortHolder{PID: 1234, UID: 0}, nil
	}
	perUserListenerClass = func(_ string, _ int, home string, _ daemon.PortHolder, _ error, _ bool) daemon.PerUserListenerClass {
		if home == installHome {
			return daemon.PerUserListenerOwnGatewayRunAsRoot
		}
		return daemon.PerUserListenerForeign
	}
	opts := Options{Home: store, HookDir: hooks, APIAddr: "127.0.0.1:19100"}
	if reason := perUserRootGatewayReason(opts); !strings.Contains(reason, "DEFENSECLAW_HOME='"+installHome+"'") {
		t.Fatalf("recorded-home diagnosis = %q, want the install home", reason)
	}
	if err := os.Chmod(filepath.Join(hooks, ".config-record"), 0o666); err != nil {
		t.Fatal(err)
	}
	if reason := perUserRootGatewayReason(opts); reason != "" {
		t.Fatalf("untrusted record diagnosis = %q, want no root claim", reason)
	}
}
