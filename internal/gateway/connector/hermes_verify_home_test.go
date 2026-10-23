// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hermespath"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// GAP-0499: Verify proves the hooks of the Hermes home the account's Hermes
// reads, or fails. A home that cannot be resolved left the generic reader
// with no config to read, and it reported the hooks present.
func TestHermesVerifyFailsWhenTheHermesHomeCannotBeResolved(t *testing.T) {
	previousOverride, previousResolver := HermesConfigPathOverride, hermesConfigPathResolver
	HermesConfigPathOverride = ""
	hermesConfigPathResolver = func() string { return "" }
	t.Cleanup(func() { HermesConfigPathOverride, hermesConfigPathResolver = previousOverride, previousResolver })

	dataDir := filepath.Join(testenv.PrivateTempDir(t), ".defenseclaw")
	for _, managed := range []bool{false, true} {
		present, err := OwnedHooksPresent(NewHermesConnector(), SetupOpts{DataDir: dataDir, ManagedEnterprise: managed})
		if present || err == nil || !strings.Contains(err.Error(), "not verified") {
			t.Fatalf("managed=%v: OwnedHooksPresent = %v, %v; want an unverified error for an unresolved Hermes home", managed, present, err)
		}
	}
	if err := NewHermesConnector().VerifyClean(SetupOpts{DataDir: dataDir}); err == nil {
		t.Fatal("VerifyClean must not report an unresolved Hermes home clean")
	}
}

// GAP-0499: Hermes started without HERMES_HOME runs from the profile its
// active_profile selects. Hooks in the default profile do not guard it, so
// Verify fails instead of reporting the default profile's hooks.
func TestHermesVerifyFailsWhenHermesRunsANamedProfile(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	configPath := filepath.Join(root, "hermes", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	previous := HermesConfigPathOverride
	HermesConfigPathOverride = configPath
	t.Cleanup(func() { HermesConfigPathOverride = previous })

	conn := NewHermesConnector()
	opts := prepareHermesSetupAdmissionFixture(t, SetupOpts{
		DataDir:  filepath.Join(root, ".defenseclaw"),
		APIAddr:  "127.0.0.1:18970",
		APIToken: "tok-test",
	})
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if present, err := OwnedHooksPresent(conn, opts); err != nil || !present {
		t.Fatalf("OwnedHooksPresent after Setup = %v, %v; want present", present, err)
	}

	activeProfile := filepath.Join(filepath.Dir(configPath), "active_profile")
	if err := os.WriteFile(activeProfile, []byte("coder\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	present, err := OwnedHooksPresent(conn, opts)
	if present || err == nil || !strings.Contains(err.Error(), "not verified") || !strings.Contains(err.Error(), `"coder"`) {
		t.Fatalf("OwnedHooksPresent with active profile coder = %v, %v; want an unverified error naming the profile", present, err)
	}
	if err := os.Remove(activeProfile); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(filepath.Dir(configPath), "profiles", "coder"), 0o700); err != nil {
		t.Fatal(err)
	}
	if present, err := OwnedHooksPresent(conn, opts); present || err == nil {
		t.Fatalf("OwnedHooksPresent with a named profile = %v, %v; want unverified", present, err)
	}
}

// GAP-0499: a service acting for an account (the managed guardian) sets up
// and verifies the Hermes home the account configured. When that home
// cannot be resolved, Setup refuses and Verify fails; only the lists of
// folders to watch or grant keep the profile default.
func TestManagedHermesSetupAndVerifyUseTheAccountsHermesHome(t *testing.T) {
	previous := HermesConfigPathOverride
	HermesConfigPathOverride = ""
	t.Cleanup(func() { HermesConfigPathOverride = previous })
	home := filepath.Join(testenv.PrivateTempDir(t), "Users", "target")
	custom := filepath.Join(home, "hermes-work")
	defaultConfig := hermespath.ConfigPathForUserHome(home)
	dataDir := filepath.Join(home, ".defenseclaw")

	restore := hermespath.OverrideAccountHomeForTest(func(string) (string, error) { return custom, nil })
	var got string
	if err := WithUserHomeDir(home, func() error { got = hermesConfigPath(SetupOpts{}); return nil }); err != nil {
		t.Fatal(err)
	}
	restore()
	if want := filepath.Join(custom, "config.yaml"); got != want {
		t.Fatalf("managed Hermes config = %q, want the account's configured home %q, not the default %q", got, want, defaultConfig)
	}

	restore = hermespath.OverrideAccountHomeForTest(func(string) (string, error) {
		return "", errors.New("the registry hive is not loaded")
	})
	t.Cleanup(restore)
	if err := WithUserHomeDir(home, func() error {
		if err := NewHermesConnector().Setup(context.Background(), SetupOpts{DataDir: dataDir, ManagedEnterprise: true}); err == nil || !strings.Contains(err.Error(), "registry hive") {
			t.Errorf("Setup = %v, want a refusal naming why the home cannot be resolved", err)
		}
		present, err := OwnedHooksPresent(NewHermesConnector(), SetupOpts{DataDir: dataDir, ManagedEnterprise: true})
		if present || err == nil || !strings.Contains(err.Error(), "not verified") {
			t.Errorf("OwnedHooksPresent = %v, %v; want not verified", present, err)
		}
		if got := hermesConfigPath(SetupOpts{}); got != defaultConfig {
			t.Errorf("watch and grant lists use %q, want the profile default %q", got, defaultConfig)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, statErr := os.Stat(dataDir); !os.IsNotExist(statErr) {
		t.Fatalf("a refused Setup must not write: %v", statErr)
	}
}
