// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func TestHermesAllowlistReadRejectsSymlinkAndOversize(t *testing.T) {
	dir := testenv.PrivateTempDir(t)
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte(`{"approvals":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "shell-hooks-allowlist.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := readHermesAllowlist(link); err == nil {
		t.Fatal("a linked allowlist was accepted")
	}
	large := filepath.Join(dir, "large.json")
	body := `{"approvals":[],"padding":"` + strings.Repeat("x", 2<<20) + `"}`
	if err := os.WriteFile(large, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readHermesAllowlist(large); err == nil {
		t.Fatal("an oversized allowlist was accepted")
	}
}

// A managed Hermes registration includes DefenseClaw's hook approvals: a
// user who empties shell-hooks-allowlist.json ('{}') makes the registration
// absent, so verify fails and the guardian's repair writes the approvals
// back into that same document.
func TestManagedHermesRegistrationRequiresOwnedApprovals(t *testing.T) {
	dir := testenv.PrivateTempDir(t)
	hermesHome := filepath.Join(dir, ".hermes")
	t.Setenv("HERMES_HOME", hermesHome)
	previousOverride := HermesConfigPathOverride
	HermesConfigPathOverride = ""
	t.Cleanup(func() { HermesConfigPathOverride = previousOverride })

	conn := NewHermesConnector()
	opts := SetupOpts{DataDir: filepath.Join(dir, "dc"), APIAddr: "127.0.0.1:18970", APIToken: "tok-test"}
	opts = prepareHermesSetupAdmissionFixture(t, opts)
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	managed := opts
	managed.ManagedEnterprise = true
	if present, err := conn.ownedHookContractPresent(managed); err != nil || !present {
		t.Fatalf("registration after setup present=%v err=%v", present, err)
	}
	movedHome := filepath.Join(dir, "moved-hermes-home")
	t.Setenv("HERMES_HOME", movedHome)
	if present, err := conn.ownedHookContractPresent(opts); err != nil || present {
		t.Fatalf("registration from former HERMES_HOME passed: present=%v err=%v", present, err)
	}
	t.Setenv("HERMES_HOME", hermesHome)

	allowlist := filepath.Join(hermesHome, hermesAllowlistFileName)
	if err := os.WriteFile(allowlist, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if present, err := conn.ownedHookContractPresent(managed); err != nil || present {
		t.Fatalf("emptied allowlist: present=%v err=%v, want absent", present, err)
	}
	if present, err := conn.ownedHookContractPresent(opts); err != nil || present {
		t.Fatalf("per-user registration without approvals passed: present=%v err=%v", present, err)
	}

	command := hermesConfiguredHookCommand(conn.hookCommand(opts), opts.HookExecutable)
	if err := patchHermesAllowlist(allowlist, command, conn.hookCommand(opts)); err != nil {
		t.Fatalf("repair of an emptied allowlist: %v", err)
	}
	if present, err := conn.ownedHookContractPresent(managed); err != nil || !present {
		t.Fatalf("after repair present=%v err=%v", present, err)
	}
}
