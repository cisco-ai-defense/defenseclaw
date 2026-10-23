// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// Review P1 (1.0.4 guard loop round 3): a revocation the operating system
// refused the gateway is saved as owed in the gateway's data directory. At
// every pass the guardian, as root or SYSTEM, rotates the key of each
// account named there, so the earlier allow is dead even while the gateway
// is down, and another account keeps its key. When every account's key is
// owed, or a saved one names no account (any doubt), every account's key
// is rotated. A lifecycle run in progress already removed every key.
func TestForeignHookGuardianEndsTheKeysTheGatewayOwes(t *testing.T) {
	skipForeignHookLedgerOnWindows(t)
	g := useForeignHookGuardian(t, nil)
	enterpriseForeignHookCanCreateSessionKey = func() bool { return true }
	process := runtime.GOOS + ":b:1:100"
	owedDir := enterprisepolicy.ForeignHookRevocationsOwedDir(cfg.DataDir)
	if err := os.MkdirAll(owedDir, 0o700); err != nil {
		t.Fatal(err)
	}
	owe := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(owedDir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	clearOwed := func() {
		t.Helper()
		if err := os.RemoveAll(owedDir); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(owedDir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	pass := func() string {
		t.Helper()
		var stderr bytes.Buffer
		ensureEnterpriseForeignHookSessionKey(&stderr)
		return stderr.String()
	}

	g.allow(t, "1001", process)
	g.allow(t, "1002", process)
	bobKey := g.key("1002")
	owe(filepath.Base(enterprisepolicy.ForeignHookRevocationOwedPath(cfg.DataDir, "1001")), "1001\n")
	if out := pass(); out != "" {
		t.Fatalf("the pass: %q", out)
	}
	if g.proves("1001", process) || g.key("1001") == "" {
		t.Fatalf("the pass must rotate the key whose revocation the gateway owes (key %q)", g.key("1001"))
	}
	if g.key("1002") != bobKey || !g.proves("1002", process) {
		t.Fatal("another account keeps its key and its allow")
	}
	if _, err := os.Lstat(enterprisepolicy.ForeignHookRevocationOwedPath(cfg.DataDir, "1001")); err != nil {
		t.Fatalf("the gateway settles what it saved, not the guardian: %v", err)
	}

	for name, entry := range map[string][2]string{
		"an entry that names no account": {"all-accounts", "all-accounts\n"},
		"a save cut short":               {filepath.Base(enterprisepolicy.ForeignHookRevocationOwedPath(cfg.DataDir, "1001")) + ".tmp", "10"},
		"a name that is not its own":     {filepath.Base(enterprisepolicy.ForeignHookRevocationOwedPath(cfg.DataDir, "1002")), "1001\n"},
	} {
		clearOwed()
		g.allow(t, "1001", process)
		g.allow(t, "1002", process)
		owe(entry[0], entry[1])
		if out := pass(); out != "" {
			t.Fatalf("%s: the pass: %q", name, out)
		}
		if g.proves("1001", process) || g.proves("1002", process) {
			t.Fatalf("%s: every account's key must be rotated", name)
		}
	}

	// A folder of owed revocations that cannot be read is every account's.
	clearOwed()
	g.allow(t, "1001", process)
	g.allow(t, "1002", process)
	if err := os.RemoveAll(owedDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(owedDir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if out := pass(); !strings.Contains(out, "owed revocations") {
		t.Fatalf("the pass must say the owed revocations could not be read: %q", out)
	}
	if g.proves("1001", process) || g.proves("1002", process) {
		t.Fatal("an unreadable folder of owed revocations must rotate every account's key")
	}
}
