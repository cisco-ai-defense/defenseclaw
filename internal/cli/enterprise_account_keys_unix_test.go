// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bytes"
	"strings"
	"testing"
)

// managedGatewayInstalled makes the account-keys refusal see a managed
// install, or none.
func managedGatewayInstalled(t *testing.T, installed bool) {
	t.Helper()
	previous := enterpriseAccountKeysManagedInstalled
	enterpriseAccountKeysManagedInstalled = func(string) bool { return installed }
	t.Cleanup(func() { enterpriseAccountKeysManagedInstalled = previous })
}

func TestEnterpriseAccountKeysNeedsRoot(t *testing.T) {
	previous := enterpriseAccountKeysEUID
	enterpriseAccountKeysEUID = func() int { return 1000 }
	t.Cleanup(func() { enterpriseAccountKeysEUID = previous })
	managedGatewayInstalled(t, true)
	var out bytes.Buffer
	enterpriseAccountKeysCmd.SetOut(&out)
	err := runEnterpriseAccountKeys(enterpriseAccountKeysCmd)
	if err == nil || !strings.Contains(err.Error(), "administrator rights") || out.Len() != 0 {
		t.Fatalf("a standard user must get no keys: %v %q", err, out.String())
	}
}

// Through the command tree: the per-user root pre-run (config load, sidecar
// bootstrap) does not run, and a standard user is refused.
func TestEnterpriseAccountKeysCommandSkipsThePerUserStartup(t *testing.T) {
	previous := enterpriseAccountKeysEUID
	enterpriseAccountKeysEUID = func() int { return 1000 }
	t.Cleanup(func() { enterpriseAccountKeysEUID = previous })
	managedGatewayInstalled(t, true)
	t.Setenv("HOME", t.TempDir())
	var out, errOut bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&errOut)
	rootCmd.SetArgs([]string{"enterprise", "account-keys"})
	t.Cleanup(func() { rootCmd.SetArgs(nil); rootCmd.SetOut(nil); rootCmd.SetErr(nil) })
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "administrator rights") || strings.Contains(err.Error()+errOut.String(), "failed to load config") || out.Len() != 0 {
		t.Fatalf("got %v; stderr %q; stdout %q", err, errOut.String(), out.String())
	}
}

func TestEnterpriseAccountKeysOffDocument(t *testing.T) {
	var out bytes.Buffer
	if err := printEnterpriseAccountKeys(&out, nil); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != `{"schema_version":1,"account_join":{"state":"off","reason_codes":["feature_off"]}}` {
		t.Fatalf("off: %s", got)
	}
}

// rel-1-0-6:GAP-0417: on a per-user install (no managed gateway), a standard
// user's refusal said "run: sudo /opt/defenseclaw/bin/defenseclaw-gateway
// enterprise account-keys", a path that does not exist there. It now says the
// keys exist only on a managed install and names no command to run; on a
// managed install the sudo command stays, with the managed gateway's path.
func TestEnterpriseAccountKeysRefusalFitsTheInstallType(t *testing.T) {
	previous := enterpriseAccountKeysEUID
	enterpriseAccountKeysEUID = func() int { return 1000 }
	t.Cleanup(func() { enterpriseAccountKeysEUID = previous })
	for _, managed := range []bool{false, true} {
		var seen string
		prev := enterpriseAccountKeysManagedInstalled
		enterpriseAccountKeysManagedInstalled = func(path string) bool { seen = path; return managed }
		var out bytes.Buffer
		enterpriseAccountKeysCmd.SetOut(&out)
		err := runEnterpriseAccountKeys(enterpriseAccountKeysCmd)
		enterpriseAccountKeysManagedInstalled = prev
		if err == nil || out.Len() != 0 || !strings.HasSuffix(seen, "/bin/defenseclaw-gateway") {
			t.Fatalf("managed=%v: err %v, output %q, checked %q", managed, err, out.String(), seen)
		}
		message := err.Error()
		if managed {
			if !strings.Contains(message, "administrator rights; run: sudo ") || !strings.Contains(message, "/bin/defenseclaw-gateway enterprise account-keys") {
				t.Fatalf("managed install: want the sudo command, got %q", message)
			}
			continue
		}
		if strings.Contains(message, "sudo") || strings.Contains(message, "run:") ||
			!strings.Contains(message, "exist only on a managed (enterprise) install of DefenseClaw") ||
			!strings.Contains(message, "a per-user install has no account join keys to print") {
			t.Fatalf("per-user install: want the managed-only refusal and no command, got %q", message)
		}
	}
}
