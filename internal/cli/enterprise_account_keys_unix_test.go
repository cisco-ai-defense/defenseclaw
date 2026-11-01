// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestEnterpriseAccountKeysNeedsRoot(t *testing.T) {
	previous := enterpriseAccountKeysEUID
	enterpriseAccountKeysEUID = func() int { return 1000 }
	t.Cleanup(func() { enterpriseAccountKeysEUID = previous })
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
