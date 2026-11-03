// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"testing"
)

const secureClientShellRendersGoldenPath = "testdata/secure_client_shell_renders.golden.json"

// TestSecureClientShellRendersKeepPrePerfBytes pins every Secure Client shell
// render (8 connectors, each with its inspect scripts, fail mode open and
// closed, delivery on and off, scoped and legacy token: 320 files) to the
// bytes the hooks had before the 1.0.7 perf rewrite (f869816d41). Secure
// Client behaviour does not change in 1.0.7 (owner rule; review of
// 0f2e3b002c): its renders keep the pre-perf statements, and the helper takes
// its pre-perf path for them. The golden holds one sha256 per file; it is not
// regenerated from this tree.
func TestSecureClientShellRendersKeepPrePerfBytes(t *testing.T) {
	raw, err := os.ReadFile(secureClientShellRendersGoldenPath)
	if err != nil {
		t.Fatal(err)
	}
	var golden struct {
		Renders map[string]string `json:"renders"`
	}
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	names := make([]string, 0, len(connectorHookScripts))
	for name := range connectorHookScripts {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, conn := range names {
		for _, fm := range []string{"open", "closed"} {
			for _, scoped := range []bool{true, false} {
				token, kind := ".token", "legacy"
				if scoped {
					token, kind = ".token-"+conn, "scoped"
				}
				for _, delivery := range []bool{true, false} {
					scripts, err := renderHookScripts("127.0.0.1:18970", fm, token, connectorHookScripts[conn], true, conn, scoped, "", "", true, delivery, "")
					if err != nil {
						t.Fatal(err)
					}
					for _, s := range scripts {
						sum := sha256.Sum256(s.body)
						got[fmt.Sprintf("%s_%s_del%v/%s/%s", fm, kind, delivery, conn, s.name)] = hex.EncodeToString(sum[:])
					}
				}
			}
		}
	}
	if len(golden.Renders) != 320 {
		t.Fatalf("golden holds %d renders, want 320", len(golden.Renders))
	}
	var bad []string
	for key, want := range golden.Renders {
		if got[key] != want {
			bad = append(bad, key)
		}
	}
	for key := range got {
		if _, ok := golden.Renders[key]; !ok {
			bad = append(bad, key+" (not in the golden)")
		}
	}
	sort.Strings(bad)
	for i, key := range bad {
		if i == 20 {
			t.Errorf("... and %d more", len(bad)-20)
			break
		}
		t.Errorf("Secure Client render %s is not the pre-1.0.7 byte-for-byte render", key)
	}
}
