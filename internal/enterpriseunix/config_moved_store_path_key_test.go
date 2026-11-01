// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var movedStorePathKeys = map[string]string{
	"audit_db":        "observability.local.path",
	"judge_bodies_db": "observability.local.judge_bodies_path",
}

// rel-1-0-6 GAP-0188: ensure --config of an administrator config that still
// carries a top-level audit_db or judge_bodies_db (0.8.x store paths) is
// refused on Linux and macOS, and the refusal names the key that replaced
// it, as config migrate does. A nested key of that name keeps the plain
// answer.
func TestManagedEnsureNamesTheKeyAMovedStorePathKeyBecame(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			write := func(body string) string {
				path := filepath.Join(t.TempDir(), "admin.yaml")
				if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
				return path
			}
			clean := string(DefaultConfig(h.env.Layout))
			for key, home := range movedStorePathKeys {
				path := write(clean + key + ": /var/tmp/store.db\n")
				r := h.run(Options{Action: ActionEnsure, ConfigFile: path})
				requireError(t, r, codeConfig)
				got := r.Errors[0].Message
				if !strings.HasPrefix(got, path) || !strings.Contains(got, key+" is an unknown setting; it moved to "+home+".") ||
					!strings.Contains(got, "The settings reference") {
					t.Fatalf("%s: ensure refusal = %q, want it to name %s", key, got, home)
				}
			}
			nested := write(strings.Replace(clean, "guardrail:\n", "guardrail:\n  audit_db: /var/tmp/store.db\n", 1))
			r := h.run(Options{Action: ActionEnsure, ConfigFile: nested})
			requireError(t, r, codeConfig)
			if got := r.Errors[0].Message; !strings.Contains(got, "guardrail.audit_db is an unknown setting.") || strings.Contains(got, "moved") {
				t.Fatalf("nested audit_db refusal = %q", got)
			}
			requireOK(t, h.run(Options{Action: ActionEnsure, ConfigFile: write(clean)}))
		})
	}
}
