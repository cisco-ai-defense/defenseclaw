// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

const (
	gap1892ValidAuthorization = `{"version":1,"updated_at":"2026-11-23T00:00:00Z","ok":true,"target_count":0,` +
		`"success_count":0,"failure_count":0,"protected_targets":[]}`
	gap1892ValidState = `{"version":1,"updated_at":"2026-11-23T00:00:00Z","manifest":"m","ok":true,` +
		`"target_count":0,"success_count":0,"failure_count":0,"results":[]}`
)

// TestGAP1892TeardownRefusesWithoutReadableGuardianRecords: the teardown
// leaves a failed account out of its expected set only on the Guardian's own
// protected records. When the authorization ledger or the state is missing,
// is not a regular file or does not parse, the teardown must refuse, never
// fall back to a smaller expected set (GAP-1892 review RV1892).
func TestGAP1892TeardownRefusesWithoutReadableGuardianRecords(t *testing.T) {
	failed := []windowsManagedHooksTeardownTarget{gap1892Target("copilot", gap1892Bob, "bob")}
	missing := "missing its protected Guardian activation evidence"
	originalTrust, originalConfig := enterpriseHookAuthorizationFileTrustCheck, cfg
	t.Cleanup(func() { enterpriseHookAuthorizationFileTrustCheck, cfg = originalTrust, originalConfig })
	enterpriseHookAuthorizationFileTrustCheck = func(string) error { return nil }
	cfg = nil
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, "")

	cases := []struct {
		name          string
		authorization string // "" = absent, "<dir>" = a directory, else file content
		state         string
		wantError     string // "" = must succeed
	}{
		{"both records valid", gap1892ValidAuthorization, gap1892ValidState, ""},
		{"both records missing", "", "", missing},
		{"authorization missing", "", gap1892ValidState, missing},
		{"state missing", gap1892ValidAuthorization, "", missing},
		{"authorization is a directory", "<dir>", gap1892ValidState, "not a regular file"},
		{"state is a directory", gap1892ValidAuthorization, "<dir>", "not a regular file"},
		{"authorization does not parse", `{"version":`, gap1892ValidState, "parse hook guardian authorization"},
		{"state does not parse", gap1892ValidAuthorization, `{"version":`, "parse hook guardian state"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := t.TempDir()
			place := func(path, content string) {
				t.Helper()
				switch content {
				case "":
					return
				case "<dir>":
					if err := os.MkdirAll(path, 0o750); err != nil {
						t.Fatal(err)
					}
				default:
					if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
						t.Fatal(err)
					}
				}
			}
			place(managed.HookGuardianAuthorizationPath(dataDir), tc.authorization)
			place(filepath.Join(dataDir, hookGuardianStateFile), tc.state)

			unenrolled, err := windowsManagedHooksTeardownUnenrolledFromGuardian(dataDir, failed)
			if tc.wantError == "" {
				if err != nil {
					t.Fatalf("valid records: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected a refusal, got unenrolled targets %v", unenrolled)
			}
			if !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.wantError)
			}
			if unenrolled != nil {
				t.Fatalf("a refusal returned targets %v", unenrolled)
			}
		})
	}
}
