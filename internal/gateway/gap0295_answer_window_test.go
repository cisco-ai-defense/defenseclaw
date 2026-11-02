// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestGAP0295GatewayRecordsFirstHookAnswer(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux per-user answer window")
	}
	for _, tc := range []struct {
		name, deployment, profile string
		marked                    bool
	}{
		{"per-user", "", "", true},
		{"secure-client", "managed_enterprise", "secure_client", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "gateway.pid"), []byte("current\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			api := instructionProtectionTestAPI(t, "codex", "action", "HIGH")
			api.scannerCfg.DataDir = dir
			api.scannerCfg.DeploymentMode = tc.deployment
			api.scannerCfg.Enterprise.Profile = tc.profile
			answer := httptest.NewRecorder()
			api.writeHookAnswer(answer, []byte(`{"action":"allow"}`))
			if answer.Code != http.StatusOK {
				t.Fatalf("hook status = %d", answer.Code)
			}
			markers, err := filepath.Glob(filepath.Join(dir, "gateway.answer.*"))
			if err != nil {
				t.Fatal(err)
			}
			if got := len(markers) == 1; got != tc.marked {
				t.Fatalf("first answer marked = %t, want %t", got, tc.marked)
			}
		})
	}
}
