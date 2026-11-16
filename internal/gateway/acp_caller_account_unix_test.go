//go:build linux || darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/acp"
)

// A managed Linux gateway runs with ProtectHome=yes, so the enrolled home
// cannot be found on disk: the home's owner must still be accepted, through
// the account database, and a copied credential presented by another account
// refused (GAP-1151).
func TestACPHomeCredentialBindsItsOwnerWhenTheGatewayCannotSeeHomes(t *testing.T) {
	const owner, borrower, unknown = 94404135, 94404136, 94404137
	home := filepath.Join(t.TempDir(), "hidden", "dcad-r103-eng1@dclab.test") // never created: hidden from the service
	principal := fmt.Sprintf("home:%x", sha256.Sum256([]byte(home)))
	cfg := acpGatewayTestConfig(t.TempDir(), "managed_enterprise")
	cfg.Enterprise.Profile = "standalone"
	api := &APIServer{scannerCfg: cfg}
	credential := acp.EnterpriseCredential{Principal: principal, UserDataDir: filepath.Join(home, "r105cto-acp")}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/acp/evaluate", nil)
	req = req.WithContext(withACPEnterpriseCredential(req.Context(), credential))
	previousPeer, previousHome := acpLoopbackPeerUID, managedHookPeerHome
	peer := owner
	acpLoopbackPeerUID = func(*http.Request) (int, error) { return peer, nil }
	managedHookPeerHome = func(uid int) string {
		switch uid {
		case owner:
			return home
		case borrower:
			return filepath.Join(filepath.Dir(home), "dcad-r103-eng2@dclab.test")
		}
		return ""
	}
	t.Cleanup(func() { acpLoopbackPeerUID, managedHookPeerHome = previousPeer, previousHome })
	if got := api.acpCallerAccountRefusal(req); got != "" {
		t.Fatalf("home owner refusal = %q, want none", got)
	}
	peer = borrower
	if got := api.acpCallerAccountRefusal(req); got != acpCallerAccountMismatchReason {
		t.Fatalf("copied home credential refusal = %q, want account mismatch", got)
	}
	peer = unknown
	if got := api.acpCallerAccountRefusal(req); got != acpCallerAccountUnverifiedReason {
		t.Fatalf("caller without a known home refusal = %q, want unverified", got)
	}
	peer = owner
	credential.UserDataDir = filepath.Join(filepath.Dir(home), "elsewhere")
	req = req.WithContext(withACPEnterpriseCredential(req.Context(), credential))
	if got := api.acpCallerAccountRefusal(req); got != acpCallerAccountMismatchReason {
		t.Fatalf("data dir outside the caller's home refusal = %q, want account mismatch", got)
	}
	credential.UserDataDir = ""
	req = req.WithContext(withACPEnterpriseCredential(req.Context(), credential))
	if got := api.acpCallerAccountRefusal(req); got != acpCallerAccountUnverifiedReason {
		t.Fatalf("home without a recorded directory refusal = %q, want unverified", got)
	}
}
