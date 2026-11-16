//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"syscall"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The Secure Client gateway runs as root, so its tokens are root:wheel and
// it starts degraded on a config failure. The standalone gateway runs as its
// service account, which owns the data_dir, and keeps exiting on a config
// failure.
func TestStandaloneProfileKeepsItsServiceOwnerAndConfigExit(t *testing.T) {
	dataDir := &syscall.Stat_t{Uid: 777, Gid: 778}
	t.Setenv(managed.EnterpriseProfileEnv, "")
	if uid, gid := enterpriseHookTokenOwnerPlatform(dataDir); uid != 0 || gid != 0 {
		t.Fatalf("Secure Client token owner = %d:%d, want 0:0", uid, gid)
	}
	if !managedServiceRetriesConfigLoadPlatform() {
		t.Fatal("a Secure Client service exits on a config failure")
	}
	if reason, unbounded := gatewayAuditOpenWait(); !unbounded || reason != gatewayAuditOpenWaitReason {
		t.Fatalf("Secure Client audit wait = %q, %v; want the unbounded repair wait", reason, unbounded)
	}

	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
	if uid, gid := enterpriseHookTokenOwnerPlatform(dataDir); uid != 777 || gid != 778 {
		t.Fatalf("standalone token owner = %d:%d, want the data_dir owner 777:778", uid, gid)
	}
	if managedServiceRetriesConfigLoadPlatform() {
		t.Fatal("a standalone service started degraded instead of exiting on a config failure")
	}
	if reason, unbounded := gatewayAuditOpenWait(); unbounded || reason != gatewayAuditGuardianWaitReason {
		t.Fatalf("standalone audit wait = %q, %v; want the bounded guardian wait", reason, unbounded)
	}
}
