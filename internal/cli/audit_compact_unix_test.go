// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestAuditCompactRootIsRefusedForAnotherAccountsPerUserStore(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the fixture must belong to an account other than root")
	}
	db := prunedAuditStore(t)
	cmd := useAuditCompact(t, db, false, 0)
	t.Setenv(managed.DeploymentModeEnv, "")
	previous := auditCompactCallerUID
	t.Cleanup(func() { auditCompactCallerUID = previous })
	auditCompactCallerUID = func() int { return 0 }
	err := runAuditCompact(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "belongs to another account; run it as that account, without sudo") {
		t.Fatalf("root compact of a user's store = %v", err)
	}
}

func TestAuditCompactRootOnAManagedComputerRunsAsTheGatewayServiceAccount(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the fixture must belong to an account other than root")
	}
	db := prunedAuditStore(t)
	before := auditCompactSize(t, db)
	cmd := useAuditCompact(t, db, false, 0)
	t.Setenv(managed.DeploymentModeEnv, managed.DeploymentModeManagedEnterprise)
	previousUID, previousRun, previousDeployment := auditCompactCallerUID, auditCompactRunAs, managedStandaloneAdminDeployment
	t.Cleanup(func() {
		auditCompactCallerUID, auditCompactRunAs, managedStandaloneAdminDeployment = previousUID, previousRun, previousDeployment
	})
	auditCompactCallerUID = func() int { return 0 }
	serviceUID, serviceGID := os.Getuid(), os.Getgid()
	managedStandaloneAdminDeployment = func() (managed.StandaloneLayout, *managed.RuntimeDescriptor, error) {
		return managed.StandaloneLayout{}, &managed.RuntimeDescriptor{ServiceUID: serviceUID, ServiceGID: serviceGID}, nil
	}
	var ranAs []uint32
	auditCompactRunAs = func(_ *cobra.Command, _ string, uid, gid uint32) error {
		ranAs = []uint32{uid, gid}
		return nil
	}
	if err := runAuditCompact(cmd, nil); err != nil {
		t.Fatalf("managed root compact: %v", err)
	}
	if len(ranAs) != 2 || ranAs[0] != uint32(serviceUID) || ranAs[1] != uint32(serviceGID) {
		t.Fatalf("ran as %v, want the service account %d:%d", ranAs, serviceUID, serviceGID)
	}
	if size := auditCompactSize(t, db); size != before {
		t.Fatalf("root compacted the store itself (%d -> %d bytes)", before, size)
	}

	// A store another account owns is refused.
	managedStandaloneAdminDeployment = func() (managed.StandaloneLayout, *managed.RuntimeDescriptor, error) {
		return managed.StandaloneLayout{}, &managed.RuntimeDescriptor{ServiceUID: serviceUID + 1, ServiceGID: serviceGID}, nil
	}
	ranAs = nil
	if err := runAuditCompact(cmd, nil); err == nil || ranAs != nil || !strings.Contains(err.Error(), "does not belong to the gateway service account") {
		t.Fatalf("managed root compact of a foreign store = %v (ran as %v)", err, ranAs)
	}
}

func TestAuditCompactIsRefusedToAStandardAccountOnAManagedComputer(t *testing.T) {
	t.Setenv(managed.ConfigPathEnv, "")
	t.Setenv("DEFENSECLAW_HOME", "")
	previousDeployment, previousUID := managedStandaloneAdminDeployment, managedHostCallerUID
	t.Cleanup(func() { managedStandaloneAdminDeployment, managedHostCallerUID = previousDeployment, previousUID })
	managedStandaloneAdminDeployment = func() (managed.StandaloneLayout, *managed.RuntimeDescriptor, error) {
		return managed.StandaloneLayout{}, &managed.RuntimeDescriptor{ServiceUID: 995, ServiceGID: 985}, nil
	}
	managedHostCallerUID = func() int { return 4242 }
	cmd := &cobra.Command{}
	err := auditCompactPersistentPreRunE(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "needs root (sudo) or the gateway service account") {
		t.Fatalf("standard account on a managed computer = %v", err)
	}
}
