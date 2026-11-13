// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

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

	// A descriptor with no service group is refused (root's group 0 must
	// never reach the child).
	managedStandaloneAdminDeployment = func() (managed.StandaloneLayout, *managed.RuntimeDescriptor, error) {
		return managed.StandaloneLayout{}, &managed.RuntimeDescriptor{ServiceUID: serviceUID, ServiceGID: 0}, nil
	}
	ranAs = nil
	if err := runAuditCompact(cmd, nil); err == nil || ranAs != nil {
		t.Fatalf("managed root compact with service gid 0 = %v (ran as %v)", err, ranAs)
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

func TestAuditCompactServiceChildGetsOnlyThePinsLocaleAndPath(t *testing.T) {
	values := map[string]string{
		managed.ConfigPathEnv:                   "/etc/defenseclaw/config.yaml",
		"DEFENSECLAW_HOME":                      "/var/lib/defenseclaw",
		managed.DeploymentModeEnv:               managed.DeploymentModeManagedEnterprise,
		managed.EnterpriseProfileEnv:            managed.ProfileStandalone,
		managed.HookGuardianAuthorizationDirEnv: "/var/lib/defenseclaw-hook-guardian",
		"LANG":                                  "C.UTF-8",
		"PATH":                                  "/root/bin:/usr/bin",
		"SUDO_USER":                             "alice",
		"LD_PRELOAD":                            "/tmp/x.so",
		"HOME":                                  "/root",
	}
	env := auditCompactChildEnv(func(key string) string { return values[key] })
	got := strings.Join(env, "\n")
	for _, want := range []string{"DEFENSECLAW_HOME=/var/lib/defenseclaw", "HOME=/var/lib/defenseclaw", "LANG=C.UTF-8", "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		managed.ConfigPathEnv + "=/etc/defenseclaw/config.yaml", managed.HookGuardianAuthorizationDirEnv + "=/var/lib/defenseclaw-hook-guardian"} {
		if !strings.Contains(got, want) {
			t.Errorf("child env lacks %q:\n%s", want, got)
		}
	}
	for _, leaked := range []string{"SUDO_USER", "LD_PRELOAD", "HOME=/root", "/root/bin"} {
		if strings.Contains(got, leaked) {
			t.Errorf("child env leaks %q:\n%s", leaked, got)
		}
	}
	if len(env) != 8 {
		t.Errorf("child env has %d entries, want 8:\n%s", len(env), got)
	}
}

func TestAuditCompactRootRefusesARootStoreInAFolderAnotherAccountOwns(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to own the store")
	}
	db := prunedAuditStore(t)
	if err := os.Chown(filepath.Dir(db), 4242, 4242); err != nil {
		t.Skipf("chown the folder: %v", err)
	}
	cmd := useAuditCompact(t, db, false, 0)
	handled, err := auditCompactAsStoreOwner(cmd, db)
	if !handled || err == nil || !strings.Contains(err.Error(), "can be changed by another account") {
		t.Fatalf("root store in a user folder = %v, %v", handled, err)
	}
}

func TestAuditCompactRunAsForwardsSignalsAndWaitsForTheChild(t *testing.T) {
	child := exec.Command(os.Args[0], "-test.run=^TestAuditCompactSignalChildProcess$")
	child.Env = append(os.Environ(), "DC_COMPACT_TEST_SIGNAL_CHILD=1")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	signals := make(chan os.Signal, 1)
	go func() {
		time.Sleep(300 * time.Millisecond)
		signals <- syscall.SIGTERM
	}()
	started := time.Now()
	err := waitForwardingSignals(child, signals)
	if err == nil || child.ProcessState == nil || !child.ProcessState.Exited() && child.ProcessState.Sys().(syscall.WaitStatus).Signal() != syscall.SIGTERM {
		t.Fatalf("child after a forwarded SIGTERM: %v (%v)", err, child.ProcessState)
	}
	if elapsed := time.Since(started); elapsed > 20*time.Second {
		t.Fatalf("the forwarded SIGTERM did not end the child (%s)", elapsed)
	}
}

// TestAuditCompactSignalChildProcess waits until it is signalled.
func TestAuditCompactSignalChildProcess(t *testing.T) {
	if os.Getenv("DC_COMPACT_TEST_SIGNAL_CHILD") != "1" {
		return
	}
	time.Sleep(30 * time.Second)
}

func TestAuditCompactRootOnlyFolderNeedsRootOwnerAndNoSharedWrite(t *testing.T) {
	for _, tc := range []struct {
		uid  uint32
		mode os.FileMode
		want bool
	}{
		{0, 0o700, true}, {0, 0o755, true}, {995, 0o700, false}, {0, 0o770, false}, {0, 0o1777, false}, {501, 0o755, false},
	} {
		if got := auditCompactRootOnlyFolder(tc.uid, tc.mode); got != tc.want {
			t.Errorf("auditCompactRootOnlyFolder(%d, %o) = %v, want %v", tc.uid, tc.mode, got, tc.want)
		}
	}
}
