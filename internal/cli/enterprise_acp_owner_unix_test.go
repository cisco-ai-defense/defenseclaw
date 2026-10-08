//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/spf13/cobra"
)

// The static gateway finds a directory account (AD, SSSD) only through the
// standalone directory lookup, which the enterprise acp administrator
// commands never turned on, so enroll refused every such user (GAP-0269).
func TestEnterpriseACPAdministratorPreRunTurnsOnTheDirectoryLookup(t *testing.T) {
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	previousCfg, previousRoot := cfg, enterpriseACPRootPreRun
	previousStandalone, previousResolver := enterprisehooks.StandaloneUnix(), enterprisehooks.StandaloneResolver()
	t.Cleanup(func() {
		cfg, enterpriseACPRootPreRun = previousCfg, previousRoot
		enterprisehooks.SetStandaloneUnix(previousStandalone)
		enterprisehooks.SetStandaloneResolver(previousResolver)
	})
	enterpriseACPRootPreRun = func(*cobra.Command, []string) error {
		cfg = &config.Config{DeploymentMode: "managed_enterprise"}
		cfg.Enterprise.Profile = "standalone"
		return nil
	}
	enterprisehooks.SetStandaloneUnix(false)
	if err := enterpriseACPCmd.PersistentPreRunE(enterpriseACPEnrollCmd, nil); err != nil {
		t.Fatal(err)
	}
	if !enterprisehooks.StandaloneUnix() {
		t.Fatal("enterprise acp enroll resolves accounts without the standalone directory lookup")
	}
}

// Root changes the service-side ACP credentials as the owner of the managed
// data_dir, so the gateway account keeps owning its credential directory
// and a second enrollment is not refused (GAP-0251).
func TestEnterpriseACPServiceChangesRunAsTheDataDirOwner(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("a root test run owns its temporary data_dir")
	}
	restoreEUID, restoreRun := enterpriseACPEUID, enterpriseACPRunAsAccount
	t.Cleanup(func() { enterpriseACPEUID, enterpriseACPRunAsAccount = restoreEUID, restoreRun })
	enterpriseACPEUID = func() int { return 0 }
	var ranAs []int
	enterpriseACPRunAsAccount = func(uid, gid int, fn func() error) error {
		ranAs = append(ranAs, uid, gid)
		return fn()
	}
	dataDir := t.TempDir()
	info, err := os.Stat(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	owner := info.Sys().(*syscall.Stat_t)
	ran := false
	if err := withEnterpriseACPServiceOwner(dataDir, func() error { ran = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if !ran || len(ranAs) != 2 || ranAs[0] != int(owner.Uid) || ranAs[1] != int(owner.Gid) {
		t.Fatalf("ran=%v as %v, want the change run as the data_dir owner %d:%d", ran, ranAs, owner.Uid, owner.Gid)
	}
}

func TestEnterpriseACPServiceRepairsLegacyRootLock(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to reproduce a legacy lock")
	}
	const uid, gid = 65534, 65534
	dataDir := t.TempDir()
	if err := os.Chmod(filepath.Dir(dataDir), 0o755); err != nil {
		t.Fatal(err)
	}
	lockDir := filepath.Join(dataDir, "acp")
	if err := os.Mkdir(lockDir, 0o700); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(lockDir, ".enterprise-credentials.lock")
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(lockDir, uid, gid); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dataDir, uid, gid); err != nil {
		t.Fatal(err)
	}
	err := withEnterpriseACPServiceOwner(dataDir, func() error {
		f, err := os.OpenFile(lockPath, os.O_RDWR, 0)
		if err == nil {
			err = f.Close()
		}
		return err
	})
	if err != nil {
		t.Fatalf("service account could not open legacy lock: %v", err)
	}
	info, err := os.Stat(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Sys().(*syscall.Stat_t).Uid; got != uid {
		t.Fatalf("lock owner=%d", got)
	}
}
