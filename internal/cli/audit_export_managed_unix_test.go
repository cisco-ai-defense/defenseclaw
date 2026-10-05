// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Export has its own config-only initializer, so it applies the managed
// audit database check itself: an administrator's export on a unix
// standalone host refuses a service-owned database that fails it, and every
// other caller reads its own database without the check.
func TestAuditExportChecksTheManagedDatabaseForAnAdministrator(t *testing.T) {
	layout := withManagedStandaloneDeployment(t, 991)
	previousConfig, previousCheck := cfg, managedAuditStoreTrustCheck
	t.Cleanup(func() { cfg, managedAuditStoreTrustCheck = previousConfig, previousCheck })
	var checked []string
	managedAuditStoreTrustCheck = func(path string) error {
		checked = append(checked, path)
		return errors.New("owner uid 1000 is not trusted")
	}
	standalone := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise, AuditDB: filepath.Join(layout.DataDir, "audit.db")}
	standalone.Enterprise.Profile = managed.ProfileStandalone

	for _, uid := range []int{0, 991} {
		checked = nil
		cfg = standalone
		withManagedHostCallerUID(t, uid)
		err := checkManagedAuditExportDatabase()
		if err == nil || !strings.Contains(err.Error(), "managed audit store") {
			t.Fatalf("uid %d: the export accepted a managed audit database that failed its check: %v", uid, err)
		}
		if len(checked) != 1 || checked[0] != standalone.AuditDB {
			t.Fatalf("uid %d: checked %q, want [%q]", uid, checked, standalone.AuditDB)
		}
	}

	checked = nil
	withManagedHostCallerUID(t, 1000)
	if err := checkManagedAuditExportDatabase(); err != nil || len(checked) != 0 {
		t.Fatalf("a standard user's export was checked as the managed database: err=%v checked=%q", err, checked)
	}

	withManagedHostCallerUID(t, 0)
	cfg = &config.Config{AuditDB: filepath.Join(t.TempDir(), "audit.db")}
	if err := checkManagedAuditExportDatabase(); err != nil || len(checked) != 0 {
		t.Fatalf("an administrator's per-user export was checked as the managed database: err=%v checked=%q", err, checked)
	}
}
