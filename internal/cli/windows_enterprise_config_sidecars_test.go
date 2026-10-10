// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
)

// GAP-0038: the Go config step of the Windows lifecycle writes these files
// beside config.yaml inside the PowerShell transaction, and a rollback only
// restores what the transaction snapshots. The module's list must name every
// file the step can write.
func TestWindowsLifecycleSnapshotsEveryFileTheConfigStepWrites(t *testing.T) {
	module, err := os.ReadFile(filepath.Join("..", "..", "packaging", "windows", "DefenseClawEnterprise.psm1"))
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ReplaceAll(string(module), "\r\n", "\n") // CRLF on a Windows checkout
	start := strings.Index(text, "function Get-DefenseClawConfigSidecarPaths")
	if start < 0 {
		t.Fatal("DefenseClawEnterprise.psm1 has no Get-DefenseClawConfigSidecarPaths")
	}
	end := strings.Index(text[start:], "\n}\n")
	if end < 0 {
		t.Fatal("Get-DefenseClawConfigSidecarPaths has no closing brace")
	}
	list := text[start : start+end]
	for _, name := range []string{
		configwrite.GenerationFileName,
		"config.yaml" + configwrite.LockSuffix,
		"config.yaml" + config.ConfigV8BackupSuffix,
		config.MigrationV9RecordFile,
	} {
		if !strings.Contains(list, "'"+name+"'") {
			t.Errorf("a rollback does not restore %s, which the config step writes beside config.yaml", name)
		}
	}
}
