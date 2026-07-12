// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestSkillScanner_SubprocessExitEmptyStdoutFails(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "fake-scanner.sh")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 7\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	ss := NewSkillScanner(config.SkillScannerConfig{Binary: bin}, config.InspectLLMConfig{}, config.CiscoAIDefenseConfig{})
	_, err := ss.Scan(context.Background(), "/tmp/target")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "exited 7") {
		t.Fatalf("subprocess exit detail missing from canonical scan failure: %v", err)
	}
}
