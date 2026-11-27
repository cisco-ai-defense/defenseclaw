// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGAP1598TestsFindRepositoryFilesFromTheTestFolder: a test of this
// package or of internal/gateway/connector that reads a repository file
// finds it from the folder the test binary starts in (repoRootFromTestFile,
// connectorRepoRoot), never from runtime.Caller: that names the folder the
// binary was compiled in, so a binary cross-built on Linux and run on the
// native Windows host could not read policies/ (34 reds, among them every
// test of installDefaultRulePackForDataDir, rel-1-0-10:GAP-1598). The check
// also proves the folder the helper reads is this package's source folder.
func TestGAP1598TestsFindRepositoryFilesFromTheTestFolder(t *testing.T) {
	root := repoRootFromTestFile(t)
	if _, err := os.Stat(filepath.Join(root, "policies", "guardrail", "default")); err != nil {
		t.Fatalf("the repository root %s from the test folder has no default rule pack: %v", root, err)
	}
	if _, err := os.Stat(filepath.Join(root, "internal", "gateway", "local_patterns_test.go")); err != nil {
		t.Fatalf("the test folder %s is not internal/gateway: %v", gatewayTestDir, err)
	}
	for _, dir := range []string{".", "connector"} {
		files, err := filepath.Glob(filepath.Join(dir, "*_test.go"))
		if err != nil || len(files) == 0 {
			t.Fatalf("%s: no test files (%v)", dir, err)
		}
		for _, file := range files {
			raw, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), "runtime."+"Caller(0)") {
				t.Errorf("%s finds a file through runtime.Caller; use repoRootFromTestFile or connectorRepoRoot", file)
			}
		}
	}
}
