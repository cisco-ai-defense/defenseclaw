// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var bundledCodeGuardAssetFiles = []string{"SKILL.md", "main.py", "skill.yaml"}

func TestBundledCodeGuardSourceAndPackagedCopyScanClean(t *testing.T) {
	sourceDir := bundledCodeGuardSourceDir(t)
	packagedDir := filepath.Join(
		t.TempDir(),
		"site-packages",
		"defenseclaw",
		"_data",
		"skills",
		"codeguard",
	)
	bundledCodeGuardCopyExact(t, sourceDir, packagedDir)

	rulesDir := filepath.Join(t.TempDir(), "empty-codeguard-rules")
	if err := os.MkdirAll(rulesDir, 0o700); err != nil {
		t.Fatal(err)
	}

	for _, layout := range []struct {
		name string
		dir  string
	}{
		{name: "source", dir: sourceDir},
		{name: "packaged", dir: packagedDir},
	} {
		for _, name := range bundledCodeGuardAssetFiles {
			t.Run(layout.name+"/"+name, func(t *testing.T) {
				result, err := ScanCode(t.Context(), filepath.Join(layout.dir, name), rulesDir)
				if err != nil {
					t.Fatal(err)
				}
				if len(result.Findings) != 0 {
					t.Fatalf(
						"bundled asset self-flagged: %s",
						bundledCodeGuardFindingIDs(result),
					)
				}
			})
		}
	}
}

func TestBundledCodeGuardCleanupPreservesMaliciousDetections(t *testing.T) {
	rulesDir := filepath.Join(t.TempDir(), "empty-codeguard-rules")
	if err := os.MkdirAll(rulesDir, 0o700); err != nil {
		t.Fatal(err)
	}

	maliciousFixture := filepath.Join(
		bundledCodeGuardRepositoryRoot(t),
		"test",
		"fixtures",
		"skills",
		"malicious-skill",
		"main.py",
	)
	maliciousResult, err := ScanCode(t.Context(), maliciousFixture, rulesDir)
	if err != nil {
		t.Fatal(err)
	}
	if !bundledCodeGuardHasRule(maliciousResult, "CG-NET-001") {
		t.Fatalf(
			"malicious fixture no longer triggers the network detector: %s",
			bundledCodeGuardFindingIDs(maliciousResult),
		)
	}

	secret := strings.Join([]string{"AK", "IA", "IOSFOD", "NN7EXAMPLE"}, "")
	shellCall := strings.Join([]string{"os.", "sys", "tem", "(command)"}, "")
	representative := filepath.Join(t.TempDir(), "representative.py")
	content := fmt.Sprintf("cloud_id = %q\n%s\n", secret, shellCall)
	if err := os.WriteFile(representative, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	representativeResult, err := ScanCode(t.Context(), representative, rulesDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, ruleID := range []string{"CG-CRED-002", "CS-SEC-AWS-KEY", "CG-EXEC-001"} {
		if !bundledCodeGuardHasRule(representativeResult, ruleID) {
			t.Errorf(
				"representative detection missing %s: %s",
				ruleID,
				bundledCodeGuardFindingIDs(representativeResult),
			)
		}
	}
}

func bundledCodeGuardSourceDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(bundledCodeGuardRepositoryRoot(t), "skills", "codeguard")
}

func bundledCodeGuardRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller could not locate the bundled asset test")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
}

func bundledCodeGuardCopyExact(t *testing.T, sourceDir, destinationDir string) {
	t.Helper()
	if err := os.MkdirAll(destinationDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range bundledCodeGuardAssetFiles {
		content, err := os.ReadFile(filepath.Join(sourceDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(destinationDir, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func bundledCodeGuardHasRule(result *ScanResult, ruleID string) bool {
	if result == nil {
		return false
	}
	for _, finding := range result.Findings {
		if finding.ID == ruleID {
			return true
		}
	}
	return false
}

func bundledCodeGuardFindingIDs(result *ScanResult) []string {
	if result == nil {
		return nil
	}
	ids := make([]string, 0, len(result.Findings))
	for _, finding := range result.Findings {
		ids = append(ids, finding.ID)
	}
	return ids
}
