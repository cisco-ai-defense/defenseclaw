// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// NewCodeScanners returns the built-in scanners that make up a public
// source-code scan. The top-level scan result remains "codeguard" for v7
// schema compatibility; individual findings keep their source scanner names.
func NewCodeScanners(rulesDir string) []Scanner {
	return []Scanner{
		NewCodeGuardScanner(rulesDir),
		NewClawShieldVulnScanner(),
		NewClawShieldSecretsScanner(),
		NewClawShieldPIIScanner(),
		NewClawShieldMalwareScanner(),
		NewClawShieldInjectionScanner(),
	}
}

// ScanCode runs the public source-code scan suite over target.
func ScanCode(ctx context.Context, target, rulesDir string) (*ScanResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	start := time.Now()

	info, err := os.Lstat(target)
	if err != nil {
		return nil, fmt.Errorf("scanner: code: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("scanner: code: refusing to scan symlink %s", target)
	}
	if !info.IsDir() && !info.Mode().IsRegular() {
		return nil, fmt.Errorf("scanner: code: refusing to scan non-regular file %s", target)
	}

	result := &ScanResult{
		Scanner:    "codeguard",
		Target:     target,
		Timestamp:  start,
		TargetType: InferTargetType("codeguard"),
	}

	for _, sc := range NewCodeScanners(rulesDir) {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("scanner: code: %w", err)
		}
		sub, err := sc.Scan(ctx, target)
		if err != nil {
			return nil, fmt.Errorf("scanner: code: %s: %w", sc.Name(), err)
		}
		for i := range sub.Findings {
			f := sub.Findings[i]
			if strings.TrimSpace(f.Scanner) == "" {
				f.Scanner = sc.Name()
			}
			result.Findings = append(result.Findings, f)
		}
	}

	result.Findings = dropEvalOnlyExecFindings(result.Findings)
	result.Duration = time.Since(start)
	return result, nil
}

// cgExecNonEval is CG-EXEC-001's pattern without eval(), which the vuln
// scanner already reports as CS-VLN-CODE-EVAL.
var cgExecNonEval = regexp.MustCompile(`(?i)(os\.system|subprocess\.call|exec\(|child_process\.exec|system\()`)

// dropEvalOnlyExecFindings removes a CodeGuard CG-EXEC-001 finding whose line
// matched only because of eval() when CS-VLN-CODE-EVAL reports the same line
// (GAP-1595: one eval() call read as two HIGH findings).
func dropEvalOnlyExecFindings(findings []Finding) []Finding {
	evalLines := map[string]bool{}
	for _, f := range findings {
		if f.ID == "CS-VLN-CODE-EVAL" {
			evalLines[codeFindingLineKey(f.Location)] = true
		}
	}
	if len(evalLines) == 0 {
		return findings
	}
	kept := findings[:0]
	for _, f := range findings {
		if f.ID == "CG-EXEC-001" && evalLines[codeFindingLineKey(f.Location)] && !cgExecNonEval.MatchString(f.Description) {
			continue
		}
		kept = append(kept, f)
	}
	return kept
}

// codeFindingLineKey normalizes "dir/calc.py:2" and "calc.py:2" to the same
// file-name:line key; both scanners report the same file in one scan.
func codeFindingLineKey(location string) string {
	file, line := location, ""
	if i := strings.LastIndex(location, ":"); i > 0 {
		file, line = location[:i], location[i+1:]
	}
	return filepath.Base(filepath.Clean(file)) + ":" + line
}
