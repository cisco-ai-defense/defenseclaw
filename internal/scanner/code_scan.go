// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"fmt"
	"os"
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

	result.Duration = time.Since(start)
	return result, nil
}
