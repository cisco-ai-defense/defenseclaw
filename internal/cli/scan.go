// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

var (
	scanOutputJSON bool
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run security scanners",
	Long:  "Run DefenseClaw security scanners against targets.",
}

var scanCodeCmd = &cobra.Command{
	Use:   "code <path>",
	Short: "Scan source code with CodeGuard",
	Long: `Scan a file or directory for security issues using the CodeGuard static scanner.

Checks for hardcoded secrets, unsafe exec calls, SQL injection, weak crypto,
path traversal, and more across Python, JS/TS, Go, Java, Ruby, PHP, Shell,
YAML, JSON, XML, C/C++, and Rust files.`,
	Args: cobra.ExactArgs(1),
	RunE: runScanCode,
}

func init() {
	scanCodeCmd.Flags().BoolVar(&scanOutputJSON, "json", false, "Output results as JSON")
	scanCmd.AddCommand(scanCodeCmd)
	rootCmd.AddCommand(scanCmd)
}

func runScanCode(_ *cobra.Command, args []string) error {
	target := args[0]

	if _, err := os.Stat(target); err != nil {
		return fmt.Errorf("target not found: %w", err)
	}

	rulesDir := ""
	if cfg != nil {
		rulesDir = cfg.Scanners.CodeGuard
	}
	cg := scanner.NewCodeGuardScanner(rulesDir)

	result, err := cg.Scan(context.Background(), target)
	if err != nil {
		return fmt.Errorf("codeguard scan failed: %w", err)
	}

	if auditLog != nil {
		_ = auditLog.LogScan(result)
	}

	if scanOutputJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}

	printCodeScanResults(result)
	return nil
}

func printCodeScanResults(result *scanner.ScanResult) {
	if len(result.Findings) == 0 {
		fmt.Printf("CodeGuard scan: %s\n", result.Target)
		fmt.Println("  No findings — clean")
		fmt.Printf("  Duration: %s\n", result.Duration)
		printHint("Run full audit:  defenseclaw doctor")
		return
	}

	fmt.Printf("CodeGuard scan: %s — %d finding(s)\n", result.Target, len(result.Findings))
	fmt.Println()

	for _, f := range result.Findings {
		fmt.Printf("  [%s] %s: %s  (%s)\n", f.Severity, f.ID, f.Title, f.Location)
		if f.Remediation != "" {
			fmt.Printf("         Remediation: %s\n", f.Remediation)
		}
	}

	fmt.Println()
	fmt.Printf("  Duration: %s\n", result.Duration)
	printHint("View alerts:  defenseclaw alerts")
}
