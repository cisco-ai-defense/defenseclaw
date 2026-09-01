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
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
	"github.com/defenseclaw/defenseclaw/internal/scanoutput"
)

var (
	scanOutputJSON  bool
	scanPrintSchema bool
	scanNoRedact    bool
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run security scanners",
	Long:  "Run DefenseClaw security scanners against targets.",
}

var scanCodeCmd = &cobra.Command{
	Use:   "code <path>",
	Short: "Scan source code with CodeGuard and ClawShield",
	Long: `Scan a file or directory for security issues using the CodeGuard static scanner
and ClawShield code scanners.

Checks for hardcoded secrets, unsafe exec calls, SQL injection, weak crypto,
path traversal, and more across Python, JS/TS, Go, Java, Ruby, PHP, Shell,
YAML, JSON, XML, C/C++, and Rust files.`,
	Args: cobra.ExactArgs(1),
	RunE: runScanCode,
}

func init() {
	scanCodeCmd.Flags().BoolVar(&scanOutputJSON, "json", false, "Output results as JSON (v7 scan-result contract)")
	scanCodeCmd.Flags().BoolVar(&scanNoRedact, "no-redact", false, "Emit raw finding text to local JSON stdout (requires --json)")
	scanCodeCmd.Flags().BoolVar(&scanPrintSchema, "schema", false, "Print scan-result.json schema (for downstream validators) and exit")
	scanCmd.AddCommand(scanCodeCmd)
	rootCmd.AddCommand(scanCmd)
}

func runScanCode(_ *cobra.Command, args []string) error {
	if scanNoRedact && !scanOutputJSON {
		return fmt.Errorf("--no-redact requires --json")
	}
	if scanPrintSchema {
		if _, err := os.Stdout.Write(scanResultSchemaJSON); err != nil {
			return err
		}
		_, _ = fmt.Fprintln(os.Stdout)
		return nil
	}

	target, err := filepath.Abs(args[0])
	if err != nil {
		return fmt.Errorf("resolve scan target: %w", err)
	}

	if _, err := os.Stat(target); err != nil {
		return fmt.Errorf("target not found: %w", err)
	}

	rulesDir := ""
	if cfg != nil {
		rulesDir = cfg.Scanners.CodeGuard
	}

	result, err := scanner.ScanCode(context.Background(), target, rulesDir)
	if err != nil {
		return fmt.Errorf("code scan failed: %w", err)
	}

	var redactor *scanoutput.Redactor
	if scanNeedsRedactor(auditLog != nil) {
		dataDir := ""
		if cfg != nil {
			dataDir = strings.TrimSpace(cfg.DataDir)
		}
		if dataDir == "" {
			redactor, err = scanoutput.NewEphemeralRedactor()
		} else {
			redactor, err = scanoutput.LoadRedactor(dataDir)
		}
		if err != nil {
			return fmt.Errorf("initialize scan output redaction: %w", err)
		}
	}

	if auditLog != nil {
		// Persistence sanitizes sensitive findings in place. Commit a detached
		// copy so --no-redact remains an explicit local-output choice while the
		// forensic database always receives the protected projection.
		persisted := scanoutput.Clone(result)
		if err := auditLog.PersistStandaloneScan(persisted, redactor); err != nil {
			return fmt.Errorf("persist code scan: %w", err)
		}
		result.ScanID = persisted.ScanID
	}

	if scanOutputJSON {
		options := scanResultV7Options{Raw: scanNoRedact, Redactor: redactor}
		if scanNoRedact {
			_, _ = fmt.Fprintln(os.Stderr, "WARNING: --no-redact exposes raw local scan paths and finding text")
		}
		b, err := marshalScanResultV7WithOptions(result, appVersion, options)
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(b)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(os.Stdout)
		return err
	}

	printCodeScanResults(result)
	return nil
}

func scanNeedsRedactor(persistProtectedCopy bool) bool {
	return persistProtectedCopy || (scanOutputJSON && !scanNoRedact)
}

func printCodeScanResults(result *scanner.ScanResult) {
	if len(result.Findings) == 0 {
		fmt.Printf("Code scan: %s\n", result.Target)
		fmt.Println("  No findings — clean")
		fmt.Printf("  Duration: %s\n", result.Duration)
		printHint("Run full audit:  defenseclaw doctor")
		return
	}

	fmt.Printf("Code scan: %s — %d finding(s)\n", result.Target, len(result.Findings))
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
