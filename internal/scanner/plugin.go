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

package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"time"
)

type PluginScanner struct {
	BinaryPath string
}

func NewPluginScanner(binaryPath string) *PluginScanner {
	if binaryPath == "" {
		binaryPath = "defenseclaw"
	}
	return &PluginScanner{BinaryPath: binaryPath}
}

func (s *PluginScanner) Name() string               { return "plugin-scanner" }
func (s *PluginScanner) Version() string            { return "1.0.0" }
func (s *PluginScanner) SupportedTargets() []string { return []string{"plugin"} }

func pluginScanCommand(binaryPath, target string) (string, []string) {
	if binaryPath == "" {
		binaryPath = "defenseclaw"
	}
	switch filepath.Base(binaryPath) {
	case "defenseclaw-plugin-scanner", "defenseclaw-plugin-scanner.exe":
		return binaryPath, []string{target}
	default:
		return binaryPath, []string{"plugin", "scan", "--json", target}
	}
}

func (s *PluginScanner) Scan(ctx context.Context, target string) (*ScanResult, error) {
	start := time.Now()

	binaryPath, args := pluginScanCommand(s.BinaryPath, target)
	cmd := exec.CommandContext(ctx, binaryPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	duration := time.Since(start)

	result := &ScanResult{
		Scanner:   s.Name(),
		Target:    target,
		Timestamp: start,
		Duration:  duration,
	}

	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, fmt.Errorf("scanner: %s not found at %q — install with: pip install defenseclaw", s.Name(), s.BinaryPath)
		}
		if stdout.Len() == 0 {
			return nil, fmt.Errorf("scanner: %s failed: %s", s.Name(), stderr.String())
		}
	}

	if stdout.Len() > 0 {
		findings, parseErr := parsePluginOutput(stdout.Bytes())
		if parseErr != nil {
			return nil, fmt.Errorf("scanner: failed to parse %s output: %w", s.Name(), parseErr)
		}
		result.Findings = findings
	}

	return result, nil
}

// pluginScanResult matches the JSON output from the Python CLI
// (defenseclaw plugin scan --json).
type pluginScanResult struct {
	Scanner   string          `json:"scanner"`
	Target    string          `json:"target"`
	Timestamp string          `json:"timestamp"`
	Findings  []pluginFinding `json:"findings"`
}

type pluginFinding struct {
	ID              string   `json:"id"`
	RuleID          string   `json:"rule_id"`
	Severity        string   `json:"severity"`
	Confidence      float64  `json:"confidence"`
	Title           string   `json:"title"`
	Description     string   `json:"description"`
	Evidence        string   `json:"evidence"`
	Location        string   `json:"location"`
	Remediation     string   `json:"remediation"`
	Tags            []string `json:"tags"`
	OccurrenceCount int      `json:"occurrence_count"`
	Suppressed      bool     `json:"suppressed"`
}

func parsePluginOutput(data []byte) ([]Finding, error) {
	var out pluginScanResult
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}

	findings := make([]Finding, 0, len(out.Findings))
	for _, f := range out.Findings {
		if f.Suppressed {
			continue
		}
		findings = append(findings, Finding{
			ID:          f.ID,
			Severity:    Severity(f.Severity),
			Title:       f.Title,
			Description: f.Description,
			Location:    f.Location,
			Remediation: f.Remediation,
			Scanner:     "plugin-scanner",
			Tags:        f.Tags,
		})
	}
	return findings, nil
}
