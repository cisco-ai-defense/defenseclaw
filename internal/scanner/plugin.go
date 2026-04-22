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
	Policy     string
	Profile    string
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

func (s *PluginScanner) pluginScanCommand(target string) (string, []string) {
	binaryPath := s.BinaryPath
	if binaryPath == "" {
		binaryPath = "defenseclaw"
	}
	var args []string
	switch filepath.Base(binaryPath) {
	case "defenseclaw-plugin-scanner", "defenseclaw-plugin-scanner.exe":
		args = []string{target}
	default:
		args = []string{"plugin", "scan", "--json", target}
	}
	if s.Policy != "" {
		args = append(args, "--policy", s.Policy)
	}
	if s.Profile != "" {
		args = append(args, "--profile", s.Profile)
	}
	return binaryPath, args
}

func (s *PluginScanner) Scan(ctx context.Context, target string) (*ScanResult, error) {
	start := time.Now()
	ctx, sp := BeginScanSpan(ctx, s.Name(), target, InferTargetType(s.Name()), AgentIdentity{})
	exitCode := 0
	var scanErr error
	var result *ScanResult
	defer func() {
		FinishScanSpan(sp, result, exitCode, scanErr)
	}()

	binaryPath, args := s.pluginScanCommand(target)
	cmd := exec.CommandContext(ctx, binaryPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	duration := time.Since(start)
	stderrStr := stderr.String()

	result = &ScanResult{
		Scanner:    s.Name(),
		Target:     target,
		Timestamp:  start,
		Duration:   duration,
		TargetType: InferTargetType(s.Name()),
	}

	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		}
		if errors.Is(err, exec.ErrNotFound) {
			scanErr = fmt.Errorf("scanner: %s not found at %q — install with: pip install defenseclaw", s.Name(), s.BinaryPath)
			return nil, scanErr
		}
		if exitCode != 0 {
			EmitSubprocessExitFromContext(ctx, binaryPath, exitCode, stderrStr)
		}
		if stdout.Len() == 0 {
			scanErr = fmt.Errorf("scanner: %s failed: %s", s.Name(), stderrStr)
			return nil, scanErr
		}
	}

	result.ExitCode = exitCode
	if exitCode != 0 {
		result.ScanError = stderrStr
	}

	if stdout.Len() > 0 {
		findings, parseErr := parsePluginOutput(stdout.Bytes())
		if parseErr != nil {
			scanErr = fmt.Errorf("scanner: failed to parse %s output: %w (stderr=%s)", s.Name(), parseErr, stderrStr)
			return nil, scanErr
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
	Category        string   `json:"category"`
	Severity        string   `json:"severity"`
	Confidence      float64  `json:"confidence"`
	Title           string   `json:"title"`
	Description     string   `json:"description"`
	Evidence        string   `json:"evidence"`
	Location        string   `json:"location"`
	Line            int      `json:"line"`
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
		var ln *int
		if f.Line > 0 {
			v := f.Line
			ln = &v
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
			RuleID:      f.RuleID,
			Category:    f.Category,
			LineNumber:  ln,
		})
	}
	return findings, nil
}
