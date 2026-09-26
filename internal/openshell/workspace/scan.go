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

package workspace

import (
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// ContentScanner inspects the new bytes of one changed file.
type ContentScanner interface {
	Name() string
	ScanContent(path string, content []byte) []scanner.Finding
}

// SecretsScanner is DefenseClaw's ClawShield secret rules.
func SecretsScanner() ContentScanner {
	return secretsContentScanner{s: scanner.NewClawShieldSecretsScanner()}
}

// CodeGuardScanner is DefenseClaw's CodeGuard rules (built-in plus custom
// rules under rulesDir; "" uses the default rules directory).
func CodeGuardScanner(rulesDir string) ContentScanner {
	return codeGuardContentScanner{s: scanner.NewCodeGuardScanner(rulesDir)}
}

// DefaultScanners is what Review runs on changed files: secrets and
// CodeGuard.
func DefaultScanners() []ContentScanner {
	return []ContentScanner{SecretsScanner(), CodeGuardScanner("")}
}

type secretsContentScanner struct {
	s *scanner.ClawShieldSecretsScanner
}

func (s secretsContentScanner) Name() string { return s.s.Name() }

func (s secretsContentScanner) ScanContent(path string, content []byte) []scanner.Finding {
	return s.s.ScanContent(path, content)
}

type codeGuardContentScanner struct{ s *scanner.CodeGuardScanner }

func (s codeGuardContentScanner) Name() string { return s.s.Name() }

func (s codeGuardContentScanner) ScanContent(path string, content []byte) []scanner.Finding {
	return s.s.ScanContent(path, string(content))
}

// ScanFinding is one scanner result on a changed file.
type ScanFinding struct {
	Path     string `json:"path"`
	Scanner  string `json:"scanner"`
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Location string `json:"location,omitempty"`
}

const (
	defaultMaxScanBytes = 1 << 20
	maxScannedFiles     = 2_000
)

func runScanners(scanners []ContentScanner, rel string, content []byte) []ScanFinding {
	var out []ScanFinding
	for _, s := range scanners {
		for _, f := range s.ScanContent(rel, content) {
			out = append(out, ScanFinding{
				Path: rel, Scanner: s.Name(), RuleID: f.RuleID, Severity: string(f.Severity),
				Title: f.Title, Location: f.Location,
			})
		}
	}
	return out
}
