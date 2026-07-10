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

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGenerateRegexImportFromEvalCorpus regenerates the "eval-" rows of
// regex/corpus.jsonl from the labeled eval corpus (gated by
// SECURITY_SUITE_IMPORT=1). Benign items the regex layer leaves clean become
// false-positive guards; attacks it already flags become regression locks;
// items it doesn't handle deterministically are skipped and stay in the live
// tier. Curated rows are preserved verbatim.
func TestGenerateRegexImportFromEvalCorpus(t *testing.T) {
	if os.Getenv("SECURITY_SUITE_IMPORT") != "1" {
		t.Skip("generator; set SECURITY_SUITE_IMPORT=1 to regenerate the generated block of regex/corpus.jsonl")
	}

	g := NewGuardrailInspector("local", nil, nil, "")
	g.SetDetectionStrategy("regex_only", "", "", "", false)

	var imported []regexCase
	var keptBenign, keptAttack, skipBenign, skipAttack int

	for _, judge := range []string{"injection", "pii", "exfil", "tool_injection"} {
		for _, it := range loadEvalCorpus(t, judge) {
			dir := it.Direction
			if dir == "" {
				dir = "prompt"
			}
			v := g.Inspect(context.Background(), dir, it.Content, nil, "model", "observe")
			high := v != nil && severityRank[v.Severity] >= severityRank["HIGH"]

			c := regexCase{
				ID:        "eval-" + it.ID,
				Direction: dir,
				ToolName:  it.ToolName,
				Content:   it.Content,
				IsAttack:  it.IsAttack,
				Surfaces:  []string{"inspector"},
			}
			switch {
			case it.IsAttack && high:
				c.ExpectedSeverityAtLeast = "HIGH"
				imported = append(imported, c)
				keptAttack++
			case it.IsAttack && !high:
				skipAttack++ // judge-only; lives in the live tier
			case !it.IsAttack && !high:
				c.ForbiddenSeverityAtLeast = "HIGH"
				imported = append(imported, c)
				keptBenign++
			default: // benign that trips the regex layer
				skipBenign++
			}
		}
	}

	// Rewrite the single regex corpus: keep comment lines and curated rows
	// (any id NOT starting with "eval-") verbatim, drop old generated rows,
	// then append the freshly generated rows. The "eval-" id prefix is the
	// only discriminator.
	path := filepath.Join("testdata", "security_suite", "regex", "corpus.jsonl")
	existing, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	var buf bytes.Buffer
	for _, ln := range strings.Split(string(existing), "\n") {
		trimmed := strings.TrimSpace(ln)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "//") {
			buf.WriteString(ln)
			buf.WriteByte('\n')
			continue
		}
		var probe struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal([]byte(trimmed), &probe); err != nil {
			t.Fatalf("parse existing line: %v\nline: %s", err, ln)
		}
		if strings.HasPrefix(probe.ID, "eval-") {
			continue // drop old generated row
		}
		buf.WriteString(ln) // keep curated row verbatim
		buf.WriteByte('\n')
	}
	for _, c := range imported {
		b, err := json.Marshal(c)
		if err != nil {
			t.Fatalf("encode case %s: %v", c.ID, err)
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}

	t.Logf("regex import written to %s", path)
	t.Logf("benign: kept=%d skipped(regex-flagged)=%d", keptBenign, skipBenign)
	t.Logf("attack: kept=%d skipped(judge-only)=%d", keptAttack, skipAttack)
}
