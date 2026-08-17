// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
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
	"path/filepath"
	"strings"
	"testing"
)

func TestCodexAttributedSourceProofMemoizesPaths(t *testing.T) {
	t.Parallel()

	cwd := t.TempDir()
	checks := 0
	trust := newCodexAttributedSourceTrust(cwd)
	trust.validate = func(path, gotCWD string) bool {
		checks++
		return filepath.ToSlash(path) == "internal/gateway/fixture.go" &&
			gotCWD == cwd
	}
	for _, line := range []string{
		"internal/gateway/fixture.go:10:first",
		"internal/gateway/fixture.go:20:second",
	} {
		if !codexAttributedWorkspaceSourceLine(line, trust) {
			t.Fatalf("trusted attributed line rejected: %q", line)
		}
	}
	if checks != 1 || len(trust.paths) != 1 {
		t.Fatalf("filesystem proofs=%d memo entries=%d, want 1/1", checks, len(trust.paths))
	}
}

func TestCodexAttributedSourceProofBoundsCandidates(t *testing.T) {
	t.Parallel()

	checks := 0
	trust := newCodexAttributedSourceTrust(t.TempDir())
	trust.validate = func(string, string) bool {
		checks++
		return checks > codexAttributedSourceMaxCandidatesPerLine
	}
	line := "internal/gateway/fixture.go" +
		strings.Repeat("-1-", codexAttributedSourceMaxCandidatesPerLine+1) +
		"content"
	if codexAttributedWorkspaceSourceLine(line, trust) {
		t.Fatal("candidate beyond the per-line bound established source trust")
	}
	if checks != codexAttributedSourceMaxCandidatesPerLine {
		t.Fatalf("filesystem proofs=%d, want bounded %d", checks, codexAttributedSourceMaxCandidatesPerLine)
	}
}

func TestCodexAttributedSourceProofRejectsNonSourcePrefixWithoutIO(t *testing.T) {
	t.Parallel()

	checks := 0
	trust := newCodexAttributedSourceTrust(t.TempDir())
	trust.validate = func(string, string) bool {
		checks++
		return true
	}
	if codexAttributedWorkspaceSourceLine("outside/fixture.go:10:value", trust) {
		t.Fatal("non-source workspace prefix established source trust")
	}
	if checks != 0 {
		t.Fatalf("non-source prefix triggered %d filesystem proofs", checks)
	}
}

func TestCodexAttributedSourceProofFailsClosedOnLeafTruncation(t *testing.T) {
	t.Parallel()

	values := make([]interface{}, 257)
	for index := range values {
		values[index] = "internal/gateway/fixture.go:10:value"
	}
	if _, _, ok := codexSplitAttributedSourceResult(
		map[string]interface{}{"stdout": values}, t.TempDir(),
	); ok {
		t.Fatal("truncated structured result established source proof")
	}
}

func TestCollectHookContentStringsReportsExactAndTruncatedTraversal(t *testing.T) {
	t.Parallel()

	exact := make([]interface{}, 256)
	for index := range exact {
		exact[index] = "value"
	}
	var leaves []string
	if !collectHookContentStrings(exact, &leaves, 0) || len(leaves) != len(exact) {
		t.Fatalf("exact traversal complete=%v leaves=%d, want true/%d",
			len(leaves) == len(exact), len(leaves), len(exact))
	}

	over := append(exact, "overflow")
	leaves = nil
	if collectHookContentStrings(over, &leaves, 0) {
		t.Fatal("bounded traversal reported a truncated value as complete")
	}
	if len(leaves) != len(exact) {
		t.Fatalf("truncated leaves=%d, want bounded %d", len(leaves), len(exact))
	}
}
