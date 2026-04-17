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
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestLogActionSitesHaveStructuredEventSibling is a static coverage
// test that pins the "every legacy LogAction call is accompanied by
// at least one structured gatewaylog emit in the same file"
// invariant. Audit sinks and OTel logs now flow through the
// gatewaylog pipeline — any .go file that still logs via the legacy
// audit.Logger.LogAction channel but never calls an emit*() helper
// is a silent drop for the new observability surface and must be
// migrated.
//
// The test intentionally runs on source (not runtime): it is a
// contract between developers and reviewers that cannot be bypassed
// by clever mocking, and it documents migration coverage for the
// observability refactor in a single grep-able place.
func TestLogActionSitesHaveStructuredEventSibling(t *testing.T) {
	logAction := regexp.MustCompile(`\.LogAction\(`)
	emit := regexp.MustCompile(`emit(Verdict|Judge|Lifecycle|Error|Diagnostic)\(`)

	// The check is scoped to the gateway package because that's
	// where the new structured emit functions live. Expanding this
	// to other packages would be a separate migration and is
	// tracked as a follow-up in docs/OBSERVABILITY.md.
	pkgDir := "."
	entries, err := os.ReadDir(pkgDir)
	if err != nil {
		t.Fatalf("read pkg dir: %v", err)
	}

	var offenders []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// Skip test files — _test.go files may reference LogAction
		// in setup/assertions without needing the structured side
		// channel. The production code that instantiates the
		// Logger is what the pipeline depends on.
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(pkgDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if !logAction.Match(data) {
			continue
		}
		if !emit.Match(data) {
			offenders = append(offenders, name)
		}
	}

	if len(offenders) > 0 {
		t.Fatalf("files calling LogAction but missing structured emit*() calls: %v\n"+
			"Add at least one emitVerdict/emitJudge/emitLifecycle/emitError/emitDiagnostic "+
			"to surface these events on the new observability pipeline (audit sinks + OTel).",
			offenders)
	}
}
