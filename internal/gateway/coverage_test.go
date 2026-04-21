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

// logActionRE matches any call of the form receiver.LogAction(...),
// i.e. a production hit on the legacy audit.Logger logging channel.
var logActionRE = regexp.MustCompile(`\.LogAction\(`)

// emitRE matches any invocation of the structured gatewaylog emitter
// family. These helpers currently live in internal/gateway — packages
// that want to fan events into the new pipeline import that package
// and call the helpers directly, which keeps the grep-able check
// simple.
var emitRE = regexp.MustCompile(`emit(Verdict|Judge|Lifecycle|Error|Diagnostic)\(`)

// scanLogActionCoverage walks the given directory (non-recursively,
// non-test Go files only) and returns the names of files that call
// LogAction without also calling at least one emit*() helper. The
// function is the single source of truth for the scoped coverage
// invariants below.
func scanLogActionCoverage(t *testing.T, dir string) []string {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var offenders []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if !logActionRE.Match(data) {
			continue
		}
		if !emitRE.Match(data) {
			offenders = append(offenders, filepath.Join(filepath.Base(dir), name))
		}
	}
	return offenders
}

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
	if offenders := scanLogActionCoverage(t, "."); len(offenders) > 0 {
		t.Fatalf("files calling LogAction but missing structured emit*() calls: %v\n"+
			"Add at least one emitVerdict/emitJudge/emitLifecycle/emitError/emitDiagnostic "+
			"to surface these events on the new observability pipeline (audit sinks + OTel).",
			offenders)
	}
}

// TestLogActionFreeInAuditAndTelemetry pins the "internal/audit and
// internal/telemetry must not grow production LogAction calls"
// invariant. Those packages sit *below* the gatewaylog pipeline —
// audit owns the SQLite store and sink fan-out, telemetry owns OTel
// wiring. A LogAction call from inside those packages would create a
// circular routing (sink → pipeline → sink) and defeat the point of
// the observability refactor.
//
// If this test fails, the fix is almost always to route the call
// through the gatewaylog package instead (emitLifecycle / emitError)
// rather than to suppress the assertion.
func TestLogActionFreeInAuditAndTelemetry(t *testing.T) {
	// Repo-relative paths are stable under `go test ./...` because
	// cwd is the package dir; we reach up two levels to the repo
	// root, then into the target packages.
	repoRoot := filepath.Join("..", "..")
	for _, sub := range []string{
		filepath.Join(repoRoot, "internal", "audit"),
		filepath.Join(repoRoot, "internal", "telemetry"),
	} {
		entries, err := os.ReadDir(sub)
		if err != nil {
			t.Fatalf("read %s: %v", sub, err)
		}
		var offenders []string
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(sub, name))
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if logActionRE.Match(data) {
				offenders = append(offenders,
					filepath.Join(filepath.Base(sub), name))
			}
		}
		if len(offenders) > 0 {
			t.Errorf("package %s must not call LogAction from production code (offenders: %v). "+
				"Route the event through gatewaylog instead.", filepath.Base(sub), offenders)
		}
	}
}
