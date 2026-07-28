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
