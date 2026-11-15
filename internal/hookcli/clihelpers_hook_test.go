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

package hookcli

import (
	"os"
	"path/filepath"
	"testing"
)

// writeHookSidecarForTest writes a hooks/.hookcfg under home so buildHookOptions
// can resolve the gateway address + fail mode without per-install flags (the
// Windows command form).
func writeHookSidecarForTest(t *testing.T, home, body string) {
	t.Helper()
	hookDir := filepath.Join(home, "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatalf("mkdir hooks: %v", err)
	}
	if err := os.WriteFile(filepath.Join(hookDir, ".hookcfg"), []byte(body), 0o600); err != nil {
		t.Fatalf("write .hookcfg: %v", err)
	}
}
