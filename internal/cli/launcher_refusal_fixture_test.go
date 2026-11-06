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
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// launcherRefusalFixture is what docs-site/scripts/test-docs-claims.ts reads
// as the refusal each OS prints: the docs gate has no Go toolchain, so it
// follows this file instead of the spelling of launcherRefusalFor. Run the
// test with DEFENSECLAW_UPDATE_LAUNCHER_REFUSAL=1 to rewrite the file after
// the launcher text changes on purpose, then update the docs pages it names.
const launcherRefusalFixture = "testdata/launcher_refusal.json"

func TestLauncherRefusalFixture(t *testing.T) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]string{
		"linux":   launcherRefusalFor("linux"),
		"darwin":  launcherRefusalFor("darwin"),
		"windows": launcherRefusalFor("windows"),
	}); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("DEFENSECLAW_UPDATE_LAUNCHER_REFUSAL") == "1" {
		if err := os.MkdirAll(filepath.Dir(launcherRefusalFixture), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(launcherRefusalFixture, buffer.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(launcherRefusalFixture)
	if err != nil {
		t.Fatalf("read %s: %v", launcherRefusalFixture, err)
	}
	if !bytes.Equal(want, buffer.Bytes()) {
		t.Fatalf("the launcher refusal changed: %s holds\n%s\nlauncherRefusalFor builds\n%s\nrewrite it with DEFENSECLAW_UPDATE_LAUNCHER_REFUSAL=1 and update the docs pages that quote the refusal (npm run test:docs-claims in docs-site)", launcherRefusalFixture, want, buffer.Bytes())
	}
}
