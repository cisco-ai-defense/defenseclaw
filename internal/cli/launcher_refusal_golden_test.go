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

// launcherRefusalGoldenPath is the per-OS refusal text the docs gate
// (docs-site/scripts/test-docs-claims.ts) reads. The docs test cannot run Go,
// so the text it compares pages against is evaluated here from
// launcherRefusalFor itself, never re-parsed from the source.
var launcherRefusalGoldenPath = filepath.Join("testdata", "launcher_refusal.json")

// TestLauncherRefusalGoldenMatchesTheLauncher pins what the launcher prints on
// each OS. Regenerate with DEFENSECLAW_UPDATE_GOLDEN=1 after an intended text
// change, then update the pages the docs gate names.
func TestLauncherRefusalGoldenMatchesTheLauncher(t *testing.T) {
	texts := map[string]string{}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		texts[goos] = launcherRefusalFor(goos)
	}
	var got bytes.Buffer
	encoder := json.NewEncoder(&got)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(texts); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("DEFENSECLAW_UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(launcherRefusalGoldenPath, got.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(launcherRefusalGoldenPath)
	if err != nil {
		t.Fatalf("read %s (DEFENSECLAW_UPDATE_GOLDEN=1 writes it): %v", launcherRefusalGoldenPath, err)
	}
	// A Windows checkout gives the golden CRLF line endings.
	want = bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("the launcher refusal changed; regenerate %s with DEFENSECLAW_UPDATE_GOLDEN=1 and update the docs pages test:docs-claims names", launcherRefusalGoldenPath)
	}
}
