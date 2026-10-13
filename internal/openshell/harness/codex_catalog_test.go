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

//go:build !windows

package harness

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0637: under the Bedrock Mantle provider the Codex launcher makes the
// catalog Codex reads hold each bundled model under its Mantle id
// (openai.<slug>), so Codex does not warn that metadata for openai.gpt-5.5 was
// not found. The launcher is valid shell, and the catalog script keeps every
// bundled entry and adds hidden copies under the Mantle ids.
func TestCodexLauncherGivesMantleModelsTheirMetadata(t *testing.T) {
	spec, ok := Get("codex")
	if !ok {
		t.Fatal("no codex harness")
	}
	script := string(spec.Launcher().Data)
	dir := t.TempDir()
	path := filepath.Join(dir, "codex-launch")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if bash, err := exec.LookPath("bash"); err == nil {
		if out, err := exec.Command(bash, "-n", path).CombinedOutput(); err != nil {
			t.Fatalf("the Codex launcher is not valid shell: %v\n%s", err, out)
		}
	}
	for _, want := range []string{`model_catalog_json=\"$cat\"`, `"${catalog[@]+"${catalog[@]}"}" "$@"`, "debug models --bundled"} {
		if !strings.Contains(script, want) {
			t.Fatalf("the Codex launcher does not hold %q", want)
		}
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("no node")
	}
	_, rest, ok := strings.Cut(script, "node -e '")
	js, _, ok2 := strings.Cut(rest, "' >")
	if !ok || !ok2 {
		t.Fatal("no catalog script in the Codex launcher")
	}
	cmd := exec.Command(node, "-e", js)
	cmd.Stdin = strings.NewReader(`{"models":[{"slug":"gpt-5.5","display_name":"GPT-5.5","visibility":"list","base_instructions":"x"},` +
		`{"slug":"openai.gpt-5.5","display_name":"mine","visibility":"list"}]}`)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("catalog script: %v", err)
	}
	var raw struct {
		Models []map[string]any `json:"models"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		t.Fatalf("catalog output: %v", err)
	}
	if len(raw.Models) != 2 {
		t.Fatalf("catalog holds %d models, want the bundled one and the one that already had a Mantle entry left alone: %s", len(raw.Models), out)
	}
	if raw.Models[1]["display_name"] != "mine" || raw.Models[0]["slug"] != "gpt-5.5" {
		t.Fatalf("catalog = %s", out)
	}
	cmd = exec.Command(node, "-e", js)
	cmd.Stdin = strings.NewReader(`{"models":[{"slug":"gpt-5.5","display_name":"GPT-5.5","visibility":"list","base_instructions":"x"}]}`)
	out, err = cmd.Output()
	if err != nil {
		t.Fatalf("catalog script: %v", err)
	}
	if err := json.Unmarshal(out, &raw); err != nil || len(raw.Models) != 2 {
		t.Fatalf("catalog output = %s, %v", out, err)
	}
	if added := raw.Models[1]; added["slug"] != "openai.gpt-5.5" || added["visibility"] != "hide" || added["base_instructions"] != "x" {
		t.Fatalf("the Mantle entry = %v", added)
	}
}
