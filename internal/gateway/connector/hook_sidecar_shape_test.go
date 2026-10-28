// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 1.0.4 review (loop round 3 of G-hooks-upg): the readers now close on a
// hooks/.hookcfg that is not one of the writers' shapes (a broken document
// with a KEY=value line in it, a key given twice, a field named in another
// case). The writers carry peer state across a rewrite, so they must refuse
// that state rather than settle it: before, a refresh of one connector
// migrated "{broken ... DEFENSECLAW_FAIL_MODE=open" to a JSON legacy open
// and kept the last of two fail_modes entries, reopening what the readers
// close. A managed sidecar is guardian-owned and is still replaced outright.
func TestHookSidecarWritersRefuseStateTheReadersClose(t *testing.T) {
	for name, body := range map[string]string{
		"broken-json-then-flat-open":   "{\"version\":2,\"fail_modes\":\nDEFENSECLAW_FAIL_MODE=open\n",
		"bom-then-flat-open":           "\ufeffDEFENSECLAW_FAIL_MODE=open\n",
		"comment-then-broken-json":     "# note\n{\"version\":2,\nDEFENSECLAW_FAIL_MODE=open\n",
		"legacy-mode-twice-open-first": "DEFENSECLAW_FAIL_MODE=open\nDEFENSECLAW_FAIL_MODE=closed\n",
		"legacy-mode-twice-open-last":  "DEFENSECLAW_FAIL_MODE=closed\nDEFENSECLAW_FAIL_MODE=open\n",
		"json-entry-twice":             `{"version":2,"fail_modes":{"codex":"closed","codex":"open"}}`,
		"json-key-twice":               `{"version":2,"fail_modes":{"codex":"closed"},"fail_modes":{"codex":"open"}}`,
		"json-field-in-another-case":   `{"version":2,"FAIL_MODES":{"codex":"open"}}`,
		// 1.0.4 review (loop round 4): the readers close on a present null
		// fail_modes and on JSON outside their contract, which the writers
		// rewrote into a valid map while carrying the legacy open mode, or
		// into a document the readers open on.
		"json-fail-modes-null-legacy-open": `{"version":2,"fail_modes":null,"legacy_fail_mode":"open"}`,
		"json-fail-modes-null":             `{"version":2,"gateway_addr":"127.0.0.1:1","fail_modes":null}`,
		"json-deeper-than-32":              `{"version":2,"fail_modes":{"codex":"open"},"x":` + strings.Repeat("[", 32) + strings.Repeat("]", 32) + `}`,
		"json-larger-than-64KiB":           `{"version":2,"fail_modes":{"codex":"open"},"pad":"` + strings.Repeat("x", 64<<10) + `"}`,
		"json-escaped-entry":               `{"version":2,"fail_modes":{"codex":"\u006fpen"}}`,
		"json-escaped-unknown-field":       `{"version":2,"fail_modes":{"codex":"open"},"x":"a\\b"}`,
		"json-version-exponent":            `{"version":2e0,"fail_modes":{"codex":"open"}}`,
		"json-version-future":              `{"version":3,"fail_modes":{"codex":"open"}}`,
		"json-nan":                         `{"version":2,"fail_modes":{"codex":"open"},"x":NaN}`,
		// Loop round 2 after round 4: every reader closes on a sidecar past
		// 64 KiB, the 0.8.x KEY=value shape included, yet the writers
		// carried its legacy open into the JSON they wrote.
		"legacy-larger-than-64KiB": "DEFENSECLAW_FAIL_MODE=open\n#" + strings.Repeat("x", 64<<10) + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			hookDir := t.TempDir()
			path := filepath.Join(hookDir, hookConfigSidecarName)
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := writeHookConfigSidecar(hookDir, "127.0.0.1:1", "claudecode", "closed", false); err == nil {
				t.Fatal("the writer rewrote state the readers close on")
			}
			if err := clearHookConfigSidecarEntry(hookDir, "codex"); err == nil {
				t.Fatal("the teardown rewrote state the readers close on")
			}
			if got, err := os.ReadFile(path); err != nil || string(got) != body {
				t.Fatalf("sidecar changed: %q (%v)", got, err)
			}
		})
	}
	// A link to open JSON: the shared hooks close on it, and a rewrite would
	// put a regular file with the carried open entry there.
	t.Run("json-link-to-open-state", func(t *testing.T) {
		hookDir := t.TempDir()
		path := filepath.Join(hookDir, hookConfigSidecarName)
		target := filepath.Join(t.TempDir(), "state.json")
		if err := os.WriteFile(target, []byte(`{"version":2,"fail_modes":{"codex":"open"}}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		if err := writeHookConfigSidecar(hookDir, "127.0.0.1:1", "claudecode", "open", false); err == nil {
			t.Fatal("the writer rewrote a link the readers close on")
		}
		if err := clearHookConfigSidecarEntry(hookDir, "codex"); err == nil {
			t.Fatal("the teardown rewrote a link the readers close on")
		}
		if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("the link was replaced: %v %v", info, err)
		}
	})
	// The writers' own shapes carry over: a 0.8.x KEY=value file and a v2
	// document.
	for name, tc := range map[string]struct {
		body       string
		wantLegacy string
		wantPeer   string
	}{
		"legacy-0.8": {body: "# DefenseClaw\nDEFENSECLAW_GATEWAY_ADDR=127.0.0.1:1\nexport DEFENSECLAW_FAIL_MODE=\"open\"\n", wantLegacy: "open"},
		"v2":         {body: `{"version":2,"gateway_addr":"127.0.0.1:1","fail_modes":{"codex":"open"},"extra":{"a":{"a":1}}}`, wantPeer: "open"},
		"v2-null-fields": {body: `{"version":2,"gateway_addr":null,"legacy_fail_mode":null,"fail_modes":{"codex":"open","cursor":null},"n":[1e5,-0.5]}`,
			wantPeer: "open"},
	} {
		t.Run("carries/"+name, func(t *testing.T) {
			hookDir := t.TempDir()
			path := filepath.Join(hookDir, hookConfigSidecarName)
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := writeHookConfigSidecar(hookDir, "127.0.0.1:1", "claudecode", "closed", false); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var state hookConfigSidecar
			if err := json.Unmarshal(data, &state); err != nil {
				t.Fatal(err)
			}
			if state.LegacyMode != tc.wantLegacy || state.FailModes["codex"] != tc.wantPeer || state.FailModes["claudecode"] != "closed" {
				t.Fatalf("carried state %+v", state)
			}
		})
	}
}

// The writers' readiness check reads a flat record as the shared Unix hooks
// do (defenseclaw_flat_hookcfg_value): a record that gives its mode twice,
// has another line or ends without a newline is not the mode it was
// written with. Before, the check took the first value and passed a record
// the hooks run closed.
func TestHookRuntimeStateCheckReadsFlatRecordsAsTheHooksDo(t *testing.T) {
	for name, suffix := range map[string]string{
		"mode-twice":  "DEFENSECLAW_FAIL_MODE=closed\n",
		"extra-line":  "{\n",
		"lower-case":  "x=1\n",
		"blank-line":  "\n",
		"cut-short":   "DEFENSECLAW_GATEWAY_ADDR=127.0.0.1:1",
		"nul":         "EXTRA=\x00\n",
		"well-formed": "",
	} {
		t.Run(name, func(t *testing.T) {
			dataDir := t.TempDir()
			hookDir := filepath.Join(dataDir, "hooks")
			if err := os.MkdirAll(hookDir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := writeHookConfigSidecar(hookDir, "127.0.0.1:1", "codex", "open", false); err != nil {
				t.Fatal(err)
			}
			flatPath := filepath.Join(hookDir, hookConfigSidecarName+".codex")
			flat, err := os.ReadFile(flatPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(flatPath, append(flat, suffix...), 0o600); err != nil {
				t.Fatal(err)
			}
			err = ValidateHookRuntimeState(dataDir, "codex", "open")
			if (err == nil) != (suffix == "") {
				t.Fatalf("ValidateHookRuntimeState = %v for record %q", err, string(flat)+suffix)
			}
		})
	}
}

// Every JSON object in the shared hooks/.hookcfg vectors that the native
// hook and status read closed as malformed state is one the writers refuse
// to rewrite, so no refresh of another connector turns it into a document a
// reader opens on (1.0.4 review, loop round 4 of G-hooks-upg).
func TestHookSidecarWritersRefuseEveryMalformedSharedVector(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "cli", "testdata", "windows_hook_sidecar_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []struct {
			Name string `json:"name"`
			Kind string `json:"kind"`
			Body string `json:"body"`
			Mode string `json:"mode"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, vector := range file.Vectors {
		var doc map[string]json.RawMessage
		if vector.Kind != "" || !strings.HasPrefix(vector.Name, "malformed/") || vector.Mode != "closed" ||
			json.Unmarshal([]byte(vector.Body), &doc) != nil || doc == nil {
			continue
		}
		checked++
		t.Run(vector.Name, func(t *testing.T) {
			hookDir := t.TempDir()
			path := filepath.Join(hookDir, hookConfigSidecarName)
			if err := os.WriteFile(path, []byte(vector.Body), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := writeHookConfigSidecar(hookDir, "127.0.0.1:1", "claudecode", "open", false); err == nil {
				t.Fatal("the writer rewrote state the native hook closes on")
			}
			if got, err := os.ReadFile(path); err != nil || string(got) != vector.Body {
				t.Fatalf("sidecar changed: %q (%v)", got, err)
			}
		})
	}
	if checked < 10 {
		t.Fatalf("only %d malformed JSON vectors", checked)
	}
}

func TestHookSidecarShapes(t *testing.T) {
	deep := func(levels int) string {
		return `{"version":2,"x":` + strings.Repeat("[", levels-1) + strings.Repeat("]", levels-1) + `}`
	}
	for body, malformed := range map[string]bool{
		`{"version":2}`: false,
		`{"version":3,"gateway_addr":null,"legacy_fail_mode":null,"fail_modes":{"a":null,"b":"open"}}`: false,
		`{"version":9223372036854775807}`:                  false,
		`{"version" : 2 , "x":[1e5,-0.5,{"version":2e0}]}`: false,
		deep(32):                                 false,
		deep(33):                                 true,
		`{"version":9223372036854775808}`:        true,
		`{"version":2e0}`:                        true,
		`{"version":2.0}`:                        true,
		`{"version":02}`:                         true,
		`{"version":-2}`:                         true,
		`{"version":"2"}`:                        true,
		`{"version":1}`:                          true,
		`{"version":null}`:                       true,
		`{}`:                                     true,
		`[]`:                                     true,
		`null`:                                   true,
		`{"version":2,"fail_modes":null}`:        true,
		`{"version":2,"fail_modes":[]}`:          true,
		`{"version":2,"fail_modes":{"a":1}}`:     true,
		`{"version":2,"gateway_addr":1}`:         true,
		`{"version":2,"legacy_fail_mode":false}`: true,
		`{"version":2,"fail_modes":{"a":"x","a":"y"}}`:              true,
		`{"version":2,"pad":"` + strings.Repeat("x", 64<<10) + `"}`: true,
	} {
		if got := HookSidecarJSONMalformed([]byte(body)) != nil; got != malformed {
			t.Errorf("HookSidecarJSONMalformed(%.60q) malformed = %v, want %v", body, got, malformed)
		}
	}
	// The shared Unix hooks also close on a backslash, which the native
	// hook reads; the writers refuse what either closes on.
	escaped := []byte(`{"version":2,"fail_modes":{"codex":"\u006fpen"}}`)
	if HookSidecarJSONMalformed(escaped) != nil || hookSidecarRewriteRefused(escaped) == nil {
		t.Fatal("an escaped entry: the native contract reads it, the writers must refuse it")
	}
	for body, want := range map[string]bool{
		`{"version":2,"fail_modes":{"codex":"open"}}`:                       false,
		`{"a":{"a":1},"b":[{"a":1},{"a":2}],"c":[[{"x":1}],{"x":{"x":2}}]}`: false,
		`{"a":1,"a":1}`:                 true,
		`{"a":{"b":1},"a":{"c":1}}`:     true,
		`[{"a":1,"b":{"c":1,"c":2}}]`:   true,
		`{"Version":2,"version":2}`:     true,
		`{"verſion":2}`:                 true,
		`{"versions":2,"fail_mode":{}}`: false,
		// Deep nesting walks without recursion; past 10000 levels it is
		// malformed.
		strings.Repeat("[", 5000) + strings.Repeat("]", 5000):                           false,
		strings.Repeat("[", 200000) + strings.Repeat("]", 200000):                       true,
		`{"x":` + strings.Repeat("[", 200000) + strings.Repeat("]", 200000) + `,"x":1}`: true,
	} {
		if got := HookSidecarJSONAmbiguous([]byte(body)); got != want {
			t.Errorf("HookSidecarJSONAmbiguous(%.60q) = %v, want %v", body, got, want)
		}
	}
	for body, want := range map[string]bool{
		"":                                    true,
		"# c\n\nDEFENSECLAW_FAIL_MODE=open\n": true,
		"export A_1='x'\r\nB=\"y\"\n":         true,
		"A=1\nA=1\n":                          false,
		"A=1\nnot a line\n":                   false,
		"\ufeffA=1\n":                         false,
		"1A=1\n":                              false,
		"{\"A\":1}":                           false,
		"[\"A=1\"]":                           false,
		"null":                                false,
		"A=1\n#" + strings.Repeat("x", 64<<10-6) + "\n": true,
		"A=1\n#" + strings.Repeat("x", 64<<10-5) + "\n": false,
	} {
		if _, ok := ParseLegacyHookSidecar([]byte(body)); ok != want {
			t.Errorf("ParseLegacyHookSidecar(%q) ok = %v, want %v", body, ok, want)
		}
	}
	if value, ok := flatHookRecordValue([]byte("DEFENSECLAW_CONNECTOR=\nDEFENSECLAW_FAIL_MODE=open\n"), "DEFENSECLAW_CONNECTOR"); !ok || value != "" {
		t.Fatalf("legacy flat record connector = %q, %v", value, ok)
	}
	if _, ok := flatHookRecordValue(bytes.Repeat([]byte("A=1\n"), 1), "B"); ok {
		t.Fatal("a missing key read as present")
	}
}
