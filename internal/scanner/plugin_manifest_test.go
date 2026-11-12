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

package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestManifestEntrypointsCommandPerLauncher(t *testing.T) {
	for _, tc := range []struct {
		binary string
		want   []string
		fail   bool
	}{
		{"", []string{"plugin", "manifest-entrypoints"}, false},
		{"/usr/local/bin/defenseclaw", []string{"plugin", "manifest-entrypoints"}, false},
		{"/opt/defenseclaw-scanners", []string{"plugin-manifest-entrypoints"}, false},
		{"defenseclaw-scanners.exe", []string{"plugin-manifest-entrypoints"}, false},
		{"defenseclaw-plugin-scanner", nil, true},
	} {
		_, args, err := (&PluginScanner{BinaryPath: tc.binary}).manifestEntrypointsCommand()
		if (err != nil) != tc.fail || !slices.Equal(args, tc.want) {
			t.Errorf("%q: args %q, err %v; want %q (fail %v)", tc.binary, args, err, tc.want, tc.fail)
		}
	}
}

// The manifests reach the scanner as base64 on stdin, never as a path it
// opens again, and the scanner answer is returned as given.
func TestDeclaredEntrypointsSendsManifestBytesAndReadsTheAnswer(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture")
	}
	dir := t.TempDir()
	seen := filepath.Join(dir, "seen")
	script := filepath.Join(dir, "defenseclaw")
	body := fmt.Sprintf("#!/bin/sh\necho \"$@\" > %q\ncat >> %q\nprintf %s\n", seen, seen, `{\"entrypoints\":[\"lib/run.js\",\"bin/x\"]}`)
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := (&PluginScanner{BinaryPath: script}).DeclaredEntrypoints(context.Background(), map[string][]byte{"plugin.yaml": []byte("main: lib/run.js\n")})
	if err != nil || !slices.Equal(got, []string{"lib/run.js", "bin/x"}) {
		t.Fatalf("entrypoints = %q, %v", got, err)
	}
	recorded, _ := os.ReadFile(seen)
	text := string(recorded)
	// bWFpbjogbGliL3J1bi5qcwo= is base64 of "main: lib/run.js\n".
	if !strings.HasPrefix(text, "plugin manifest-entrypoints\n") || !strings.Contains(text, "bWFpbjogbGliL3J1bi5qcwo=") || strings.Contains(text, dir) && strings.Contains(text, "plugin.yaml\":\"/") {
		t.Fatalf("scanner saw %q", text)
	}
}

// A scanner that cannot answer is an error, not an empty list: the caller must
// not treat it as declaring nothing.
func TestDeclaredEntrypointsErrorIsNotAnEmptyAnswer(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture")
	}
	dir := t.TempDir()
	for name, body := range map[string]string{
		"exit":    "#!/bin/sh\ncat >/dev/null\necho boom >&2\nexit 3\n",
		"garbage": "#!/bin/sh\ncat >/dev/null\necho not-json\n",
	} {
		script := filepath.Join(dir, name, "defenseclaw")
		if err := os.MkdirAll(filepath.Dir(script), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		if got, err := (&PluginScanner{BinaryPath: script}).DeclaredEntrypoints(context.Background(), map[string][]byte{"plugin.yaml": nil}); err == nil {
			t.Errorf("%s: answered %q without an error", name, got)
		}
	}
}
