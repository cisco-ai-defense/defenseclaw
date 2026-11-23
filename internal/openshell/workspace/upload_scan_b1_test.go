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

package workspace

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// b1Key builds a GitHub-token-shaped value at run time (no key-shaped
// literal in the source).
func b1Key(n int) string { return "gh" + "p_" + strings.Repeat("Z9", 18) + strings.Repeat("a", n) }

func readStaged(t *testing.T, root, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A file over the per-file limit is uploaded unscanned, and the copy says
// so (it used to be skipped with no report at all above 256 KiB).
func TestB1ScanLargeFileReported(t *testing.T) {
	e := newEnv(t)
	writeFile(t, e.project, "big.txt", strings.Repeat("plain text\n", 2000))
	writeFile(t, e.project, "small.txt", "ok\n")
	opts := e.stageOpts("big")
	opts.ScanMaxFileBytes = 4 << 10
	rec, err := Stage(bg, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(rec.NotScanned, []string{"big.txt"}) {
		t.Fatalf("not scanned = %v, want [big.txt]", rec.NotScanned)
	}
	if !slices.ContainsFunc(rec.Warnings, func(w string) bool {
		return strings.Contains(w, "1 file(s) not scanned for secrets") && strings.Contains(w, "big.txt")
	}) {
		t.Fatalf("warnings = %q", rec.Warnings)
	}
}

// A key past the old 256 KiB read limit is found (and, without rewrite,
// held back as before for smaller files).
func TestB1StreamFindsKeyPast256KiB(t *testing.T) {
	e := newEnv(t)
	writeFile(t, e.project, "data.txt", strings.Repeat("filler line\n", 30000)+"token: "+b1Key(0)+"\n")
	rec, err := Stage(bg, e.stageOpts("deep"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(rec.HeldBack, "data.txt") {
		t.Fatalf("held back = %v, want data.txt (key at byte %d)", rec.HeldBack, 30000*12)
	}
}

// With RewriteSecrets the file goes up with the value replaced; the record
// keeps where it was, never the value.
func TestB1RewriteKeepsFileUploadsPlaceholder(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	key := b1Key(0)
	src := "import os\nTOKEN = \"" + key + "\"\nprint(TOKEN)\n"
	writeFile(t, e.project, "config.py", src)
	e.git(e.project, "add", "config.py")
	e.commit("config")
	writeFile(t, e.project, "id_rsa", "named secret\n")
	opts := e.stageOpts("rw")
	opts.RewriteSecrets = PlaceholderToken
	rec, err := Stage(bg, opts)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(rec.HeldBack, "config.py") || !slices.Contains(rec.HeldBack, "id_rsa") {
		t.Fatalf("held back = %v, want id_rsa only", rec.HeldBack)
	}
	got := readStaged(t, rec.Stage, "config.py")
	if want := "import os\nTOKEN = \"DC_SECRET_1\"\nprint(TOKEN)\n"; got != want {
		t.Fatalf("uploaded config.py = %q, want %q", got, want)
	}
	if len(rec.SecretLines) != 1 {
		t.Fatalf("secret lines = %+v", rec.SecretLines)
	}
	l := rec.SecretLines[0]
	if l.Rel != "config.py" || l.Line != 2 || l.Lines != 1 || l.Column != len("TOKEN = \"") || l.Length != len(key) || l.Placeholder != "DC_SECRET_1" {
		t.Fatalf("secret line = %+v", l)
	}
	_ = filepath.WalkDir(e.data, func(p string, d os.DirEntry, err error) error {
		if err == nil && strings.HasSuffix(p, ".json") {
			if raw, _ := os.ReadFile(p); strings.Contains(string(raw), key) {
				t.Errorf("%s holds the value", p)
			}
		}
		return nil
	})
	// The committed version (which holds the value) is not in the copy's
	// objects; the replaced working file is in its baseline.
	if strings.Contains(e.git(rec.Stage, "cat-file", "--batch-all-objects", "--batch"), key) {
		t.Fatal("the copy's objects hold the value")
	}
	if !strings.Contains(e.git(rec.Stage, "show", rec.Baseline+":config.py"), "DC_SECRET_1") {
		t.Fatal("baseline lacks the replaced file")
	}
}

// Past the time budget the remaining files are listed, not scanned.
func TestB1ScanTimeBudgetListsRest(t *testing.T) {
	e := newEnv(t)
	for _, n := range []string{"a.txt", "b.txt", "c.txt"} {
		writeFile(t, e.project, n, "x\n")
	}
	now := time.Unix(1000, 0)
	opts := secretScanOptions{detector: DefaultSecretDetector(), contentScan: true, timeBudget: time.Second,
		clock: func() time.Time { now = now.Add(600 * time.Millisecond); return now }}
	s, err := detectSecretsIn(e.project, []string{"a.txt", "b.txt", "c.txt"}, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.late) == 0 || s.late[len(s.late)-1] != "c.txt" {
		t.Fatalf("late = %v", s.late)
	}
}
