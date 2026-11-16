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

package harness

import (
	"os"
	"path/filepath"
	"testing"
)

// A Windows host has no /bin/sh: a test that starts one fails to start the
// process, and the cases that read the failure as a refusal go red. The
// tests that need a POSIX shell take it from the accessors below, which skip
// (binSh, binBash) or report the absence (maybeBinSh, maybeBinBash).

// shellIfPresent returns the shell at the path, or "" when the host has none.
func shellIfPresent(shell string) string {
	if fi, err := os.Stat(shell); err != nil || fi.IsDir() {
		return ""
	}
	return shell
}

// maybeBinSh and maybeBinBash return the host shell, or "" for a test that
// runs a lighter check without one.
func maybeBinSh() string   { return shellIfPresent("/bin/sh") }
func maybeBinBash() string { return shellIfPresent("/bin/bash") }

// needShell skips the test when the shell is empty (absent) and returns it.
func needShell(t testing.TB, shell string) string {
	t.Helper()
	if shell == "" {
		t.Skip("a POSIX shell is required")
	}
	return shell
}

// binSh and binBash skip the test when the host has no such shell. They are
// for the tests that run an image-build shell fragment; the fragments run in
// the Linux sandbox image, never on the host.
func binSh(t testing.TB) string   { t.Helper(); return needShell(t, maybeBinSh()) }
func binBash(t testing.TB) string { t.Helper(); return needShell(t, maybeBinBash()) }

func TestShellAccessorsSkipWhenTheShellIsMissing(t *testing.T) {
	if got := shellIfPresent(filepath.Join(t.TempDir(), "no-such-shell")); got != "" {
		t.Errorf("a missing shell came back as %q", got)
	}
	if got := shellIfPresent(t.TempDir()); got != "" {
		t.Errorf("a directory came back as the shell %q", got)
	}
	here := filepath.Join(t.TempDir(), "sh")
	if err := os.WriteFile(here, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := shellIfPresent(here); got != here {
		t.Errorf("a present shell came back as %q, want %q", got, here)
	}
	if got := needShell(t, here); got != here {
		t.Errorf("needShell returned %q, want %q", got, here)
	}
	skipped := false
	t.Run("without a shell", func(t *testing.T) {
		defer func() { skipped = t.Skipped() }()
		needShell(t, "")
		t.Error("the test ran on after needShell on an empty shell")
	})
	if !skipped {
		t.Error("a missing shell did not skip the test")
	}
}
