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

package openshell_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// TestUpgradeRunsThroughTheHomebrewThatOwnsTheInstalledCLI (GAP-1119): a Mac
// whose first brew on PATH belongs to another account and whose OpenShell
// CLI sits in the account's own Homebrew was refused ("cannot write to
// /opt/homebrew/Library/Taps"), although the same command with the own
// Homebrew first on PATH upgrades. The upgrade now checks and runs the
// Homebrew that owns the installed CLI.
func TestUpgradeRunsThroughTheHomebrewThatOwnsTheInstalledCLI(t *testing.T) {
	root := t.TempDir()
	own := filepath.Join(root, "Users", "dcm-std2", "homebrew")
	other := filepath.Join(root, "opt", "homebrew")
	cli := filepath.Join(own, "bin", "openshell")
	for _, dir := range []string{filepath.Dir(cli), filepath.Join(own, "Cellar", "openshell", "0.1.3"), filepath.Join(own, "Library", "Taps"), filepath.Join(other, "Library", "Taps")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", filepath.Join(root, "Users", "dcm-std2"))
	writeExecutable(t, cli)
	f := newInstallFixture(t, fakeScript, "", "")
	f.inst.GOOS, f.inst.PackageCLI = "darwin", ""
	f.inst.BrewPrefix = other // the first brew on PATH
	f.inst.HomebrewPrefixProblem = nil
	f.inst.Candidates, f.inst.E2fsprogsDirs = []string{cli}, []string{t.TempDir()}
	version := "openshell 0.1.3"
	f.runner.OnFunc(cli+" --version", func(context.Context, openshell.Command) ([]byte, error) { return []byte(version + "\n"), nil })
	f.runner.OnFunc("/bin/sh", func(context.Context, openshell.Command) ([]byte, error) {
		version = "openshell " + openshell.InstallerVersion
		return nil, nil
	})
	// The other account's prefix is read-only for this account, the own one is not.
	if err := os.Chmod(filepath.Join(other, "Library", "Taps"), 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(other, "Library", "Taps"), 0o755) })
	if os.Geteuid() == 0 {
		t.Skip("root writes any directory")
	}
	res, err := f.inst.Upgrade(context.Background())
	if err != nil || !res.Installed || !f.ran() {
		t.Fatalf("Upgrade = %+v, %v (ran %v)\n%s", res, err, f.ran(), f.out.String())
	}
	path := ""
	for _, kv := range f.scriptRun().Env {
		if v, ok := strings.CutPrefix(kv, "PATH="); ok {
			path = v
		}
	}
	if !strings.HasPrefix(path, filepath.Join(own, "bin")+string(os.PathListSeparator)) {
		t.Fatalf("the installer's PATH %q does not start with the owning Homebrew's bin", path)
	}
	if !strings.Contains(f.out.String(), "the installed OpenShell belongs to the Homebrew at ") {
		t.Fatalf("plan names no owning Homebrew:\n%s", f.out.String())
	}
}
