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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// TestUpgradeInAHomebrewUnderTheHome: on a Mac whose own Homebrew is under
// the home directory (~/homebrew), the formula CLI in its bin directory is
// Homebrew and a reinstall of the formula replaces it, so the upgrade runs
// (GAP-0391: sandbox setup refused the formula 0.1.1 there as installed
// another way, after it had started the old gateway service). A tarball CLI
// elsewhere in the home directory is still refused, with the way out.
func TestUpgradeInAHomebrewUnderTheHome(t *testing.T) {
	setup := func(t *testing.T, cli string) (*installFixture, *int) {
		t.Helper()
		home := filepath.Dir(filepath.Dir(filepath.Dir(cli)))
		t.Setenv("HOME", home)
		if err := os.MkdirAll(filepath.Dir(cli), 0o755); err != nil {
			t.Fatal(err)
		}
		writeExecutable(t, cli)
		f := newInstallFixture(t, fakeScript, "", "")
		prefix := filepath.Join(home, "homebrew")
		f.inst.Release = openshell.InstallerTag
		f.inst.GOOS, f.inst.BrewPrefix, f.inst.PackageCLI = "darwin", prefix, ""
		f.inst.Candidates, f.inst.E2fsprogsDirs = []string{cli}, []string{t.TempDir()}
		version := "openshell 0.1.1"
		f.runner.OnFunc(cli+" --version", func(context.Context, openshell.Command) ([]byte, error) {
			return []byte(version + "\n"), nil
		})
		f.runner.OnFunc("/bin/sh", func(context.Context, openshell.Command) ([]byte, error) {
			version = "openshell " + openshell.InstallerVersion
			return nil, nil
		})
		prepared := new(int)
		f.inst.PrepareUpgrade = func(context.Context, openshell.Version) error { *prepared++; return nil }
		return f, prepared
	}
	t.Run("the formula CLI of a Homebrew in the home", func(t *testing.T) {
		cli := filepath.Join(t.TempDir(), "Users", "dcm-std2", "homebrew", "bin", "openshell")
		f, prepared := setup(t, cli)
		res, err := f.inst.Upgrade(context.Background())
		if err != nil || !res.Installed || res.CLIVersion.String() != openshell.InstallerVersion || *prepared != 1 || !f.ran() {
			t.Fatalf("Upgrade = %+v, %v (prepared %d, ran %v)", res, err, *prepared, f.ran())
		}
	})
	t.Run("a tarball CLI in the home", func(t *testing.T) {
		cli := filepath.Join(t.TempDir(), "home", ".local", "bin", "openshell")
		f, prepared := setup(t, cli)
		_, err := f.inst.Upgrade(context.Background())
		if !errors.Is(err, openshell.ErrUnmanagedUpgrade) || !strings.Contains(err.Error(), "the way you installed it") || f.ran() || *prepared != 0 {
			t.Fatalf("Upgrade = %v (prepared %d, ran %v)", err, *prepared, f.ran())
		}
	})
}
