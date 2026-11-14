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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSubstrate_Admin_BundleStageAndRollback(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "v3.dcbundle")
	if err := os.WriteFile(file, []byte("signed"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Run("apply names the stage", func(t *testing.T) {
		f := newSubAdminFake(t)
		subAdminSeams(t, func() (*substrateSession, error) { return f.session(t, f.context()), nil }, nil)
		if _, _, err := runSubAdmin(newSubstrateBundleCmd(), "apply", file, "--stage", "canary", "--atespaces", "team-a"); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(f.bundleBody), `"stage":"canary"`) {
			t.Errorf("body %s", f.bundleBody)
		}
	})
	t.Run("rollback", func(t *testing.T) {
		f := newSubAdminFake(t)
		subAdminSeams(t, func() (*substrateSession, error) { return f.session(t, f.context()), nil }, nil)
		out, _, err := runSubAdmin(newSubstrateBundleCmd(), "rollback", "--stage", "canary")
		if err != nil || !strings.Contains(out, "Stage canary rolled back") || !strings.Contains(out, "rolled_back") {
			t.Fatalf("%v\n%s", err, out)
		}
		if string(f.rollbackBody) != `{"stage":"canary"}` || f.rollbackClient == "" {
			t.Errorf("body %s client %q", f.rollbackBody, f.rollbackClient)
		}
	})
	t.Run("rollback needs a stage", func(t *testing.T) {
		if _, _, err := runSubAdmin(newSubstrateBundleCmd(), "rollback"); err == nil || commandExitCode(err) != 2 {
			t.Fatalf("err %v", err)
		}
	})
}
