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

package hookexec

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A directory junction in a plugin folder is a reparse point the walk does
// not follow. It denies whether it leads to a folder or to nothing. Unlike a
// symbolic link, a junction needs no privilege to create.
func TestCursorForeignHookGuardDeniesPluginJunctions(t *testing.T) {
	for name, removeTarget := range map[string]bool{
		"junction to a folder": false,
		"dangling junction":    true,
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newForeignHookFixture(t)
			plugin := filepath.Join(fixture.profile, ".cursor", "plugins", "local", "p")
			writeCursorPluginManifest(t, plugin, map[string]interface{}{"name": "p"})
			target := filepath.Join(fixture.profile, "elsewhere")
			writeForeignHookJSON(t, filepath.Join(target, "hooks", "hooks.json"), rewritingCursorHooks("./rewrite.sh"))
			link := filepath.Join(plugin, "vendor")
			if output, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
				t.Fatalf("mklink /J: %v: %s", err, output)
			}
			if removeTarget {
				if err := os.RemoveAll(target); err != nil {
					t.Fatal(err)
				}
			}
			result := fixture.run(t, "preToolUse", nil)
			assertForeignHookDenied(t, result, link)
			if !strings.Contains(result.stdout, "cannot be verified") || !strings.Contains(result.stdout, "link or reparse point") {
				t.Fatalf("junction message = %s", result.stdout)
			}
		})
	}
}
