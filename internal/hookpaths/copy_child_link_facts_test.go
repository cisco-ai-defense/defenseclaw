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

package hookpaths

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// A cp with a pattern source walks the link children of its destination
// directory, and only then: the gateway matches the child names against the
// pattern words it reads (GAP-1053).
func TestLinkWalkFactsListsLinkChildrenOfCopyDestination(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("link walk facts are POSIX only")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "state", "config.yaml")
	linked := filepath.Join(root, "proj", "linked")
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(linked, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(linked, "config.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(linked, "plain.txt"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cwd := filepath.Join(root, "proj")
	for _, row := range []struct {
		name, command string
		want          bool
	}{
		{"pattern-source-plain-destination", "cp /tmp/x/conf*.yaml linked/", true},
		{"pattern-source-target-directory", "cp -t linked /tmp/x/*.yaml", true},
		{"pattern-source-long-target-directory", "cp --target-directory=linked /tmp/x/*.yaml", true},
		{"brace-source", "cp /tmp/x/{a,b}.yaml linked/", true},
		{"plain-source", "cp /tmp/x/config.yaml linked/", false},
		{"pattern-source-file-destination", "cp /tmp/x/*.yaml linked/plain.txt", false},
		{"pattern-source-other-directory", "cp /tmp/x/*.yaml ./", false},
		{"move", "mv /tmp/x/*.yaml linked/", false},
	} {
		facts := LinkWalkFacts(row.command, cwd, root)
		children := WalkFactChildren(facts, linked)
		got := children["config.yaml"] == target
		if got != row.want || len(children) > 1 || children["plain.txt"] != "" {
			t.Errorf("%s: children of linked for %q = %v, want config.yaml %t only", row.name, row.command, children, row.want)
		}
	}
}
