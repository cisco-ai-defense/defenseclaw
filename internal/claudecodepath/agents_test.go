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

package claudecodepath

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestProjectAgentDirsUseClosestFirstAncestorScopes(t *testing.T) {
	repository := filepath.Join(t.TempDir(), "repo")
	launch := filepath.Join(repository, "apps", "web")
	if err := os.MkdirAll(filepath.Join(repository, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(launch, 0o700); err != nil {
		t.Fatal(err)
	}

	got := ProjectAgentDirs(launch)
	want := []string{
		filepath.Join(launch, ".claude", "agents"),
		filepath.Join(repository, "apps", ".claude", "agents"),
		filepath.Join(repository, ".claude", "agents"),
	}
	if !slices.Equal(got, want) {
		t.Fatalf("ProjectAgentDirs() = %v, want %v", got, want)
	}
}

func TestAgentFilesAreRecursiveMarkdownAndDoNotFollowLinks(t *testing.T) {
	root := filepath.Join(t.TempDir(), "agents")
	nested := filepath.Join(root, "review", "security.md")
	ignored := filepath.Join(root, "review", "notes.txt")
	for path, content := range map[string]string{
		nested:  "---\nname: security-reviewer\ndescription: Reviews security\n---\n",
		ignored: "not an agent\n",
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	got := AgentFiles(root)
	if !slices.Equal(got, []string{nested}) {
		t.Fatalf("AgentFiles() = %v, want [%s]", got, nested)
	}
}
