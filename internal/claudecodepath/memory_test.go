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
	"strings"
	"testing"
)

func TestResolveAutoMemoryUsesSharedLinkedWorktreeRoot(t *testing.T) {
	root := t.TempDir()
	main := filepath.Join(root, "main")
	gitDir := filepath.Join(main, ".git")
	worktree := filepath.Join(root, "worktree")
	worktreeGit := filepath.Join(gitDir, "worktrees", "feature")
	for _, dir := range []string{worktree, worktreeGit} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(worktree, ".git"), []byte("gitdir: "+worktreeGit+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(worktreeGit, "commondir"), []byte("../..\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configDir := filepath.Join(root, "claude-home")

	got := ResolveAutoMemory(configDir, worktree, []string{})
	want := filepath.Join(configDir, "projects", projectStorageKey(main), "memory")
	if got.Path != want || got.ProjectRoot != main {
		t.Fatalf("ResolveAutoMemory() = %#v, want path=%s root=%s", got, want, main)
	}
	if got.ActivationVerified || !strings.Contains(got.Limitation, "--settings") {
		t.Fatalf("ResolveAutoMemory() verification = %#v, want unverified session limitation", got)
	}
}

func TestResolveAutoMemoryHonorsFilePrecedence(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "project")
	configDir := filepath.Join(root, "claude-home")
	managed := filepath.Join(root, "managed-settings.json")
	if err := os.MkdirAll(filepath.Join(project, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	for path, value := range map[string]string{
		filepath.Join(configDir, "settings.json"):                filepath.Join(root, "user-memory"),
		filepath.Join(project, ".claude", "settings.json"):       filepath.Join(root, "project-memory"),
		filepath.Join(project, ".claude", "settings.local.json"): filepath.Join(root, "local-memory"),
		managed: filepath.Join(root, "managed-memory"),
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(`{"autoMemoryDirectory":`+quoteJSON(value)+`}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	got := ResolveAutoMemory(configDir, project, []string{managed})
	if got.Path != filepath.Join(root, "managed-memory") || got.Source != managed {
		t.Fatalf("ResolveAutoMemory() = %#v, want managed override", got)
	}
}

func TestAutoMemoryFilesReturnsRecursiveMarkdown(t *testing.T) {
	root := t.TempDir()
	memory := filepath.Join(root, "memory")
	index := filepath.Join(memory, "MEMORY.md")
	topic := filepath.Join(memory, "topics", "debugging.md")
	ignored := filepath.Join(memory, "notes.txt")
	for path, body := range map[string]string{index: "index", topic: "topic", ignored: "ignored"} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got := AutoMemoryFiles(AutoMemoryResolution{Path: memory})
	if !slices.Equal(got, []string{index, topic}) {
		t.Fatalf("AutoMemoryFiles() = %v, want [%s %s]", got, index, topic)
	}
}

func quoteJSON(value string) string {
	quoted := strings.ReplaceAll(value, `\`, `\\`)
	quoted = strings.ReplaceAll(quoted, `"`, `\"`)
	return `"` + quoted + `"`
}
