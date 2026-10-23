// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestR103B36ReviewRealClientCopyFact(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX copy command")
	}
	project := t.TempDir()
	t.Setenv("HOME", project)
	if err := os.Symlink("source-target", filepath.Join(project, "source")); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(project, "copied")
	for _, row := range []struct {
		name, command, want string
	}{
		{"one copy", "cp -P source copied; echo hi > copied", "c"},
		{"two copies", "cp -P source copied; cp -P source copied; echo hi > copied", ""},
	} {
		t.Run(row.name, func(t *testing.T) {
			body, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": project,
				"tool_input": map[string]string{"command": row.command}})
			if err != nil {
				t.Fatal(err)
			}
			facts, ok := Decode(Resolve(body))
			if !ok {
				t.Fatal("invalid real-client header")
			}
			if got := facts[OpaqueScopeFactPrefix+destination]; got != row.want {
				t.Fatalf("copy fact = %q, want %q", got, row.want)
			}
		})
	}
}

func TestR103B36ReviewCopyScopeOwnership(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX path fixture")
	}
	root := t.TempDir()
	path := filepath.Join(root, "copied")
	other := filepath.Join(root, "outside")
	copyLinks := shellLinks{opaque: true, opaqueScopes: []opaqueScope{{path: path, copy: true}}, copyDestinations: []string{path}}
	if got := copyLinks.opaqueScopeFact(path); got != "c" {
		t.Fatalf("single copy fact = %q, want c", got)
	}
	if got := copyLinks.opaqueScopeFact(other); got != "0" {
		t.Fatalf("outside fact = %q, want 0", got)
	}
	if copyLinks.opaqueTargetWithFacts(path, "", map[string]string{OpaqueScopeFactPrefix + path: "c"}) == false {
		t.Fatal("c fact escaped without own-copy ownership")
	}
	t.Run("second copy to same destination", func(t *testing.T) {
		copyLinks.copyDestinations = []string{path, path}
		if got := copyLinks.opaqueScopeFact(path); got != "" {
			t.Fatalf("two-copy fact = %q, want no fact", got)
		}
		if !copyLinks.opaqueTargetWithFacts(path, path, map[string]string{OpaqueScopeFactPrefix + path: "c"}) {
			t.Fatal("two copies accepted a c fact")
		}
	})
	t.Run("archive overlaps copy", func(t *testing.T) {
		copyLinks.copyDestinations = []string{path}
		copyLinks.opaqueScopes = append(copyLinks.opaqueScopes, opaqueScope{path: root})
		if got := copyLinks.opaqueScopeFact(path); got != "" {
			t.Fatalf("overlap fact = %q, want no fact", got)
		}
		if !copyLinks.opaqueTargetWithFacts(path, path, map[string]string{OpaqueScopeFactPrefix + path: "c"}) {
			t.Fatal("overlapping archive accepted a c fact")
		}
	})
}

func TestR103B36ReviewFactOnlyReplacesIncompleteWalk(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX path walk")
	}
	root := t.TempDir()
	hidden := filepath.Join(root, "hidden")
	scope := filepath.Join(hidden, "scope")
	if err := os.MkdirAll(scope, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(hidden, "alias")
	if err := os.Symlink("scope", alias); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(alias, "n")
	links := shellLinks{opaque: true, opaqueScopes: []opaqueScope{{path: scope}}}
	forged := map[string]string{OpaqueScopeFactPrefix + target: "0"}
	if !links.opaqueTargetWithFacts(target, "", forged) {
		t.Fatal("complete walk ignored its symlink hop into scope")
	}
	if got := links.opaqueScopeFact(target); got != "" {
		t.Fatalf("client generated %q for link hop into scope", got)
	}
	if err := os.Chmod(hidden, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(hidden, 0o700) })
	if !links.opaqueTargetWithFacts(target, "", nil) {
		t.Fatal("incomplete walk with no fact did not fail closed")
	}
	if !links.opaqueTargetWithFacts(filepath.Join(scope, "n"), "", forged) {
		t.Fatal("lexical scope was cleared by another operand's fact")
	}
}
