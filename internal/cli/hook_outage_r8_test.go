// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenClawOutageKnownWriteTargets(t *testing.T) {
	home := t.TempDir()
	previous := outageAccountHome
	outageAccountHome = func() string { return home }
	t.Cleanup(func() { outageAccountHome = previous })
	root := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	protected := filepath.Join(root, "config.yaml")
	if err := os.WriteFile(protected, []byte("guardrail: {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ordinary := t.TempDir()
	link := filepath.Join(ordinary, "config-link")
	if err := os.Symlink(protected, link); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, command, value, want string
	}{
		{"named-file", "printf x >> " + protected, "", "protected"},
		{"named-link", "printf x >> " + link, "", "protected"},
		{"named-workdir", "printf x >> config.yaml", "", "protected"},
		{"local-known-file", "out='" + protected + "'; printf x >> \"$out\"", "", "protected"},
		{"local-known-link", "out='" + link + "'; printf x >> \"$out\"", "", "protected"},
		{"env-known-file", "printf x >> \"$OUT\"", protected, "protected"},
		{"env-known-link", "printf x >> \"$OUT\"", link, "protected"},
		{"positional-known-file", "sh -c 'printf x >> \"$1\"' _ '" + protected + "'", "", "protected"},
		{"ordinary-literal", "printf x >> notes.txt", protected, "open"},
		{"ordinary-local", "out=notes.txt; printf x >> \"$out\"", protected, "open"},
		{"ordinary-positional", "sh -c 'printf x >> \"$1\"' _ notes.txt", protected, "open"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := map[string]interface{}{"command": tc.command}
			if tc.value != "" {
				args["env"] = map[string]interface{}{"OUT": tc.value}
			}
			if tc.name == "named-workdir" {
				args["workdir"] = root
			}
			blob, err := json.Marshal(outageToolPayload{Name: "exec", Args: args, CWD: ordinary})
			if err != nil {
				t.Fatal(err)
			}
			if got := outageToolDecision(strings.NewReader(string(blob)), root); got != tc.want {
				t.Errorf("decision=%q want=%q", got, tc.want)
			}
		})
	}
}

// TestOpenClawOutageKnownAndNamedTargetBoundary keeps the outage check on named
// targets. Known values and named targets retain the same protected outcome;
// ordinary work remains open.
func TestOpenClawOutageKnownAndNamedTargetBoundary(t *testing.T) {
	home := t.TempDir()
	prior := outageAccountHome
	outageAccountHome = func() string { return home }
	t.Cleanup(func() { outageAccountHome = prior })
	root := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	protected := filepath.Join(root, "config.yaml")
	if err := os.WriteFile(protected, []byte("guardrail: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ordinary := t.TempDir()
	link := filepath.Join(ordinary, "config-link")
	if err := os.Symlink(protected, link); err != nil {
		t.Fatal(err)
	}
	branchy := ""
	for i := 1; i <= 6; i++ {
		branchy += fmt.Sprintf("if test -f marker%d; then V%d=a; else V%d=b; fi; ", i, i, i)
	}
	branchy += `printf x >> "$OUT"`
	cases := []struct{ name, command, out, copy, want string }{
		{"named config", "printf x >> " + protected, "notes.txt", "cp", "protected"},
		{"named link", "printf x >> " + link, "notes.txt", "cp", "protected"},
		{"named config read", "cat " + protected, "notes.txt", "cp", "protected"},
		{"named link read", "cat " + link, "notes.txt", "cp", "protected"},
		{"ordinary literal", "printf x >> notes.txt", protected, "cp", "open"},
		{"ordinary read", "cat notes.txt", protected, "cp", "open"},
		{"known program ordinary", `"$COPY" notes.txt "$OUT"`, "notes.txt", "cp", "open"},
		{"split program ordinary", `$COPY notes.txt "$OUT"`, "notes.txt", "env cp", "open"},
		{"function ordinary", `f(){ printf x >> "$1"; }; f "$OUT"`, "notes.txt", "cp", "open"},
		{"case fallthrough ordinary", `bash -c 'case word in word) OUT=notes.txt;& other) printf x >> "$OUT";; esac'`, protected, "cp", "open"},
		{"case glob ordinary", `case other in w*) OUT="$PROT";; *) OUT=notes.txt;; esac; printf x >> "$OUT"`, protected, "cp", "open"},
		{"for break ordinary", `for x in notes.txt "$PROT"; do OUT="$x"; break; done; printf x >> "$OUT"`, protected, "cp", "open"},
		{"for continue ordinary", `for x in "$PROT"; do continue; OUT="$x"; done; printf x >> "$OUT"`, "notes.txt", "cp", "open"},
		{"compound true ordinary", `OUT=notes.txt; { true; } || OUT="$PROT"; printf x >> "$OUT"`, protected, "cp", "open"},
		{"bounded states ordinary", branchy, "notes.txt", "cp", "open"},
		{"known target deferred", `printf x >> "$OUT"`, protected, "cp", "protected"},
		{"known link deferred", `printf x >> "$OUT"`, link, "cp", "protected"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			blob, err := json.Marshal(outageToolPayload{Name: "exec", Args: map[string]interface{}{
				"command": tc.command,
				"env":     map[string]interface{}{"OUT": tc.out, "PROT": protected, "COPY": tc.copy},
			}, CWD: ordinary})
			if err != nil {
				t.Fatal(err)
			}
			if got := outageToolDecision(strings.NewReader(string(blob)), root); got != tc.want {
				t.Errorf("decision=%q want=%q", got, tc.want)
			}
		})
	}
}
