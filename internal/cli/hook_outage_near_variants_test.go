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

func TestOpenClawOutageKnownValueNearVariants(t *testing.T) {
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
	if err := os.WriteFile(filepath.Join(ordinary, "notes.txt"), []byte("notes\n"), 0600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(ordinary, "config-link")
	if err := os.Symlink(protected, linked); err != nil {
		t.Fatal(err)
	}
	branchy := ""
	for i := 1; i <= 6; i++ {
		branchy += fmt.Sprintf("if test -f marker%d; then V%d=a; else V%d=b; fi; ", i, i, i)
	}
	branchy += `printf x >> "$OUT"`
	cases := []struct{ name, command, out, copy, want string }{
		{"control known program protected", `"$COPY" notes.txt "$OUT"`, protected, "cp", "protected"},
		{"control known program ordinary", `"$COPY" notes.txt "$OUT"`, "ordinary.txt", "cp", "open"},
		{"split known program protected", `$COPY notes.txt "$OUT"`, protected, "env cp", "protected"},
		{"split known program ordinary", `$COPY notes.txt "$OUT"`, "ordinary.txt", "env cp", "open"},
		{"split known program option protected", `$COPY notes.txt "$OUT"`, protected, "cp -f", "protected"},
		{"function positional protected", `f(){ printf x >> "$1"; }; f "$OUT"`, protected, "cp", "protected"},
		{"function positional link protected", `f(){ printf x >> "$1"; }; f "$OUT"`, linked, "cp", "protected"},
		{"function positional ordinary", `f(){ printf x >> "$1"; }; f "$OUT"`, "ordinary.txt", "cp", "open"},
		{"function second positional protected", `f(){ printf x >> "$2"; }; f skip "$OUT"`, protected, "cp", "protected"},
		{"function local value protected", `f(){ printf x >> "$target"; }; target="$OUT"; f`, protected, "cp", "protected"},
		{"function local value ordinary", `f(){ printf x >> "$target"; }; target=ordinary.txt; f`, protected, "cp", "open"},
		{"case fallthrough protected", `bash -c 'case word in word) OUT="$PROT";& other) printf x >> "$OUT";; esac'`, "ordinary.txt", "cp", "protected"},
		{"case fallthrough ordinary", `bash -c 'case word in word) OUT=ordinary.txt;& other) printf x >> "$OUT";; esac'`, protected, "cp", "open"},
		{"case glob ordinary", `case other in w*) OUT="$PROT";; *) OUT=ordinary.txt;; esac; printf x >> "$OUT"`, protected, "cp", "open"},
		{"case glob protected", `case word in w*) OUT="$PROT";; *) OUT=ordinary.txt;; esac; printf x >> "$OUT"`, "ordinary.txt", "cp", "protected"},
		{"for break protected", `for x in "$PROT" ordinary.txt; do OUT="$x"; break; done; printf x >> "$OUT"`, "ordinary.txt", "cp", "protected"},
		{"for break ordinary", `for x in ordinary.txt "$PROT"; do OUT="$x"; break; done; printf x >> "$OUT"`, protected, "cp", "open"},
		{"for continue ordinary", `for x in "$PROT"; do continue; OUT="$x"; done; printf x >> "$OUT"`, "ordinary.txt", "cp", "open"},
		{"compound true branch ordinary", `OUT=ordinary.txt; { true; } || OUT="$PROT"; printf x >> "$OUT"`, protected, "cp", "open"},
		{"six unknown conditions protected", branchy, protected, "cp", "protected"},
		{"six unknown conditions ordinary", branchy, "ordinary.txt", "cp", "open"},
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
				t.Errorf("decision=%s want=%s command=%s", got, tc.want, tc.command)
			}
		})
	}
}
