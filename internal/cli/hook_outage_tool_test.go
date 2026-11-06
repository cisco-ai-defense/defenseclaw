// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenClawOutageToolKeepsProtectedTargetsClosed(t *testing.T) {
	home := t.TempDir()
	old := outageAccountHome
	outageAccountHome = func() string { return home }
	t.Cleanup(func() { outageAccountHome = old })
	protected := filepath.Join(home, ".defenseclaw", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(protected), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(protected, []byte("guardrail: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(home, "config-alias")
	if err := os.Symlink(protected, alias); err != nil {
		t.Fatal(err)
	}
	custom := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(custom, 0o700); err != nil {
		t.Fatal(err)
	}
	customConfig := filepath.Join(custom, "config.yaml")
	if err := os.WriteFile(customConfig, []byte("guardrail: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	customAlias := filepath.Join(home, "custom-alias")
	if err := os.Symlink(customConfig, customAlias); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		args    map[string]interface{}
		dataDir string
		want    string
	}{
		{"ordinary command", map[string]interface{}{"command": "date"}, "", "open"},
		{"direct write", map[string]interface{}{"command": "printf x >> ~/.defenseclaw/config.yaml"}, "", "protected"},
		{"known home write", map[string]interface{}{"command": `printf x >> "$HOME/.defenseclaw/config.yaml"`}, "", "protected"},
		{"known local value", map[string]interface{}{"command": `target="$HOME/.defenseclaw/config.yaml"; printf x >> "$target"`}, "", "protected"},
		{"linked write", map[string]interface{}{"command": "printf x >> " + alias}, "", "protected"},
		{"nested command", map[string]interface{}{"request": map[string]interface{}{"command": `printf x >> "$HOME/.defenseclaw/config.yaml"`}}, "", "protected"},
		{"direct path", map[string]interface{}{"path": protected}, "", "protected"},
		{"ordinary path", map[string]interface{}{"path": filepath.Join(home, "notes.txt")}, "", "open"},
		{"custom root ordinary", map[string]interface{}{"command": "date"}, custom, "open"},
		{"custom root write", map[string]interface{}{"command": "printf x >> " + customConfig}, custom, "protected"},
		{"custom root known value", map[string]interface{}{"command": `printf x >> "$DEFENSECLAW_HOME/config.yaml"`}, custom, "protected"},
		{"custom root link", map[string]interface{}{"command": "printf x >> " + customAlias}, custom, "protected"},
		{"custom root ordinary write", map[string]interface{}{"command": "printf x >> " + filepath.Join(home, "notes.txt")}, custom, "open"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			blob, err := json.Marshal(outageToolPayload{Name: "exec", Args: tc.args, CWD: home})
			if err != nil {
				t.Fatal(err)
			}
			dataDir := tc.dataDir
			if dataDir == "" {
				dataDir = filepath.Join(home, ".defenseclaw")
			}
			if got := outageToolDecision(strings.NewReader(string(blob)), dataDir); got != tc.want {
				t.Fatalf("outage decision = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestOpenClawOutageExecContextTargets(t *testing.T) {
	home := t.TempDir()
	old := outageAccountHome
	outageAccountHome = func() string { return home }
	t.Cleanup(func() { outageAccountHome = old })
	dataDir := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	protected := filepath.Join(dataDir, "config.yaml")
	if err := os.WriteFile(protected, []byte("guardrail: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	for _, tc := range []struct {
		name string
		args map[string]interface{}
		want string
	}{
		{"ordinary", map[string]interface{}{"command": "date"}, "open"},
		{"unused environment path", map[string]interface{}{"command": "date", "env": map[string]interface{}{"OUT": protected}}, "open"},
		{"unused FILE", map[string]interface{}{"command": "printf x >> notes.txt", "env": map[string]interface{}{"FILE": protected}}, "open"},
		{"unused TARGET", map[string]interface{}{"command": "printf x >> notes.txt", "env": map[string]interface{}{"TARGET": protected}}, "open"},
		{"unused DEST", map[string]interface{}{"command": "printf x >> notes.txt", "env": map[string]interface{}{"DEST": protected}}, "open"},
		{"literal environment spelling", map[string]interface{}{"command": "printf x >> '$OUT'", "env": map[string]interface{}{"OUT": protected}}, "open"},
		{"read-only environment path", map[string]interface{}{"command": "printf '%s' \"$OUT\"", "env": map[string]interface{}{"OUT": protected}}, "open"},
		{"read environment to ordinary file", map[string]interface{}{"command": "printf '%s' \"$OUT\" > " + filepath.Join(other, "notes.txt"), "env": map[string]interface{}{"OUT": protected}}, "open"},
		{"nested read environment to ordinary file", map[string]interface{}{"command": `sh -c 'printf "%s" "$OUT" > notes.txt'`, "env": map[string]interface{}{"OUT": protected}}, "open"},
		{"empty environment uses ordinary default", map[string]interface{}{"command": `printf x >> "${OUT:-notes.txt}"`, "env": map[string]interface{}{"OUT": ""}}, "open"},
		{"direct", map[string]interface{}{"command": "printf x >> " + protected}, "protected"},
		{"workdir", map[string]interface{}{"command": "printf x >> config.yaml", "workdir": dataDir}, "protected"},
		{"home workdir", map[string]interface{}{"command": "printf x >> .defenseclaw/config.yaml", "workdir": "~"}, "protected"},
		{"env", map[string]interface{}{"command": "printf x >> \"$OUT\"", "env": map[string]interface{}{"OUT": protected}}, "protected"},
		{"unquoted env", map[string]interface{}{"command": "printf x >> $OUT", "env": map[string]interface{}{"OUT": protected}}, "protected"},
		{"braced env", map[string]interface{}{"command": "printf x >> \"${OUT}\"", "env": map[string]interface{}{"OUT": protected}}, "protected"},
		{"defaulted braced env", map[string]interface{}{"command": "printf x >> \"${OUT:-notes.txt}\"", "env": map[string]interface{}{"OUT": protected}}, "protected"},
		{"alternate braced env", map[string]interface{}{"command": "printf x >> \"${OUT-notes.txt}\"", "env": map[string]interface{}{"OUT": protected}}, "protected"},
		{"nested sh env", map[string]interface{}{"command": `sh -c 'printf x >> "$OUT"'`, "env": map[string]interface{}{"OUT": protected}}, "protected"},
		{"nested bash env", map[string]interface{}{"command": `bash -c 'printf x >> "$OUT"'`, "env": map[string]interface{}{"OUT": protected}}, "protected"},
		{"nested bash flags env", map[string]interface{}{"command": `bash -lc 'printf x >> "${OUT:-notes.txt}"'`, "env": map[string]interface{}{"OUT": protected}}, "protected"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			blob, err := json.Marshal(outageToolPayload{Name: "exec", Args: tc.args, CWD: other})
			if err != nil {
				t.Fatal(err)
			}
			if got := outageToolDecision(strings.NewReader(string(blob)), dataDir); got != tc.want {
				t.Errorf("decision=%q want=%q", got, tc.want)
			}
		})
	}
}

func TestOpenClawOutageApplyPatchTarget(t *testing.T) {
	home := t.TempDir()
	old := outageAccountHome
	outageAccountHome = func() string { return home }
	t.Cleanup(func() { outageAccountHome = old })
	dataDir := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	protected := filepath.Join(dataDir, "config.yaml")
	if err := os.WriteFile(protected, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	patch := "*** Begin Patch\n*** Update File: " + protected + "\n@@\n-old\n+new\n*** End Patch"
	blob, err := json.Marshal(outageToolPayload{Name: "apply_patch", Args: map[string]interface{}{"input": patch}, CWD: home})
	if err != nil {
		t.Fatal(err)
	}
	if got := outageToolDecision(strings.NewReader(string(blob)), dataDir); got != "protected" {
		t.Errorf("apply_patch decision=%q want=protected", got)
	}
}

func TestOpenClawOutageBenignVariants(t *testing.T) {
	home := t.TempDir()
	old := outageAccountHome
	outageAccountHome = func() string { return home }
	t.Cleanup(func() { outageAccountHome = old })
	dataDir := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	for _, tc := range []struct {
		name string
		tool string
		args map[string]interface{}
	}{
		{"date", "exec", map[string]interface{}{"command": "date"}},
		{"pwd", "exec", map[string]interface{}{"command": "pwd"}},
		{"project-write", "exec", map[string]interface{}{"command": "printf x >> notes.txt"}},
		{"home-write", "exec", map[string]interface{}{"command": "printf x >> ~/notes.txt"}},
		{"workdir-date", "exec", map[string]interface{}{"command": "date", "workdir": dataDir}},
		{"write-path", "write", map[string]interface{}{"path": filepath.Join(home, "notes.txt"), "content": "hi"}},
		{"patch", "apply_patch", map[string]interface{}{"input": "*** Begin Patch\n*** Add File: " + filepath.Join(home, "notes.txt") + "\n+hi\n*** End Patch"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			blob, err := json.Marshal(outageToolPayload{Name: tc.tool, Args: tc.args, CWD: other})
			if err != nil {
				t.Fatal(err)
			}
			if got := outageToolDecision(strings.NewReader(string(blob)), dataDir); got != "open" {
				t.Errorf("decision=%q want=open", got)
			}
		})
	}
}

func TestOpenClawOutageEnvLinkedTarget(t *testing.T) {
	home := t.TempDir()
	old := outageAccountHome
	outageAccountHome = func() string { return home }
	t.Cleanup(func() { outageAccountHome = old })
	dataDir := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	protected := filepath.Join(dataDir, "config.yaml")
	if err := os.WriteFile(protected, []byte("guardrail: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(home, "state-link")
	if err := os.Symlink(protected, alias); err != nil {
		t.Fatal(err)
	}
	blob, err := json.Marshal(outageToolPayload{Name: "exec", Args: map[string]interface{}{"command": "printf x >> \"$OUT\"", "env": map[string]interface{}{"OUT": alias}}, CWD: home})
	if err != nil {
		t.Fatal(err)
	}
	if got := outageToolDecision(strings.NewReader(string(blob)), dataDir); got != "protected" {
		t.Errorf("known env link decision=%q want=protected", got)
	}
}

func TestOpenClawOutageWorkdirFalseBlock(t *testing.T) {
	home := t.TempDir()
	old := outageAccountHome
	outageAccountHome = func() string { return home }
	t.Cleanup(func() { outageAccountHome = old })
	dataDir := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "config.yaml"), []byte("guardrail: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	blob, err := json.Marshal(outageToolPayload{Name: "exec", Args: map[string]interface{}{"command": "printf x >> config.yaml", "workdir": other}, CWD: dataDir})
	if err != nil {
		t.Fatal(err)
	}
	if got := outageToolDecision(strings.NewReader(string(blob)), dataDir); got != "open" {
		t.Errorf("ordinary workdir write decision=%q want=open", got)
	}
}

func TestOpenClawOutageKnownEnvironmentShellVariants(t *testing.T) {
	home := t.TempDir()
	prior := outageAccountHome
	outageAccountHome = func() string { return home }
	t.Cleanup(func() { outageAccountHome = prior })
	root := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	protected := filepath.Join(root, "config.yaml")
	if err := os.WriteFile(protected, []byte("guardrail: {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ordinary := t.TempDir()
	cases := []struct{ name, command, want string }{
		{"nested direct control", `sh -c 'printf x >> "$OUT"'`, "protected"},
		{"nested dynamic unused arg", `sh -c 'printf x >> "$OUT"' "$UNUSED"`, "protected"},
		{"nested dynamic unused arg with dash", `sh -c 'printf x >> "$OUT"' -- "$UNUSED"`, "protected"},
		{"env wrapped nested shell", `env sh -c 'printf x >> "$OUT"'`, "protected"},
		{"command wrapped nested shell", `command sh -c 'printf x >> "$OUT"'`, "protected"},
		{"exec wrapped nested shell", `exec sh -c 'printf x >> "$OUT"'`, "protected"},
		{"grouped nested shell", `{ sh -c 'printf x >> "$OUT"'; }`, "protected"},
		{"subshell nested shell", `(sh -c 'printf x >> "$OUT"')`, "protected"},
		{"conditional nested shell", `if true; then sh -c 'printf x >> "$OUT"'; fi`, "protected"},
		{"and-list nested shell", `true && sh -c 'printf x >> "$OUT"'`, "protected"},
		{"nested unrelated local assignment", `sh -c 'OTHER=notes.txt; printf x >> "$OUT"'`, "protected"},
		{"direct local override", `OUT=notes.txt; printf x >> "$OUT"`, "open"},
		{"nested local override", `sh -c 'OUT=notes.txt; printf x >> "$OUT"'`, "open"},
		{"nested environment assignment override", `OUT=notes.txt sh -c 'printf x >> "$OUT"'`, "open"},
		{"argument expansion precedes invocation assignment", `OUT=notes.txt cp notes "$OUT"`, "protected"},
		{"redirect expansion precedes invocation assignment", `OUT=notes.txt printf x >> "$OUT"`, "protected"},
		{"unused protected env", `printf x >> notes.txt`, "open"},
		{"known copy destination", `cp notes "$OUT"`, "protected"},
		{"known copy source", `cp "$OUT" notes`, "open"},
		{"nested copy destination", `env sh -c 'cp notes "$OUT"'`, "protected"},
		{"env local override", `env OUT=notes.txt sh -c 'printf x >> "$OUT"'`, "open"},
		{"env unset", `env -u OUT sh -c 'printf x >> "$OUT"'`, "open"},
		{"command env override", `command env OUT=notes.txt sh -c 'printf x >> "$OUT"'`, "open"},
		{"invocation value does not persist", `OUT=notes.txt sh -c 'date'; printf x >> "$OUT"`, "protected"},
		{"env value does not persist", `env OUT=notes.txt sh -c 'date'; printf x >> "$OUT"`, "protected"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			blob, err := json.Marshal(outageToolPayload{Name: "exec", Args: map[string]interface{}{
				"command": tc.command,
				"env":     map[string]interface{}{"OUT": protected},
			}, CWD: ordinary})
			if err != nil {
				t.Fatal(err)
			}
			got := outageToolDecision(strings.NewReader(string(blob)), root)
			if got != tc.want {
				t.Errorf("decision=%q want=%q for %s", got, tc.want, tc.command)
			}
		})
	}
}

func TestOpenClawOutageKnownEnvironmentCompoundAndChildValues(t *testing.T) {
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
	linked := filepath.Join(ordinary, "config-link")
	if err := os.Symlink(protected, linked); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, command, initial, want string
	}{
		{"protected direct assignment", `OUT="$PROT"; printf x >> "$OUT"`, "notes.txt", "protected"},
		{"protected and assignment", `OUT="$PROT" && true; printf x >> "$OUT"`, "notes.txt", "protected"},
		{"protected or assignment", `OUT="$PROT" || true; printf x >> "$OUT"`, "notes.txt", "protected"},
		{"protected if assignment", `if true; then OUT="$PROT"; fi; printf x >> "$OUT"`, "notes.txt", "protected"},
		{"protected for assignment", `for x in 1; do OUT="$PROT"; done; printf x >> "$OUT"`, "notes.txt", "protected"},
		{"protected quoted for value", `TARGET=notes.txt; for x in "$OUT"; do TARGET="$x"; done; printf x >> "$TARGET"`, protected, "protected"},
		{"protected unquoted for value", `TARGET=notes.txt; for x in $OUT; do TARGET="$x"; done; printf x >> "$TARGET"`, protected, "protected"},
		{"protected else assignment", `if false; then OUT=notes.txt; else OUT="$PROT"; fi; printf x >> "$OUT"`, "notes.txt", "protected"},
		{"protected possible assignment", `if test -f marker; then OUT="$PROT"; fi; printf x >> "$OUT"`, "notes.txt", "protected"},
		{"protected case assignment", `case word in word) OUT="$PROT";; *) OUT=notes.txt;; esac; printf x >> "$OUT"`, "notes.txt", "protected"},
		{"ordinary direct assignment", `OUT=notes.txt; printf x >> "$OUT"`, protected, "open"},
		{"ordinary and assignment", `OUT=notes.txt && true; printf x >> "$OUT"`, protected, "open"},
		{"ordinary or assignment", `OUT=notes.txt || true; printf x >> "$OUT"`, protected, "open"},
		{"ordinary and replacement", `OUT="$PROT" && OUT=notes.txt; printf x >> "$OUT"`, protected, "open"},
		{"ordinary or skip", `OUT=notes.txt || OUT="$PROT"; printf x >> "$OUT"`, protected, "open"},
		{"ordinary if assignment", `if true; then OUT=notes.txt; fi; printf x >> "$OUT"`, protected, "open"},
		{"ordinary assignment condition", `if OUT=notes.txt; then true; else OUT="$PROT"; fi; printf x >> "$OUT"`, protected, "open"},
		{"ordinary for assignment", `for x in 1; do OUT=notes.txt; done; printf x >> "$OUT"`, protected, "open"},
		{"ordinary repeated for assignment", `for x in 1 2; do OUT=notes.txt; done; printf x >> "$OUT"`, protected, "open"},
		{"ordinary quoted for value", `for x in "$OUT"; do TARGET="$x"; done; printf x >> "$TARGET"`, "notes.txt", "open"},
		{"ordinary unquoted for value", `for x in $OUT; do TARGET="$x"; done; printf x >> "$TARGET"`, "notes.txt", "open"},
		{"ordinary overridden home in for", `for x in "$HOME"; do OUT="$x/config.yaml"; done; printf x >> "$OUT"`, protected, "open"},
		{"ordinary empty for", `for x in; do OUT="$PROT"; done; printf x >> "$OUT"`, "notes.txt", "open"},
		{"ordinary skipped and branch", `false && OUT="$PROT"; printf x >> "$OUT"`, "notes.txt", "open"},
		{"ordinary skipped or branch", `true || OUT="$PROT"; printf x >> "$OUT"`, "notes.txt", "open"},
		{"ordinary false if branch", `if false; then OUT="$PROT"; fi; printf x >> "$OUT"`, "notes.txt", "open"},
		{"ordinary else assignment", `if false; then OUT="$PROT"; else OUT=notes.txt; fi; printf x >> "$OUT"`, protected, "open"},
		{"ordinary both possible assignments", `if test -f marker; then OUT=notes.txt; else OUT=other.txt; fi; printf x >> "$OUT"`, protected, "open"},
		{"ordinary case wildcard", `case word in *) OUT=notes.txt;; esac; printf x >> "$OUT"`, protected, "open"},
		{"ordinary case exact", `case word in word) OUT=notes.txt;; *) OUT="$PROT";; esac; printf x >> "$OUT"`, protected, "open"},
		{"protected known program", `"$COPY" notes "$OUT"`, protected, "protected"},
		{"ordinary known program", `"$COPY" notes "$OUT"`, "notes.txt", "open"},
		{"protected local program", `COPY=cp; "$COPY" notes "$OUT"`, protected, "protected"},
		{"ordinary local program", `COPY=cp; "$COPY" notes "$OUT"`, "notes.txt", "open"},
		{"protected shell positional", `sh -c 'printf x >> "$1"' _ "$OUT"`, protected, "protected"},
		{"ordinary shell positional", `sh -c 'printf x >> "$1"' _ "$OUT"`, "notes.txt", "open"},
		{"protected shell positional zero", `sh -c 'printf x >> "$0"' "$OUT"`, protected, "protected"},
		{"ordinary shell positional zero", `sh -c 'printf x >> "$0"' "$OUT"`, "notes.txt", "open"},
		{"protected shell positional two", `sh -c 'printf x >> "$2"' _ skip "$OUT"`, protected, "protected"},
		{"ordinary shell positional two", `sh -c 'printf x >> "$2"' _ skip "$OUT"`, "notes.txt", "open"},
		{"protected wrapped positional", `env sh -c 'printf x >> "$1"' _ "$OUT"`, protected, "protected"},
		{"ordinary wrapped positional", `env sh -c 'printf x >> "$1"' _ "$OUT"`, "notes.txt", "open"},
		{"protected known shell", `"$SHELL" -c 'printf x >> "$OUT"'`, protected, "protected"},
		{"ordinary known shell", `"$SHELL" -c 'printf x >> "$OUT"'`, "notes.txt", "open"},
		{"protected known shell body", `sh -c "$CMD"`, protected, "protected"},
		{"ordinary known shell body", `sh -c "$CMD"`, "notes.txt", "open"},
		{"protected local shell body", `CMD='printf x >> "$OUT"'; sh -c "$CMD"`, protected, "protected"},
		{"ordinary local shell body", `CMD='printf x >> "$OUT"'; sh -c "$CMD"`, "notes.txt", "open"},
		{"protected known eval body", `eval "$CMD"`, protected, "protected"},
		{"ordinary known eval body", `eval "$CMD"`, "notes.txt", "open"},
		{"protected eval assignment", `CMD='OUT="$PROT"'; eval "$CMD"; printf x >> "$OUT"`, "notes.txt", "protected"},
		{"ordinary eval assignment", `CMD='OUT=notes.txt'; eval "$CMD"; printf x >> "$OUT"`, protected, "open"},
		{"protected known link", `printf x >> "$OUT"`, linked, "protected"},
		{"protected nested known link", `sh -c 'printf x >> "$OUT"'`, linked, "protected"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			blob, err := json.Marshal(outageToolPayload{Name: "exec", Args: map[string]interface{}{
				"command": tc.command,
				"env":     map[string]interface{}{"OUT": tc.initial, "TARGET": protected, "PROT": protected, "HOME": ordinary, "COPY": "cp", "SHELL": "sh", "CMD": `printf x >> "$OUT"`},
			}, CWD: ordinary})
			if err != nil {
				t.Fatal(err)
			}
			if got := outageToolDecision(strings.NewReader(string(blob)), root); got != tc.want {
				t.Errorf("decision=%q want=%q for %s", got, tc.want, tc.command)
			}
		})
	}
}
