// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rel-1-0-6:GAP-0431: each declined shape has a direct proof row. Some
// guards are masked by other readers in four-cell decisions, so the proof
// boundary is checked here as well as in the gateway rows.
func TestGAP0431ClientProofGuards(t *testing.T) {
	// The proof needs an absolute working directory, as every hook reports;
	// /tmp/project is not one on Windows.
	root := t.TempDir()
	cwd, home := filepath.Join(root, "project"), filepath.Join(root, "home")
	var saturated strings.Builder
	saturated.WriteString("f=a.txt; ")
	for i := 0; i < 10; i++ {
		fmt.Fprintf(&saturated, "if [ -z \"$K%d\" ]; then V%d=one; fi; ", i, i)
	}
	saturated.WriteString(`echo m >> "$f"`)
	rows := []struct {
		name, command string
		want          bool
	}{
		{"ordinary-target", `f=keylink; f=a.txt; echo m >> "$f"`, true},
		{"M4-home-rebound", `HOME=/tmp/project; f=a.txt; echo m >> "$f"`, false},
		{"M5-tilde", `f=~+/keylink; f=a.txt; echo m >> "$f"`, false},
		{"M6-loop-body", `for x in a.txt; do echo ok; done; f=a.txt; echo m >> "$f"`, false},
		{"M8-nested-target", `f=a.txt; (echo m >> "$f")`, false},
		{"M11-unquoted-install", `f=a.txt; install b.txt $f`, false},
		{"M11r-unquoted-rsync", `f=a.txt; rsync b.txt $f`, false},
		{"M12-cd", `cd /tmp; f=a.txt; echo m >> "$f"`, false},
		{"M13-printf-v", `f=a.txt; printf -v f %s b.txt; echo m >> "$f"`, false},
		{"M14-builtin", `f=a.txt; builtin true; echo m >> "$f"`, false},
		{"M16-no-parameter", `f=a.txt; echo m >> a.txt`, false},
		{"M17-saturated", saturated.String(), false},
		{"M18-glob", `f='a*.txt'; echo m >> "$f"`, false},
		{"printf-attached", `f=a.txt; printf -vf %s keylink; echo m >> "$f"`, false},
		{"printf-dynamic", `f=a.txt; opt=-vf; printf "$opt" %s keylink; echo m >> "$f"`, false},
		{"printf-dynamic-own-redirect", `f=keylink; f=a.txt; printf "$fmt" >> "$f"`, true},
		{"printf-dynamic-later-redirect", `f=keylink; f=a.txt; printf "$fmt" >> "$f"; echo m >> "$f"`, false},
		{"printf-dynamic-binary", `f=keylink; f=a.txt; printf "$fmt" >> "$f" && echo m >> "$f"`, false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			got := actionClientProvedSafeVariableTargets(row.command, cwd, home)
			t.Logf("HP7GUARDROW %s | %t | want %t", row.name, got, row.want)
			if got != row.want {
				t.Errorf("proof %t, want %t for %q", got, row.want, row.command)
			}
		})
	}
}

func TestGAP0431LoopCopyProofGuards(t *testing.T) {
	root := t.TempDir()
	home, cwd := filepath.Join(root, "home"), filepath.Join(root, "project")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte("# decoy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "a.txt"), []byte("a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "authorized_keys"), []byte("a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		name, command string
		want          bool
	}{
		{"loop-name-protected", `for f in authorized_keys; do cp a.txt "$HOME/.ssh/$f"; done`, true},
		{"no-op-before-loop", `true; for f in authorized_keys; do cp -f a.txt "$HOME/.ssh/$f"; done`, true},
		{"no-op-after-copy", `for f in authorized_keys; do cp a.txt "$HOME/.ssh/$f"; echo ok; done`, true},
		{"changed-directory", `cd /tmp; for f in authorized_keys; do cp a.txt "$HOME/.ssh/$f"; done`, false},
		{"path-qualified-prefix", `./echo; for f in authorized_keys; do cp a.txt "$HOME/.ssh/$f"; done`, false},
		{"no-clobber", `for f in authorized_keys; do cp -n a.txt "$HOME/.ssh/$f"; done`, true},
		{"L5-no-loop-name", `for f in authorized_keys; do cp a.txt ~/.ssh/authorized_keys; done`, false},
		{"L6-quoted-copy-source", `for f in authorized_keys; do cp "$src" "$HOME/.ssh/$f"; done`, true},
		{"L6-assigned-copy-source", `src=a.txt; for f in authorized_keys; do cp "$src" "$HOME/.ssh/$f"; done`, true},
		// What a source operand holds says nothing about the program the name cp
		// reaches, so a quoted dynamic source never clears the destination
		// (rel-1-0-6:GAP-0880, GAP-0885).
		{"L6-empty-copy-source", `src=; for f in authorized_keys; do cp "$src" "$HOME/.ssh/$f"; done`, true},
		{"L6-empty-unset-default", `src=; for f in authorized_keys; do cp "${src-a.txt}" "$HOME/.ssh/$f"; done`, true},
		{"L6-empty-null-alternative", `src=; for f in authorized_keys; do cp "${src:+a.txt}" "$HOME/.ssh/$f"; done`, true},
		{"L6-empty-required", `src=; for f in authorized_keys; do cp "${src?missing}" "$HOME/.ssh/$f"; done`, true},
		{"L6-empty-substring", `src=; for f in authorized_keys; do cp "${src:0:1}" "$HOME/.ssh/$f"; done`, true},
		{"L6-loop-source-overwrites-empty", `src=; for src in authorized_keys; do cp "$src" "$HOME/.ssh/$src"; done`, true},
		{"L6-dynamic-move-source", `for f in authorized_keys; do mv "$src" "$HOME/.ssh/$f"; done`, true},
		{"L6-option-source", `src=-n; for f in authorized_keys; do cp "$src" "$HOME/.ssh/$f"; done`, true},
		{"L6-option-after-separator", `src=-n; for f in authorized_keys; do cp -- "$src" "$HOME/.ssh/$f"; done`, true},
		{"L6-joined-option-separator", `src=-n; for f in authorized_keys; do cp "-"'-' "$src" "$HOME/.ssh/$f"; done`, true},
		{"L6-special-source-index", `OPTIND=; for f in authorized_keys; do cp "$OPTIND" "$HOME/.ssh/$f"; done`, true},
		{"L6-special-source-seconds", `SECONDS=; for f in authorized_keys; do cp "$SECONDS" "$HOME/.ssh/$f"; done`, true},
		{"L6-empty-reply", `REPLY=; for f in authorized_keys; do cp "$REPLY" "$HOME/.ssh/$f"; done`, true},
		{"L6-empty-option-argument", `OPTARG=; for f in authorized_keys; do cp "$OPTARG" "$HOME/.ssh/$f"; done`, true},
		{"L6-literal-empty-source", `for f in authorized_keys; do cp '' "$HOME/.ssh/$f"; done`, true},
		{"L6-literal-option-source", `for f in authorized_keys; do cp -n "$HOME/.ssh/$f"; done`, true},
		{"L6-missing-source", `for f in authorized_keys; do cp "$HOME/.ssh/$f"; done`, true},
		{"L6-glob-source", `for f in authorized_keys; do cp *.nomatch "$HOME/.ssh/$f"; done`, true},
		{"L6-literal-empty-source-ordinary-destination", `for f in ordinary; do cp '' "$f"; done`, false},
		{"cp-recursive", `for f in authorized_keys; do cp -r a.txt "$HOME/.ssh/$f"; done`, true},
		{"cp-recursive-capital", `for f in authorized_keys; do cp -R a.txt "$HOME/.ssh/$f"; done`, true},
		{"cp-archive-force", `for f in authorized_keys; do cp -af a.txt "$HOME/.ssh/$f"; done`, true},
		{"cp-target-directory-short", `for f in .ssh; do cp -t "$HOME/$f" a.txt; done`, true},
		{"cp-target-directory-joined", `for f in .ssh; do cp -t"$HOME/$f" a.txt; done`, true},
		{"cp-target-directory-grouped", `for f in .ssh; do cp -rt "$HOME/$f" a.txt; done`, true},
		{"cp-target-directory-long", `for f in .ssh; do cp --target-directory "$HOME/$f" a.txt; done`, true},
		{"cp-target-directory-attached", `for f in .ssh; do cp --target-directory="$HOME/$f" a.txt; done`, true},
		{"cp-target-directory-quoted", `for f in .ssh; do cp "--target-directory=$HOME/$f" a.txt; done`, true},
		{"cp-target-directory-ordinary", `for f in ordinary; do cp -t "$f" a.txt; done`, false},
		{"cp-target-directory-protected-source", `for f in authorized_keys; do cp -t out "$HOME/.ssh/$f"; done`, false},
		{"mv-literal-empty-source", `for f in authorized_keys; do mv '' "$HOME/.ssh/$f"; done`, true},
		{"mv-named-source", `for f in authorized_keys; do mv a.txt "$HOME/.ssh/$f"; done`, true},
		{"mv-option-source", `for f in authorized_keys; do mv -f "$src" "$HOME/.ssh/$f"; done`, true},
		{"install-dynamic-source", `for f in authorized_keys; do install -m 600 "$src" "$HOME/.ssh/$f"; done`, true},
		{"ln-dynamic-source", `for f in authorized_keys; do ln -sf "$src" "$HOME/.ssh/$f"; done`, true},
		{"tee-operand", `for f in authorized_keys; do tee -a "$HOME/.ssh/$f"; done`, true},
		{"mv-ordinary-destination", `for f in ordinary; do mv "$src" "$f"; done`, false},
		{"install-ordinary-destination", `for f in ordinary; do install -m 600 "$src" "$f"; done`, false},
		{"tee-ordinary-destination", `for f in ordinary; do tee "$f"; done`, false},
		{"mv-empty-list", `for f in; do mv "$src" "$HOME/.ssh/$f"; done`, false},
		{"L6-two-loops-protected-second", `for f in ordinary; do cp a.txt "$f"; done; for f in authorized_keys; do cp a.txt "$HOME/.ssh/$f"; done`, true},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			got := actionClientLoopCopyDestinationProtected(row.command, cwd, home)
			t.Logf("HP7GUARDROW %s | %t | want %t", row.name, got, row.want)
			if got != row.want {
				t.Errorf("proof %t, want %t for %q", got, row.want, row.command)
			}
		})
	}
	t.Run("startup-env-empty-assignment", func(t *testing.T) {
		t.Setenv("BASH_ENV", filepath.Join(root, "startup.sh"))
		command := `src=; for f in authorized_keys; do cp "$src" "$HOME/.ssh/$f"; done`
		if !actionClientLoopCopyDestinationProtected(command, cwd, home) {
			t.Fatal("startup source proof missed protected destination")
		}
	})
}

func TestGAP0428PrintfAttachedValueTracking(t *testing.T) {
	for _, command := range []string{
		`printf -vf %s keylink`,
		`printf -v"f" %s keylink`,
		`printf -v f %s keylink`,
		`printf -vf 'key\x6cink'`,
		`printf -v f 'key\x6cink'`,
		`printf -vf 'key\x6cink%s' ''`,
		`printf -v f 'key\x6cink%s' ''`,
		`printf -vf 'key\x6cink%s'`,
		`printf -v f 'key\x6cink%s'`,
		`printf -vf 'key\154ink'`,
		`printf -v f 'key\u006cink'`,
	} {
		t.Run(command, func(t *testing.T) {
			file, ok := parseShell(command)
			if !ok || len(file.Stmts) != 1 {
				t.Fatalf("parse %q", command)
			}
			values := actionValues{"f": "a.txt"}
			actionUpdateValuesAs(file.Stmts[0], values, "/tmp/project", "/tmp/home", true)
			if got := values["f"]; got != "keylink" {
				t.Errorf("tracked value %q, want keylink", got)
			}
			actionForgetValues(file.Stmts[0], values, "/tmp/project", "/tmp/home")
			if _, kept := values["f"]; kept {
				t.Error("bound name still has a known value after a nested printf")
			}
		})
	}
}
