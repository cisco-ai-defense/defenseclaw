// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/testenv/hlinkmatrix"
)

// GAP-0377: the replace-verb proof reads the sed script. Replace-only
// scripts keep it; a script that writes, runs, reads a file, is unknown or
// is not read in full does not.
func TestSedScriptReplaceOnly(t *testing.T) {
	for _, tc := range []struct {
		id, script string
		want       bool
	}{
		{"substitute", `s/x/y/`, true},
		{"substitute-flags", `s/x/y/gI`, true},
		{"substitute-number", `s/x/y/2p`, true},
		{"substitute-delimiter", `s|a/b|c/d|g`, true},
		{"substitute-escaped-delimiter", `s/a\/b/c/`, true},
		{"transliterate", `y/abc/xyz/`, true},
		{"delete-line", `3d`, true},
		{"range", `1,3p`, true},
		{"regex-address-not", `/x/!d`, true},
		{"step-address", `0~2d`, true},
		{"last-line", `$d`, true},
		{"relative-range", `/x/,+2d`, true},
		{"block", `/x/{p;d}`, true},
		{"nested-block", `1{/a/{s/a/b/}}`, true},
		{"hold-space", `1h;2G;$x`, true},
		{"append-text", "1a text\n2d", true},
		{"branch", `b end`, true},
		{"quit-code", `q5`, true},
		{"comment", "# note\np", true},
		{"two-commands-newline", "s/a/b/\ns/c/d/", true},
		{"empty", ``, true},
		{"w-command", `w out`, false},
		{"W-command", `W out`, false},
		{"w-flag", `s/x/y/w out`, false},
		{"w-flag-after-g", `s/x/y/gw out`, false},
		{"e-command", `e touch f`, false},
		{"e-flag", `s/x/y/e`, false},
		{"r-command", `r in`, false},
		{"R-command", `R in`, false},
		{"v-command", `v 4.2`, false},
		{"label-definition", `:a`, false},
		{"unknown-command", `k`, false},
		{"unbalanced-open", `/x/{p`, false},
		{"unbalanced-close", `p}`, false},
		{"unterminated-substitute", `s/x/y`, false},
		{"unterminated-regex-address", `/x p`, false},
		{"junk-after-command", `p x`, false},
		{"after-block-w", `/x/{p;w out}`, false},
		{"w-after-text-line", "a one\nw out", false},
		{"substitute-then-w", "s/a/b/;w out", false},
	} {
		t.Run(tc.id, func(t *testing.T) {
			if got := sedScriptReplaceOnly(tc.script); got != tc.want {
				t.Errorf("sedScriptReplaceOnly(%q) = %t, want %t", tc.script, got, tc.want)
			}
		})
	}
}

// The proof against GNU sed itself: for every script of the sed command
// alphabet over two names of the corpus, the proof holds only for a script
// that leaves the decoy keys inode alone when sed runs it, and the proof's
// own reader (sedScriptReplaceOnly) agrees. Rows are the corpus' sed -i rows
// with the script swapped in code.
func TestReplaceVerbProofNeverHoldsForAScriptThatTouchesTheKeys(t *testing.T) {
	sed := "/usr/bin/sed"
	if out, err := exec.Command(sed, "--version").Output(); err != nil || !strings.Contains(string(out), "GNU sed") {
		t.Skip("GNU sed not available")
	}
	f := newShellWordFixture(t)
	letters := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	held, refused := 0, 0
	for _, target := range []string{f.keys, f.names.KeyHard} {
		for _, form := range []string{"cmd", "sflag"} {
			for _, l := range letters {
				script := string(l) + " " + target
				if form == "sflag" {
					script = "s/x/y/" + string(l) + " " + target
				}
				command := "sed -i '" + script + "' a.txt"
				proof := replaceVerbSafe(command, f.project, f.home)
				if !proof {
					refused++
					continue
				}
				held++
				// A proof holds: sed must leave the keys alone.
				before, _ := os.ReadFile(f.keys)
				info, _ := os.Stat(f.keys)
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				cmd := exec.CommandContext(ctx, "/usr/bin/bash", "-c", command)
				cmd.Dir = f.project
				cmd.Env = []string{"HOME=" + f.home, "PATH=/usr/bin:/bin", "LANG=C"}
				_ = cmd.Run()
				cancel()
				after, _ := os.ReadFile(f.keys)
				afterInfo, _ := os.Stat(f.keys)
				if !bytes.Equal(before, after) || info.Mode() != afterInfo.Mode() || !info.ModTime().Equal(afterInfo.ModTime()) {
					t.Errorf("proof held for a script that changed the keys inode: form %s letter %c target %s", form, l, filepath.Base(target))
				}
			}
		}
	}
	t.Logf("proof held %d, refused %d", held, refused)
	if held == 0 || refused == 0 {
		t.Errorf("the alphabet must cover both: held %d refused %d", held, refused)
	}
}

// The glob words of the resolver against real bash. Every pattern in the
// modeled subset gives bash's own answer under each option the resolver
// models; every other form is uncertain. Names and patterns are generated
// from the corpus names and the glob alphabet.
func TestResolverMatchesRealBashOnTheModeledSubset(t *testing.T) {
	bash := "/usr/bin/bash"
	if _, err := os.Stat(bash); err != nil {
		t.Skip("bash not available")
	}
	f := newShellWordFixture(t)
	for _, name := range []string{"File1", "file2", "file10", ".hidden1", "a1.txt", "b2.txt", "A3.TXT", "note", "dir"} {
		if err := os.WriteFile(filepath.Join(f.project, name), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	stem := f.names.HardBracket[:strings.IndexByte(f.names.HardBracket, '[')]
	modeled := []string{
		"*", "?", "file*", "*1", "file?", "?ile[0-9]", "file[12]", "[a-b]1.txt", "file[1-9]*", "*.txt", "*.TXT", ".hid*",
		".*", "a?.txt", "[ab][12].txt", "nomatch*", "nomatch", stem + "[1]", stem + "?1?", f.names.NoMatchHard, "FILE*", "FILE[12]", "dir/*", "nodir/*",
		"[0-9]*", "[!x]", // the last one is NOT modeled
	}
	options := []struct {
		id    string
		shopt string
		opts  shellGlobOptions
	}{
		{"none", "", shellGlobOptions{}},
		{"dotglob", "shopt -s dotglob; ", shellGlobOptions{dotGlob: true}},
		{"nocaseglob", "shopt -s nocaseglob; ", shellGlobOptions{noCaseGlob: true}},
		{"nullglob", "shopt -s nullglob; ", shellGlobOptions{nullGlob: true}},
	}
	for _, option := range options {
		for _, pattern := range modeled {
			t.Run(option.id+"/"+pattern, func(t *testing.T) {
				word := shellWordOf(t, "touch "+pattern, 1)
				got := resolveShellWord(word, f.values, f.project, option.opts, nil)
				if !resolverPatternModeled(pattern) {
					if got.uncertain == "" {
						t.Fatalf("a form outside the subset is settled: %q", got.candidates)
					}
					return
				}
				if got.uncertain != "" {
					t.Fatalf("uncertain %q", got.uncertain)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, bash, "-c", option.shopt+`printf '%s\n' `+pattern)
				cmd.Dir = f.project
				cmd.Env = []string{"HOME=" + f.home, "PATH=/usr/bin:/bin", "LANG=C"}
				out, err := cmd.Output()
				if err != nil {
					t.Fatal(err)
				}
				var want []string
				for _, line := range strings.Split(strings.TrimSuffix(string(out), "\n"), "\n") {
					if line == "" {
						continue
					}
					// The literal fallback names a path that can only be
					// written when its directory exists (here "dir" is a
					// file, "nodir" is missing): the resolver names nothing.
					if _, err := os.Stat(filepath.Dir(filepath.Join(f.project, line))); err != nil {
						continue
					}
					if info, _ := os.Stat(filepath.Dir(filepath.Join(f.project, line))); info != nil && !info.IsDir() {
						continue
					}
					want = append(want, filepath.Join(f.project, line))
				}
				have := append([]string(nil), got.candidates...)
				sort.Strings(have)
				sort.Strings(want)
				if strings.Join(have, "\n") != strings.Join(want, "\n") {
					t.Errorf("resolver %q, bash %q", have, want)
				}
			})
		}
	}
}

// Forms outside the subset, an option the resolver does not model and any
// command that may change the options are uncertain, from the reviewer's
// class variants (case ids only).
func TestResolverUncertainOutsideTheModeledSubset(t *testing.T) {
	f := newShellWordFixture(t)
	for _, v := range hlinkmatrix.Rev2ClassVariants(f.names) {
		if !strings.HasPrefix(v.ID, "HL-nomatch-hard-unquoted-touch/L3/") {
			continue
		}
		forms := strings.SplitN(v.Transform, "+", 2)[0]
		opt := strings.SplitN(v.Transform, "+", 2)[1]
		wantUncertain := false
		switch forms {
		case "cls-bang", "cls-range-bang", "cls-caret", "cls-posix", "star2", "ext":
			wantUncertain = true
		}
		if strings.Contains(opt, "globignore") || strings.Contains(opt, "extglob") || strings.Contains(opt, "globstar") ||
			strings.HasPrefix(opt, "shopt-") {
			wantUncertain = true
		}
		t.Run(v.ID, func(t *testing.T) {
			for name, value := range v.Env {
				t.Setenv(name, value)
			}
			if got := NewTargetMemo().UncertainWriteReason(v.Command, f.project, f.home, nil); (got != "") != wantUncertain {
				t.Errorf("UncertainWriteReason = %q, uncertain wanted %t", got, wantUncertain)
			}
		})
	}
}

// Every row of the corpus that the matrix marks UNCERTAIN reports a reason;
// every row it proves does not.
func TestUncertainWriteReasonOnTheCorpus(t *testing.T) {
	f := newShellWordFixture(t)
	for _, row := range hlinkmatrix.UncertainRows() {
		if reason := NewTargetMemo().UncertainWriteReason(row.Command, f.project, f.home, nil); reason == "" {
			t.Errorf("%s: uncertain operand has no reason", row.ID)
		}
	}
	for _, row := range hlinkmatrix.Rows(f.names) {
		if reason := NewTargetMemo().UncertainWriteReason(row.Command, f.project, f.home, nil); reason != "" {
			t.Errorf("%s: proven row reports %q", row.ID, reason)
		}
	}
}

// The real-bash oracle over the reviewer's variants: truth is whether the
// decoy keys inode changed when bash ran the row. A row that changes it must
// be a protected-target decision or an UNCERTAIN operand; never a plain
// allow. The class and extra sets run in CI; the full set (26k rows) runs
// with HLINK_ORACLE_FULL=1.
func TestHLinkRealBashOracle(t *testing.T) {
	bash := "/usr/bin/bash"
	if _, err := os.Stat(bash); err != nil {
		t.Skip("bash not available")
	}
	n := hlinkmatrix.DefaultNames()
	variants := append(hlinkmatrix.Rev2ClassVariants(n), hlinkmatrix.Rev2ExtraVariants(n)...)
	if os.Getenv("HLINK_ORACLE_FULL") == "1" {
		variants = append(variants, hlinkmatrix.Rev2Variants(n)...)
	}
	missed := map[string][]string{}
	for _, v := range variants {
		root, err := os.MkdirTemp("", "hlink-oracle-")
		if err != nil {
			t.Fatal(err)
		}
		home := filepath.Join(root, "home")
		project := filepath.Join(home, "project")
		keys := filepath.Join(home, ".ssh", "authorized_keys")
		for _, dir := range []string{filepath.Dir(keys), project} {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(keys, []byte("# decoy\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		old := time.Now().Add(-time.Hour)
		_ = os.Chtimes(keys, old, old)
		hlinkmatrix.Rev2Setup(t, project, keys, n, v.Layout)
		before, _ := os.Stat(keys)
		beforeData, _ := os.ReadFile(keys)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		cmd := exec.CommandContext(ctx, bash, "-c", v.Command)
		cmd.Dir = project
		cmd.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin", "LANG=C", "TMPDIR=" + root}
		for k, val := range v.Env {
			cmd.Env = append(cmd.Env, k+"="+val)
		}
		cmd.Stdin = strings.NewReader("")
		_ = cmd.Run()
		cancel()
		after, _ := os.Stat(keys)
		afterData, _ := os.ReadFile(keys)
		touched := !bytes.Equal(beforeData, afterData) || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime())
		if touched {
			t.Setenv("HOME", home)
			for k, val := range v.Env {
				t.Setenv(k, val)
			}
			startup := CurrentShellStartup()
			decision := ActionCommandDecision(v.Command, project, home) != ""
			uncertain := NewTargetMemo().UncertainWriteReason(v.Command, project, home, &startup) != ""
			if !decision && !uncertain {
				missed[v.Layout+"/"+v.Transform] = append(missed[v.Layout+"/"+v.Transform], v.Base.ID)
			}
			for k := range v.Env {
				os.Unsetenv(k)
			}
		}
		os.RemoveAll(root)
	}
	var keysList []string
	for k := range missed {
		keysList = append(keysList, k)
	}
	sort.Strings(keysList)
	for _, k := range keysList {
		ids := missed[k]
		if len(ids) > 6 {
			ids = ids[:6]
		}
		t.Errorf("bash changed the keys inode with neither a protected-target decision nor an uncertain operand: %s: %d rows, e.g. %s", k, len(missed[k]), strings.Join(ids, ","))
	}
	t.Logf("variants=%d", len(variants))
}

// The startup header carries the agent's glob options, and a call that may
// change them makes the glob words of the call uncertain.
func TestShellGlobOptionsForCall(t *testing.T) {
	startup := ShellStartup{glob: shellGlobOptions{dotGlob: true, noCaseGlob: true, globIgnore: true}}
	got, ok := DecodeShellStartup(startup.Encode())
	if !ok || got.glob != startup.glob {
		t.Fatalf("round trip: %+v ok=%t", got.glob, ok)
	}
	if old, ok := DecodeShellStartup("f=0;o=0;fn="); !ok || old.glob != (shellGlobOptions{}) {
		t.Errorf("a header without g= decodes to no options: %+v ok=%t", old.glob, ok)
	}
	if _, ok := DecodeShellStartup("f=0;o=0;fn=;g=q"); ok {
		t.Error("an unknown option letter decoded")
	}
	if !UnknownShellStartup().glob.unmodeled() {
		t.Error("an unreadable header must leave glob words uncertain")
	}
	if o := shellGlobOptionsForCall("touch a*", ShellStartup{}); o.unmodeled() {
		t.Errorf("a plain call is modeled: %+v", o)
	}
	for _, change := range []string{"shopt -s nullglob; touch a*", "GLOBIGNORE=x touch a*", "set -f; touch a*", "eval touch a*", "bash -O dotglob -c 'touch a*'", "source x; touch a*"} {
		if o := shellGlobOptionsForCall(change, ShellStartup{}); !o.unknown {
			t.Errorf("%q: options not marked unknown", change)
		}
	}
}
