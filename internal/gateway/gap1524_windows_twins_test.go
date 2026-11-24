// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rel-1-0-10:GAP-1524: gateway tests whose fixtures are POSIX shell text or
// a POSIX home skip on native Windows (accepted by design, DET111
// 2026-11-24). These are their Windows twins: the same classes on a Windows
// home, through the Claude Code Bash tool, which a Windows gateway reads as
// Git Bash (POSIX) when the call parses as POSIX, in the five tiers. A
// Windows home whose state, wrapped or handed off, read as nothing fails
// here.

// gap1524Verdicts is the hook action of every row in every tier.
func gap1524Verdicts(t *testing.T, cwd string, commands map[string]string) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	for _, pack := range gap0437Packs {
		hook := gap0437Server(t, pack, "claudecode", "action")
		for id, command := range commands {
			out[pack.name+"/"+id] = gap0437Hook(t, hook, cwd, "gap1524-"+pack.name+id, command)
		}
	}
	return out
}

func gap1524Strict(pack string) bool { return pack == "strict" || pack == "managed-strict" }

// Class: a state delete or mutation behind a prefix wrapper, an xargs
// reader, a heredoc consumer, an inline-code hand-off and a find child
// (POSIX twins TestStateDeleteBehindAnyPrefixWrapperFiveTiers,
// TestStateMutationBehindAnyPrefixWrapperFiveTiers,
// TestXargsStdinReaderReadsTheShellWordsFiveTiers, TestGAP1182*,
// TestGAP1183*, TestGAP1240GAP1241ReviewRowsOnClaudeHook, TestTMin2*). The
// oracle is the plain call: a wrapped or handed-off spelling is never
// weaker than the plain one, and the plain one is never an allow.
func TestGAP1524WindowsWrappedStateWritesKeepThePlainVerdict(t *testing.T) {
	_, cwd := gap1173WindowsStateHome(t)
	plain := map[string]string{
		"delete": "rm -rf ~/.defenseclaw",
		"mutate": "truncate -s 0 ~/.defenseclaw/config.yaml",
	}
	wrapped := map[string]string{}
	for _, w := range []string{"nohup", "nice -n 5", "timeout 5", "env", "stdbuf -o0", "command", "time", "nohup nice"} {
		for kind, call := range plain {
			wrapped[kind+"/"+w] = w + " " + call
		}
	}
	wrapped["delete/xargs"] = "printf '%s\\n' ~/.defenseclaw | xargs rm -rf"
	wrapped["mutate/sh heredoc"] = "sh <<'EOF'\n: > ~/.defenseclaw/config.yaml\nEOF"
	wrapped["mutate/bash heredoc"] = "bash <<EOF\ntruncate -s 0 ~/.defenseclaw/config.yaml\nEOF"
	wrapped["mutate/nohup sh heredoc"] = "nohup sh <<'EOF'\n: > ~/.defenseclaw/config.yaml\nEOF"
	wrapped["mutate/python -c"] = "python3 -c 'import sys; open(sys.argv[1], \"w\").write(\"\")' ~/.defenseclaw/config.yaml"
	wrapped["mutate/find -exec"] = "find ~/.defenseclaw -name config.yaml -exec truncate -s 0 {} \\;"
	allowed := map[string]string{
		"project delete":       "nohup rm -rf build",
		"project mutate":       "nice -n 5 truncate -s 0 notes.txt",
		"heredoc data":         "cat <<'EOF'\nordinary data\nEOF",
		"python -c read":       "python3 -c 'import sys; print(open(sys.argv[1]).read())' notes.txt",
		"find -exec read":      "find . -name notes.txt -exec cat {} \\;",
		"xargs project delete": "printf '%s\\n' build | xargs rm -rf",
	}
	all := map[string]string{}
	for id, c := range plain {
		all["plain/"+id] = c
	}
	for id, c := range wrapped {
		all["wrapped/"+id] = c
	}
	for id, c := range allowed {
		all["allowed/"+id] = c
	}
	got := gap1524Verdicts(t, cwd, all)
	for _, pack := range gap0437Packs {
		for kind := range plain {
			p := got[pack.name+"/plain/"+kind]
			if p["action"] == "allow" {
				t.Errorf("%s plain %s %q: allow on a Windows home: %v", pack.name, kind, plain[kind], p["reason"])
			}
			if gap1524Strict(pack.name) && p["action"] != "block" {
				t.Errorf("%s plain %s %q: action %v, want block in strict: %v", pack.name, kind, plain[kind], p["action"], p["reason"])
			}
		}
		for id, call := range wrapped {
			kind := id[:6]
			w, p := got[pack.name+"/wrapped/"+id], got[pack.name+"/plain/"+kind]
			if hookActionRank(fmt.Sprint(w["action"])) < hookActionRank(fmt.Sprint(p["action"])) {
				t.Errorf("%s %s %q: action %v, weaker than the plain call's %v: %v", pack.name, id, call, w["action"], p["action"], w["reason"])
			}
		}
		for id, call := range allowed {
			if a := got[pack.name+"/allowed/"+id]; a["action"] != "allow" {
				t.Errorf("%s %s %q: action %v, want allow: %v", pack.name, id, call, a["action"], a["reason"])
			}
		}
	}
}

// Class: a delete of the whole home (POSIX twin
// TestGAP0594CriticalScopeEveryTier, TestHomeDeleteBehindSetsidOrAnsweredPromptsFiveTiers):
// on a Windows home it is never an allow and blocks in strict; a project
// folder delete stays allowed.
func TestGAP1524WindowsHomeDeleteIsCriticalInEveryTier(t *testing.T) {
	_, cwd := gap1173WindowsStateHome(t)
	critical := map[string]string{
		"rm -rf ~": "rm -rf ~", "rm -rf ~/*": "rm -rf ~/*", "rm -rf HOME": "rm -rf $HOME",
		"nohup rm -rf ~": "nohup rm -rf ~",
	}
	allowed := map[string]string{"project": "rm -rf build", "home project": "rm -rf ~/project/build"}
	all := map[string]string{}
	for id, c := range critical {
		all["critical/"+id] = c
	}
	for id, c := range allowed {
		all["allowed/"+id] = c
	}
	got := gap1524Verdicts(t, cwd, all)
	for _, pack := range gap0437Packs {
		for id, call := range critical {
			a := got[pack.name+"/critical/"+id]
			if a["action"] == "allow" || gap1524Strict(pack.name) && a["action"] != "block" {
				t.Errorf("%s %q: action %v on a Windows home: %v", pack.name, call, a["action"], a["reason"])
			}
		}
		for id, call := range allowed {
			if a := got[pack.name+"/allowed/"+id]; a["action"] != "allow" {
				t.Errorf("%s %q: action %v, want allow: %v", pack.name, call, a["action"], a["reason"])
			}
		}
	}
}

// Class: a long operand list in a deep project folder keeps a protected
// target (POSIX twins
// TestLongOperandListInADeepFolderIsAllowedAndKeepsProtectedTargets,
// TestDeepFolderFixtureReachesItsDepthOnAShortTempRoot): 300 operands and
// then a second name of the keys file get the verdict of the short call
// that names only it, which is never an allow; the same list with an
// ordinary file last stays allowed. The second name is a hard link, which
// the Limited token may create.
func TestGAP1524WindowsLongOperandListKeepsProtectedTarget(t *testing.T) {
	home, cwd := gap1173WindowsStateHome(t)
	deep := filepath.Join(cwd, "a", "b", "c", "d", "e", "f", "g", "h")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(keys, []byte("k\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(keys, filepath.Join(deep, "output")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deep, "plain.txt"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	words := make([]string, 0, 300)
	for i := 0; i < 300; i++ {
		words = append(words, fmt.Sprintf("h%04d", i))
	}
	list := strings.Join(words, " ")
	got := gap1524Verdicts(t, deep, map[string]string{
		"short keys": "touch output",
		"long keys":  "touch " + list + " output",
		"long plain": "touch " + list + " plain.txt",
	})
	for _, pack := range gap0437Packs {
		short, long, plain := got[pack.name+"/short keys"], got[pack.name+"/long keys"], got[pack.name+"/long plain"]
		if short["action"] == "allow" {
			t.Errorf("%s touch of a second name of the keys file: allow: %v", pack.name, short["reason"])
		}
		if hookActionRank(fmt.Sprint(long["action"])) < hookActionRank(fmt.Sprint(short["action"])) {
			t.Errorf("%s 300 operands then the keys file's second name: action %v, weaker than the short call's %v: %v", pack.name, long["action"], short["action"], long["reason"])
		}
		if plain["action"] != "allow" {
			t.Errorf("%s 300 ordinary operands: action %v, want allow: %v", pack.name, plain["action"], plain["reason"])
		}
	}
}
