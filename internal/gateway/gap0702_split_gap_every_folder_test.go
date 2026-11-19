// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestGAP0702SplitGapJudgesEveryFolder: after a call the split cannot read
// whose dynamic part follows && in a mover body, the facts place a relative
// operand only in the mover's target, though the unread part may move the
// shell anywhere, home included (substrate-1:GAP-0702: from the home, `f(){
// cd /tmp && "$@"; }; f cd && rm .aws/credentials` allowed at FU11 c8090b1056
// and t6/fix-0690 525d661c1f, where rel 740c0de8fd alerts in default and
// blocks in strict and the plain rm blocks). Every effect on a protected
// home file after each such shape is at least the unknown tier, and one
// spelled from the home is never below its plain statement, with the bar of
// TestGAP0698SplitGapJudgesEveryPathEffect. The same effects on ordinary
// files, and ordinary developer commands after the shapes, stay an allow.
func TestGAP0702SplitGapJudgesEveryFolder(t *testing.T) {
	installCorrelationHMACForTest(t)
	home := filepath.Join(t.TempDir(), "home", "alice")
	project := filepath.Join(home, "proj")
	for _, name := range []string{
		"proj/README.md", "proj/build.sh", "proj/.env", "proj/src/x.go", "proj/out.txt", "proj/build/out.o", "proj/node_modules/x",
		".aws/credentials", ".bashrc", ".netrc", ".ssh/id_rsa", "x.txt",
	} {
		file := filepath.Join(home, name)
		if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	// The mover bodies whose dynamic part follows && (FIX-0698-RV A01-A13).
	// The first six run every effect; the rest a write, an append, a delete,
	// a read, a rename away and a mode change.
	shapes := []string{
		`f(){ cd /tmp && "$@"; }; f cd && `,
		`f(){ cd /tmp && $y; }; f && `,
		`f(){ cd /tmp && eval "$c"; }; f && `,
		`f(){ cd /tmp && $r ~; }; f && `,
		`f(){ pushd /tmp >/dev/null && "$@"; }; f cd && `,
		`f(){ cd /tmp; cd /var && "$@"; }; f cd && `,
		`f(){ cd /tmp && { "$@"; }; }; f cd && `,
		`f(){ cd /tmp && "$@" && :; }; f cd && `,
		`f(){ [ -d /tmp ] && cd /tmp && "$@"; }; f cd && `,
		`f(){ cd /tmp && "$@" || true; }; f cd && `,
		`f(){ cd /tmp && command "$@"; }; f cd && `,
		`g(){ cd /tmp && "$@"; }; f(){ g "$@"; }; f cd && `,
	}
	const everyEffect = 6
	some := map[string]bool{"echo x > T": true, "echo x >> T": true, "rm T": true, "cat T": true, "mv T /tmp/c": true, "chmod 600 T": true}
	// The effect kinds of the FIX-0698-RV break probe (shape N34and), after
	// the first shape.
	more := []string{
		"truncate -s 0 T", ": > T", "> T", "cp --remove-destination /tmp/x T", "install -m 600 /tmp/x T", "rsync /tmp/x T",
		"find T -delete", `find T -exec rm {} \;`, "cat > T <<'EOF'\nx\nEOF", "printf x 1> T", "echo x 2> T", "mv T T.bak",
		"cp -f /tmp/x T", "cat /tmp/x >> T", "tee -a T < /tmp/x", "dd of=T < /tmp/x", "sh -c 'echo x > T'", `bash -c "rm T"`,
		`eval "rm T"`, "command rm T", "builtin echo x > T", "exec rm T", "env rm T", "nohup rm T", "sudo rm T", "(rm T)",
		"{ rm T; }", "rm T | cat", "rm -rf T", "rm -- T", "base64 T",
	}
	rank := map[string]int{"allow": 0, "alert": 1, "block": 2}
	tier := map[string]string{"default": "alert", "strict": "block"}
	for _, pack := range []string{"default", "strict"} {
		handler := hostClaudeHookHandlerForTest(t, pack)
		n := 0
		decide := func(cwd, command string) string {
			n++
			ev := claudeToolEvent("PreToolUse", "gap0702-"+pack+strconv.Itoa(n), "c"+strconv.Itoa(n), command)
			ev["cwd"] = cwd
			return callAgentHookForTest(t, handler, ev).Action
		}
		atLeast := func(command, want, plain string) {
			if got := decide(home, command); rank[got] < rank[want] {
				t.Errorf("%s: %q is %s, want at least %s (plain %s)", pack, command, got, want, plain)
			}
		}
		for _, target := range []string{".aws/credentials", ".bashrc", "~/.aws/credentials"} {
			resolved := filepath.Join(home, strings.TrimPrefix(target, "~/"))
			spelled := strings.HasPrefix(target, "~/")
			for _, effect := range gap0698PathEffects {
				statement := strings.ReplaceAll(effect.text, "T", target)
				plain := decide(home, statement)
				protected := false
				for _, access := range effect.access {
					protected = protected || decide(home, gap0698EffectTwin[access]+resolved) != "allow"
				}
				want := "allow"
				if protected {
					want = tier[pack]
				}
				if spelled && rank[plain] > rank[want] {
					want = plain
				}
				for i, shape := range shapes {
					if i < everyEffect || some[effect.text] {
						atLeast(shape+statement, want, plain)
					}
				}
			}
			if spelled {
				continue
			}
			for _, effect := range more {
				statement := strings.ReplaceAll(effect, "T", target)
				if plain := decide(home, statement); plain != "allow" {
					atLeast(shapes[0]+statement, tier[pack], plain)
				}
			}
		}
		// Other spellings of the same file.
		for _, statement := range []string{
			"rm ./.aws/credentials", "rm .aws//credentials", "rm .aws/./credentials", "cat proj/../.aws/credentials",
			"rm ../alice/.aws/credentials",
		} {
			atLeast(shapes[0]+statement, tier[pack], "")
		}
		// Controls: ordinary files, and developer commands, after the same
		// shapes (two of them for the effects) stay an allow.
		for _, control := range []struct{ cwd, target string }{
			{project, "out.txt"}, {home, "x.txt"},
		} {
			for _, effect := range gap0698PathEffects {
				if strings.HasPrefix(effect.text, "ln ") || strings.HasPrefix(effect.text, "chmod 777") {
					continue
				}
				statement := strings.ReplaceAll(effect.text, "T", control.target)
				for _, shape := range shapes[:2] {
					if got := decide(control.cwd, shape+statement); got != "allow" {
						t.Errorf("%s: control %q in %s is %s, want allow", pack, shape+statement, filepath.Base(control.cwd), got)
					}
				}
			}
		}
		for _, command := range []string{
			"cat README.md", "chmod +x ./build.sh", "cat .env", "sed -i s/a/b/ src/x.go", "rm -rf node_modules build",
		} {
			for _, shape := range []string{shapes[0], `f(){ cd /tmp && "$@"; }; f make && `, `f(){ "$@"; }; f make && `} {
				if got := decide(project, shape+command); got != "allow" {
					t.Errorf("%s: control %q in proj is %s, want allow", pack, shape+command, got)
				}
			}
		}
	}
}
