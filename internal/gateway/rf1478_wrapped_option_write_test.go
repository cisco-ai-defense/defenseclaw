// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestGAP1478WrappedOptionWriteIsTheUnwrappedWrite (rel-1-0-10:GAP-1478,
// TST-17813): an identity wrapper (sudo, doas), a HOME change (env -i, a
// HOME= prefix) or any other env input the allow list does not account for
// (FOO=1, env or sudo FOO=1, an export, XDG_CONFIG_HOME=, RSYNC_RSH=, PATH=)
// in front of a writer the program table models (rsync --log-file, a sed w
// command or s///w flag, curl -o) does not change the files the call names:
// the option-argument write keeps the verdict the unwrapped writer gets on
// that member, and the unwrapped writer gets the action of the plain cp
// spelling. At f6e151801a the wrapped rsync spellings were allowed in every
// tier (the env input demoted the named write to an unknown role); at
// 25efdf4371 only a HOME change was taken back. LANG=C and TZ=UTC are inert
// names and pin the unchanged rows. A log, w or output file in a project
// folder stays allowed under every wrapper. On a Windows host the calls are
// Git Bash text (hardP5Routes: Claude Code's Bash only), the home is the
// active USERPROFILE spelled with forward slashes (hardP5Path) and /tmp is a
// test folder, as in the other DET111 hard rows.
func TestGAP1478WrappedOptionWriteIsTheUnwrappedWrite(t *testing.T) {
	home := t.TempDir()
	for _, f := range []string{".defenseclaw/audit.db", ".defenseclaw/config.yaml", ".codex/config.toml", "proj/notes.txt"} {
		p := filepath.Join(home, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // the active home on Windows
	sh := filepath.ToSlash(home)  // the home as POSIX text spells it (hardP5Path)
	tmp := "/tmp"
	if runtime.GOOS == "windows" {
		// Git Bash maps /tmp to a folder of its own install, which a Windows
		// host's reading cannot place; a drive path of the test stands in.
		tmp = filepath.ToSlash(t.TempDir())
	}
	writers := map[string]string{
		"rsync -n log":  "rsync -n --log-file={t} a/ b/",
		"rsync -an log": "rsync -an --log-file={t} a/ b/",
		"sed w":         "sed -n \"w {t}\" /dev/null",
		"sed s w":       "sed \"s/a/b/w {t}\" /dev/null",
		"curl -o":       "curl -sS -o {t} https://example.invalid/c",
	}
	wrappers := []string{"sudo ", "sudo -n ", "doas ", "env -i ", "HOME=/tmp ",
		"FOO=1 ", "env FOO=1 ", "sudo FOO=1 ", "export FOO=1; ", "XDG_CONFIG_HOME=/tmp ", "RSYNC_RSH=ssh ",
		"HOME=/tmp FOO=1 ", "PATH=/usr/bin:/bin ", "env -i PATH=/usr/bin ", "LANG=C ", "TZ=UTC "}
	targets := []string{".defenseclaw/audit.db", ".defenseclaw/config.yaml", ".codex/config.toml"}
	benign := []string{
		"rsync -an --log-file=" + sh + "/proj/rs.log " + sh + "/proj/ " + tmp + "/bk/",
		"rsync -av " + sh + "/proj/ " + tmp + "/bk/",
		"sed -n \"w " + sh + "/proj/out.txt\" " + sh + "/proj/notes.txt",
		"sed \"s/a/b/w " + sh + "/proj/out.txt\" " + sh + "/proj/notes.txt",
		"curl -sS -o " + sh + "/proj/out.txt https://example.invalid/c",
	}
	useDefaultEffectsLane(t)
	for _, tier := range boundedTestTiers {
		for _, route := range hardP5Routes() {
			api := gap0589TierAPI(t, route, tier.posture, tier.managed, tier.tier)
			for _, target := range targets {
				member := hardP5Path(home, target)
				spellings := map[string]string{"abs": member, "tilde": "~/" + target}
				if runtime.GOOS == "windows" {
					// On a Windows host the option-argument and sed-program
					// tilde spellings (--log-file=~/..., "w ~/...") are not
					// read as the home member yet: rel-1-0-10:GAP-2306.
					delete(spellings, "tilde")
				}
				ctlAction, _ := hardP2Verdict(t, api, route, home, "cp "+tmp+"/x "+member)
				if ctlAction == "allow" && tier.name == "default" {
					t.Fatalf("%s %s: plain cp control on %s allows: the control is void", tier.name, route, target)
				}
				for name, w := range writers {
					for sp, path := range spellings {
						cmd := strings.ReplaceAll(w, "{t}", path)
						wantAction, wantSev := hardP2Verdict(t, api, route, home, cmd)
						if wantAction != ctlAction {
							t.Errorf("%s %s %s (%s) on %s: unwrapped %s, plain cp %s", tier.name, route, name, sp, target, wantAction, ctlAction)
						}
						for _, wrap := range wrappers {
							if action, sev := hardP2Verdict(t, api, route, home, wrap+cmd); action != wantAction || sev != wantSev {
								t.Errorf("%s %s %q%s (%s) on %s: %s/%s, unwrapped %s/%s", tier.name, route, wrap, name, sp, target, action, sev, wantAction, wantSev)
							}
						}
					}
				}
			}
			for i, command := range benign {
				for _, wrap := range append([]string{""}, wrappers...) {
					if action, _ := hardP2Verdict(t, api, route, filepath.Join(home, "proj"), wrap+command); action != "allow" {
						t.Errorf("%s %s benign #%d %q: %s, want allow", tier.name, route, i, wrap, action)
					}
				}
			}
		}
	}
}
