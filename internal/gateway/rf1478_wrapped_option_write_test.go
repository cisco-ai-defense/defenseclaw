// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGAP1478WrappedOptionWriteIsTheUnwrappedWrite (rel-1-0-10:GAP-1478,
// TST-17813): an identity wrapper (sudo, doas) or another HOME change
// (env -i, a HOME= prefix) in front of a writer the program table models
// (rsync --log-file, a sed w command or s///w flag) does not change the files
// the call names: the option-argument write keeps the verdict the unwrapped
// writer gets on that member, and the unwrapped writer gets the action of the
// plain cp spelling. At f6e151801a the wrapped rsync spellings were allowed in
// every tier (the HOME change demoted the named write to an unknown role). A
// log or w file in a project folder stays allowed under every wrapper.
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
	writers := map[string]string{
		"rsync -n log":  "rsync -n --log-file={t} a/ b/",
		"rsync -an log": "rsync -an --log-file={t} a/ b/",
		"sed w":         "sed -n \"w {t}\" /dev/null",
		"sed s w":       "sed \"s/a/b/w {t}\" /dev/null",
	}
	wrappers := []string{"sudo ", "sudo -n ", "doas ", "env -i ", "HOME=/tmp "}
	targets := []string{".defenseclaw/audit.db", ".defenseclaw/config.yaml", ".codex/config.toml"}
	benign := []string{
		"rsync -an --log-file=" + home + "/proj/rs.log " + home + "/proj/ /tmp/bk/",
		"rsync -av " + home + "/proj/ /tmp/bk/",
		"sed -n \"w " + home + "/proj/out.txt\" " + home + "/proj/notes.txt",
		"sed \"s/a/b/w " + home + "/proj/out.txt\" " + home + "/proj/notes.txt",
	}
	useDefaultEffectsLane(t)
	for _, tier := range boundedTestTiers {
		for _, route := range []string{"claudecode", "codex"} {
			api := gap0589TierAPI(t, route, tier.posture, tier.managed, tier.tier)
			for _, target := range targets {
				member := filepath.Join(home, target)
				spellings := map[string]string{"abs": member, "tilde": "~/" + target}
				ctlAction, _ := hardP2Verdict(t, api, route, home, "cp /tmp/x "+member)
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
					if action, _ := hardP2Verdict(t, api, route, home+"/proj", wrap+command); action != "allow" {
						t.Errorf("%s %s benign #%d %q: %s, want allow", tier.name, route, i, wrap, action)
					}
				}
			}
		}
	}
}
