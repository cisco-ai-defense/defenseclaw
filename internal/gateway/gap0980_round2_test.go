// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// Review round-one rows, read as scripts only at shell script sources.
// The fixtures are synthetic and their protected paths belong to this test.
func gap0980Round2ReviewRows(t *testing.T, tierName string) {
	env := boundedLaneEnv(t)
	payloads := []struct{ id, s string }{
		{"rmdc", "rm -rf " + filepath.ToSlash(filepath.Join(env.home, ".defenseclaw"))},
		{"dccfg", "printf x >> " + filepath.ToSlash(filepath.Join(env.home, ".defenseclaw", "config.yaml"))},
		{"rc", "echo x >> " + filepath.ToSlash(filepath.Join(env.home, ".bashrc"))},
		{"ak", "echo k >> " + filepath.ToSlash(filepath.Join(env.home, ".ssh", "authorized_keys"))},
		{"ben-echo", "echo hi"}, {"ben-git", "git status"},
	}
	progs := []struct{ id, s string }{
		{"LIT", `bash`}, {"dqSHELL", `"$SHELL"`}, {"errSHELL", `"${SHELL:?}"`}, {"errSHELLm", `"${SHELL:?unset}"`},
		{"emptysq", `"$SHELL"''`}, {"emptydq", `"$SHELL"""`}, {"leadsq", `''"$SHELL"`}, {"unqempty", `$SHELL""`},
		{"dirbash", `"${SHELL%/*}/bash"`}, {"prefbash", `"$PREFIX/bin/bash"`}, {"dnbash", `"$(dirname "$SHELL")/bash"`},
		{"procself", `/proc/self/exe`}, {"procpid", `/proc/$$/exe`}, {"argv0", `"$BASH_ARGV0"`}, {"lower", `"${SHELL,,}"`},
		{"PSHELL", `"$PSHELL"`}, {"BASHVER", `"$BASH_VERSION"`}, {"cmdv", `$(command -v bash)`}, {"cmdpv", `$(command -pv bash)`},
		{"which2", `"$(which bash 2>/dev/null)"`}, {"whichor", `"$(command -v bash || echo sh)"`}, {"typep", `$(type -p sh)`},
		{"bqwz", "`which zsh`"}, {"whicha", `"$(which -a bash | head -n1)"`}, {"readl", `"$(readlink -f "$SHELL")"`},
		{"ZSH", `"$ZSH_NAME"`}, {"pfx", `"${SHELL##/*/}"`}, {"usrbin", `/usr/bin/bash`}, {"envbin", `/usr/bin/env bash`},
	}
	forms := []struct{ id, f string }{
		{"eval-sq", `eval '%P -c "%S"'`}, {"eval-dq", `eval "%Q -c '%S'"`},
		{"exec-a", `exec -a myname %P -c '%S'`}, {"stdin-s", `echo '%S' | %P -s`}, {"herestr-s", `%P -s <<< '%S'`},
		{"heredoc-in", "bash <<'EOS'\n%P -c '%S'\nEOS"}, {"pipe-in", `echo '%P -c "%S"' | bash`},
		{"herestr-in", `bash <<< '%P -c "%S"'`}, {"nested-dq", `bash -c "%Q -c '%S'"`}, {"nested-sh", `sh -c '%P -c "%S"'`},
		{"find", `find . -maxdepth 0 -exec %P -c '%S' \;`},
		{"find-two", `find . -maxdepth 0 -exec true \; -exec %P -c '%S' \;`}, {"xargs", `echo x | xargs %P -c '%S'`},
		{"timeout", `timeout 5 %P -c '%S'`}, {"nice", `nice -n 5 %P -c '%S'`}, {"setsid", `setsid %P -c '%S'`},
		{"stdbuf", `stdbuf -o0 %P -c '%S'`}, {"env-i", `env -i %P -c '%S'`}, {"env-u", `env -u FOO %P -c '%S'`},
		{"command-p", `command -p %P -c '%S'`}, {"sudo-u", `sudo -u root %P -c '%S'`}, {"flock", `flock /tmp/l %P -c '%S'`},
		{"subsh", `(%P -c '%S')`}, {"if", `if true; then %P -c '%S'; fi`}, {"bg", `%P -c '%S' &`},
		{"cmdsub", `x=$(%P -c '%S')`}, {"and", `true && %P -c '%S'`}, {"func", `f() { %P -c '%S'; }; f`},
	}

	ran := false
	for _, tier := range boundedTestTiers {
		if tier.name != tierName {
			continue
		}
		ran = true
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		decide := func(command string) string {
			action, _ := boundedDecideClaudeCode(t, api, env, boundedLaneCall{tool: "Bash", input: map[string]any{"command": command}})
			return action
		}
		check := func(id, command, body string, benign bool) {
			t.Run(tier.name+"/"+id, func(t *testing.T) {
				got := decide(command)
				if benign {
					if got == "block" {
						t.Errorf("benign script blocked")
					}
					return
				}
				floor := decide(body)
				if gap0980ActionRank[got] < gap0980ActionRank[floor] {
					t.Errorf("action %s below shell reading %s", got, floor)
				}
			})
		}
		for _, p := range progs {
			if p.id == "PSHELL" || p.id == "BASHVER" {
				for _, pl := range payloads {
					t.Run(tier.name+"/unknown/"+p.id+"/"+pl.id, func(t *testing.T) {
						got := decide(p.s + " -c '" + pl.s + "'")
						want := decide("$T send '" + pl.s + "'")
						if got != want {
							t.Errorf("generic runtime option action %s, want %s", got, want)
						}
					})
				}
				continue
			}
			for _, pl := range payloads {
				check("pw/"+p.id+"/"+pl.id, p.s+" -c '"+pl.s+"'", "bash -c "+fmt.Sprintf("%q", pl.s), strings.HasPrefix(pl.id, "ben-"))
			}
		}
		for _, p := range []struct{ id, p, q string }{{"LIT", "bash", "bash"}, {"dqSHELL", `"$SHELL"`, `\"\$SHELL\"`}} {
			for _, f := range forms {
				for _, pl := range payloads {
					command := strings.NewReplacer("%P", p.p, "%Q", p.q, "%S", pl.s).Replace(f.f)
					literal := strings.NewReplacer("%P", "bash", "%Q", "bash", "%S", pl.s).Replace(f.f)
					if strings.Contains(f.id, "stdin") || strings.Contains(f.id, "herestr") || strings.Contains(f.id, "pipe-in") {
						literal = "bash -c " + fmt.Sprintf("%q", pl.s)
					}
					check("form/"+f.id+"/"+p.id+"/"+pl.id, command, literal, strings.HasPrefix(pl.id, "ben-"))
				}
			}
		}
		for _, row := range []struct{ id, form string }{
			{"zero-name-sh", `bash -c '"$0" -c "%s"' bash`},
			{"underscore", `: bash; "$_" -c '%s'`},
			{"stdin", `bash <<< '%s'`},
			{"pipe", `echo '%s' | bash`},
		} {
			for _, pl := range payloads {
				check("special/"+row.id+"/"+pl.id, fmt.Sprintf(row.form, pl.s), "bash -c "+fmt.Sprintf("%q", pl.s), strings.HasPrefix(pl.id, "ben-"))
			}
		}
	}
	if !ran {
		t.Fatalf("no bounded tier %q", tierName)
	}
}

// TestGAP0980Round2ReviewRows<Tier> run the review rows one bounded tier each,
// so the race shards can split their cost (rel-1-0-10:GAP-1032: 582 s under
// -race as one test, past what one shard holds).
func TestGAP0980Round2ReviewRowsDefault(t *testing.T)    { gap0980Round2ReviewRows(t, "default") }
func TestGAP0980Round2ReviewRowsPermissive(t *testing.T) { gap0980Round2ReviewRows(t, "permissive") }
func TestGAP0980Round2ReviewRowsStrict(t *testing.T)     { gap0980Round2ReviewRows(t, "strict") }
func TestGAP0980Round2ReviewRowsManaged(t *testing.T)    { gap0980Round2ReviewRows(t, "managed") }
func TestGAP0980Round2ReviewRowsManagedStrict(t *testing.T) {
	gap0980Round2ReviewRows(t, "managed strict")
}

func TestGAP0991UnknownProgramSlashText(t *testing.T) {
	env := boundedLaneEnv(t)
	keys := filepath.ToSlash(filepath.Join(env.home, ".ssh", "authorized_keys"))
	for _, tier := range boundedTestTiers {
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		for index, form := range []string{"cp new.pub %s", "tee -a %s < new.pub", "cat new.pub >> %s"} {
			t.Run(fmt.Sprintf("%s/%d", tier.name, index), func(t *testing.T) {
				command := "$T send '" + fmt.Sprintf(form, keys) + "'"
				got, _ := boundedDecideClaudeCode(t, api, env, boundedLaneCall{tool: "Bash", input: map[string]any{"command": command}})
				want := "block"
				if !tier.managed && tier.posture != "strict" {
					want = "alert"
				}
				if gap0980ActionRank[got] < gap0980ActionRank[want] {
					t.Errorf("action %s below %s", got, want)
				}
			})
		}
	}
}
