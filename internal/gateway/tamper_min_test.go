// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"
)

// rel-1-0-10:GAP-0142 and GAP-0365 (lane s7-tmin). Two shell shapes wrote
// DefenseClaw state or an agent hook config with no target named:
//
//   - an archive extraction into the home that names a member below
//     .defenseclaw or an agent config folder (the extraction folder was judged,
//     the member never);
//   - an inline interpreter (python -c CODE ARG...) whose code is not proven
//     read-only, handed a protected path by a runner (direct argv, sudo, env,
//     xargs, parallel, sh -c, a for or while loop, a variable, find -exec).
//
// Every row here is a write: DefenseClaw state blocks in every tier; an agent
// hook config alerts in the default pack and blocks in strict, as the same
// file written by truncate does in each tier. Set TMIN_LOG=1 to print the
// verdict of every row instead of asserting it (the head-versus-rel diff).

func tminHome(t *testing.T) gap0048Home {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX home and shell only")
	}
	h := newGAP0048Home(t)
	for _, name := range []string{".defenseclaw/config.yaml", ".defenseclaw/hooks/codex-hook.sh"} {
		path := filepath.Join(h.home, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("x: 1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

// tminWant is the verdict a write of the target gets in a tier. The state is
// a block everywhere; the hook config is pinned in the default (alert) and
// strict (block) packs; in the other tiers it is what the same file written
// by truncate gets there (control).
func tminWant(tier string, state bool, control string) string {
	switch {
	case state:
		return "block"
	case tier == "default":
		return "alert"
	case tier == "strict":
		return "block"
	}
	return control
}

// tminRules names the tamper rules a verdict carries.
func tminRules(findings []string) string {
	var fired []string
	for _, rule := range []string{"tamper.detector_state_write", agentHookConfigWriteRuleID, agentHookConfigDisableRuleID} {
		if slices.ContainsFunc(findings, func(f string) bool { return strings.HasPrefix(f, rule) }) {
			fired = append(fired, rule)
		}
	}
	return strings.Join(fired, ",")
}

// tminDecide judges one shell call in a tier, as the Claude Code hook route
// does (the same harness as TestBoundRuleEveryLaneCap).
func tminDecide(t *testing.T, api *APIServer, h gap0048Home, command string) (string, []string) {
	t.Helper()
	return boundedDecideClaudeCode(t, api, boundedEnv{home: h.home, cwd: h.project},
		boundedLaneCall{tool: "Bash", input: map[string]any{"command": command}})
}

// tminRow is one command, its target kind and the label it logs under.
type tminRow struct {
	group, name, command string
	state                bool
}

// tminRun judges every row in every tier. With TMIN_LOG set it logs
// "TMIN <tier> <group> <name> action=<a> rules=<r>" and asserts nothing;
// otherwise a row that is not the wanted verdict fails.
func tminRun(t *testing.T, h gap0048Home, rows []tminRow) {
	t.Helper()
	logOnly := os.Getenv("TMIN_LOG") != ""
	for _, tier := range boundedTestTiers {
		t.Run(tier.name, func(t *testing.T) {
			api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
			hookControl, _ := tminDecide(t, api, h, "truncate -s 0 ~/.claude/settings.json")
			for _, row := range rows {
				action, findings := tminDecide(t, api, h, row.command)
				rules := tminRules(findings)
				if logOnly {
					t.Logf("TMIN\t%s\t%s\t%s\taction=%s\trules=%s", tier.name, row.group, row.name, action, rules)
					continue
				}
				want := tminWant(tier.name, row.state, hookControl)
				if action != want || want != "allow" && rules == "" {
					t.Errorf("%s %s %s: action %q rules %q, want %q: %v", tier.name, row.group, row.name, action, rules, want, findings)
				}
			}
		})
	}
}

// rel-1-0-10:GAP-0142: an extraction names members; the folder and the member
// joined, normalized, are what it writes.
func TestTMinArchiveMemberLandsInProtectedFile(t *testing.T) {
	h := tminHome(t)
	spell := strings.NewReplacer("{H}", h.home)
	var rows []tminRow
	for _, member := range []struct {
		path  string
		state bool
	}{
		{".defenseclaw/config.yaml", true},
		{".defenseclaw/hooks/codex-hook.sh", true},
		{".claude/settings.json", false},
		{".codex/config.toml", false},
	} {
		for name, template := range map[string]string{
			"tar -C ~":               `tar -xf /tmp/tmin.tar -C ~ M`,
			"tar -C abs":             `tar -xf /tmp/tmin.tar -C {H} M`,
			"tar -C attached":        `tar -xf /tmp/tmin.tar -C{H} M`,
			"tar --directory sep":    `tar -xf /tmp/tmin.tar --directory ~ M`,
			"tar --directory=":       `tar -xf /tmp/tmin.tar --directory={H} M`,
			"tar old-style":          `tar xf /tmp/tmin.tar -C ~ M`,
			"tar gz cluster":         `tar -xzf /tmp/tmin.tgz -C ~ M`,
			"tar -C first":           `tar -C ~ -xf /tmp/tmin.tar M`,
			"tar long extract":       `tar --extract --file=/tmp/tmin.tar --directory ~ M`,
			"tar dot-slash member":   `tar -xf /tmp/tmin.tar -C ~ ./M`,
			"tar dotdot from proj":   `tar -xf /tmp/tmin.tar -C ~/proj ../M`,
			"tar sudo":               `sudo tar -xf /tmp/tmin.tar -C ~ M`,
			"bsdtar":                 `bsdtar -xf /tmp/tmin.tar -C ~ M`,
			"tar strip-components":   `tar -xf /tmp/tmin.tar --strip-components=1 -C ~ pkg/M`,
			"unzip -d after":         `unzip -o /tmp/tmin.zip M -d ~`,
			"unzip -d attached":      `unzip -o /tmp/tmin.zip M -d{H}`,
			"unzip -d before":        `unzip -d ~ /tmp/tmin.zip M`,
			"unzip cluster -od":      `unzip -od ~ /tmp/tmin.zip M`,
			"unzip -q member -x":     `unzip -q /tmp/tmin.zip M -x other -d ~`,
			"unzip sudo":             `sudo unzip -o /tmp/tmin.zip M -d ~`,
			"unzip -d then redirect": `unzip -o /tmp/tmin.zip M -d ~ > /tmp/tmin.out`,
		} {
			rows = append(rows, tminRow{"archive", name + " " + member.path, spell.Replace(strings.NewReplacer("M", member.path).Replace(template)), member.state})
		}
	}
	// A member folder and a pattern reach the files below them.
	for name, command := range map[string]string{
		"tar state folder member": `tar -xf /tmp/tmin.tar -C ~ .defenseclaw`,
		"unzip state pattern":     `unzip -o -d ~ /tmp/tmin.zip '.defenseclaw/*'`,
	} {
		rows = append(rows, tminRow{"archive", name, command, true})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].name < rows[j].name })
	tminRun(t, h, rows)
}

// An extraction that writes none of the protected files stays what it was:
// listings, output to stdout, another folder, a project member, no member
// list, a create, an excluded member and unzip -j (members lose their folder).
func TestTMinArchiveReadsAndOtherFoldersStayAllowed(t *testing.T) {
	h := tminHome(t)
	logOnly := os.Getenv("TMIN_LOG") != ""
	for name, command := range map[string]string{
		"tar project member":          `tar -xf /tmp/tmin.tar -C ~ proj/notes.txt`,
		"tar state member to stdout":  `tar -xOf /tmp/tmin.tar -C ~ .defenseclaw/config.yaml | sha256sum`,
		"tar list a state member":     `tar -tf /tmp/tmin.tar .defenseclaw/config.yaml`,
		"tar other folder":            `tar -xf /tmp/tmin.tar -C /var/tmp/tmin .defenseclaw/config.yaml`,
		"tar no member list":          `tar -xf /tmp/tmin.tar -C ~`,
		"tar exclude names a state":   `tar -xf /tmp/tmin.tar -C ~ --exclude=.defenseclaw/config.yaml proj/notes.txt`,
		"tar create from state":       `tar -cf /tmp/tmin.tar -C ~ .defenseclaw/config.yaml .claude/settings.json`,
		"unzip list a state member":   `unzip -l /tmp/tmin.zip .defenseclaw/config.yaml -d ~`,
		"unzip pipe a state member":   `unzip -p /tmp/tmin.zip .defenseclaw/config.yaml | sha256sum`,
		"unzip other folder":          `unzip -o /tmp/tmin.zip .defenseclaw/config.yaml -d /var/tmp/tmin`,
		"unzip junk paths into home":  `unzip -j /tmp/tmin.zip .defenseclaw/config.yaml -d ~`,
		"unzip project member":        `unzip -o /tmp/tmin.zip proj/notes.txt -d ~`,
		"perl reads a hook config":    `perl -ne 'print' ~/.claude/settings.json`,
		"perl reads state":            `perl -ne 'print' ~/.defenseclaw/config.yaml`,
		"unzip exclude names a state": `unzip -o /tmp/tmin.zip proj/notes.txt -x .defenseclaw/config.yaml -d ~`,
	} {
		for _, tier := range boundedTestTiers {
			t.Run(tier.name+"/"+name, func(t *testing.T) {
				api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
				action, findings := tminDecide(t, api, h, command)
				if logOnly {
					t.Logf("TMIN\t%s\tkeep\t%s\taction=%s\trules=%s", tier.name, name, action, tminRules(findings))
				} else if rules := tminRules(findings); rules != "" {
					t.Errorf("%s %s: a call that writes no protected file names %s (action %s): %v", tier.name, name, rules, action, findings)
				}
			})
		}
	}
}

// tminCode is one inline interpreter write body and the words that run it.
type tminCode struct{ id, run, code string }

// tminCodes are the write bodies of the existing GAP-0104 / GAP-0269 fixtures
// (the python ones, by id) and one write body for each other inline
// interpreter whose words reach its code (not perl: the shell readers take
// perl without -i as a read, TestRegistrationWriteReachDestinationRoles).
var tminCodes = []tminCode{
	{"py-os-remove", "python3 -c", `import os, sys; os.remove(sys.argv[1])`},
	{"py-os-chmod", "python3 -c", `import os, sys; os.chmod(sys.argv[1], 0o777)`},
	{"py-shutil-copy", "python3 -c", `import shutil, sys; shutil.copy("/tmp/x", sys.argv[1])`},
	{"py-subprocess-run", "python3 -c", `import subprocess, sys; subprocess.run(["rm", sys.argv[1]])`},
	{"py-gap0269-writes", "python3 -c", `import sys; open(sys.argv[1], "w").write("")`},
	{"node-write", "node -e", `require("fs").writeFileSync(process.argv[1], "")`},
	{"ruby-write", "ruby -e", `File.write(ARGV[0], "")`},
	{"php-write", "php -r", `file_put_contents($argv[1], "");`},
}

func tminQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// tminRunners builds, in code, every runner that hands target to the child
// `child` (the interpreter, its code option and quoted code, no handed word).
func tminRunners(child, dir, name, target string) map[string]string {
	find := "find " + dir + " -name " + name
	return map[string]string{
		"direct":        child + " " + target,
		"sudo":          "sudo " + child + " " + target,
		"env":           "env " + child + " " + target,
		"nice":          "nice -n 5 " + child + " " + target,
		"timeout":       "timeout 5 " + child + " " + target,
		"sh -c":         "sh -c " + tminQuote(child+" "+target),
		"sh -c nested":  "sh -c " + tminQuote("bash -c "+tminQuote(child+" "+target)),
		"for loop":      "for f in " + target + "; do " + child + ` "$f"; done`,
		"while read":    "echo " + target + " | while read f; do " + child + ` "$f"; done`,
		"while here":    "while read -r f; do " + child + ` "$f"; done <<< ` + target,
		"while find":    find + " | while read -r f; do " + child + ` "$f"; done`,
		"xargs echo":    "echo " + target + " | xargs " + child,
		"xargs printf":  "printf '%s\\n' " + target + " | xargs -n1 " + child,
		"xargs -I":      "echo " + target + " | xargs -I{} " + child + " {}",
		"xargs -0":      find + " -print0 | xargs -0 " + child,
		"xargs sh -c":   "echo " + target + " | xargs -I{} sh -c " + tminQuote(child+` "$0"`) + " {}",
		"bash -c xargs": "bash -c " + tminQuote("echo "+target+" | xargs "+child),
		"parallel :::":  "parallel " + child + " ::: " + target,
		"parallel pipe": find + " | parallel " + child + " {}",
		"variable":      "p=" + target + "; " + child + ` "$p"`,
		"find exec":     find + " -exec " + child + ` {} \;`,
		"find exec env": find + " -exec env " + child + ` {} \;`,
		"find execdir":  find + " -execdir " + child + ` {} \;`,
		"find exec sh":  find + " -exec sh -c " + tminQuote(child+` "$1"`) + ` sh {} \;`,
		"find exec for": find + " -exec sh -c " + tminQuote(`for f do `+child+` "$f"; done`) + " sh {} +",
	}
}

// rel-1-0-10:GAP-0365: an inline interpreter child whose code is not proven
// read-only reaches every fixed path a runner hands it.
func TestTMinRunnersHandThePathToInlineCode(t *testing.T) {
	h := tminHome(t)
	var rows []tminRow
	for _, code := range tminCodes {
		for _, target := range []struct {
			tag, dir, name, path string
			state                bool
		}{
			{"state", "~/.defenseclaw", "config.yaml", "~/.defenseclaw/config.yaml", true},
			{"hookcfg", "~/.claude", "settings.json", "~/.claude/settings.json", false},
		} {
			child := code.run + " " + tminQuote(code.code)
			for runner, command := range tminRunners(child, target.dir, target.name, target.path) {
				rows = append(rows, tminRow{target.tag, code.id + " " + runner, command, target.state})
			}
			// The interpreter options and spellings a runner passes through.
			for name, spelling := range map[string]string{
				"abs path": "/usr/bin/" + code.run,
			} {
				rows = append(rows, tminRow{target.tag, code.id + " " + name, spelling + " " + tminQuote(code.code) + " " + target.path, target.state})
			}
			if strings.HasPrefix(code.run, "python3") {
				rows = append(rows, tminRow{target.tag, code.id + " isolated", "python3 -I -c " + tminQuote(code.code) + " " + target.path, target.state})
			}
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].group != rows[j].group {
			return rows[i].group < rows[j].group
		}
		return rows[i].name < rows[j].name
	})
	tminRun(t, h, rows)
}

// rel-1-0-10:GAP-0365: the spellings of the handed path and of the child.
func TestTMinSpellingsOfTheHandedPath(t *testing.T) {
	h := tminHome(t)
	for link, target := range map[string]string{
		"state-link": filepath.Join(h.home, ".defenseclaw", "config.yaml"),
		"hook-link":  filepath.Join(h.home, ".claude", "settings.json"),
	} {
		if err := os.Symlink(target, filepath.Join(h.project, link)); err != nil {
			t.Fatal(err)
		}
	}
	const body = `import sys; open(sys.argv[1], "w").write("")`
	child := "python3 -c " + tminQuote(body)
	var rows []tminRow
	for _, target := range []struct {
		tag, path, link string
		state           bool
	}{
		{"state", "~/.defenseclaw/config.yaml", "state-link", true},
		{"hookcfg", "~/.claude/settings.json", "hook-link", false},
	} {
		dir, name := filepath.Dir(target.path), filepath.Base(target.path)
		for spelling, command := range map[string]string{
			"HOME variable":   child + ` "$HOME` + strings.TrimPrefix(target.path, "~") + `"`,
			"braced HOME":     child + ` "${HOME}` + strings.TrimPrefix(target.path, "~") + `"`,
			"dot dot":         child + " ~/proj/.." + strings.TrimPrefix(target.path, "~"),
			"double slash":    child + " " + dir + "//" + name,
			"through a link":  child + " ./" + target.link,
			"after --":        child + " -- " + target.path,
			"after an option": "python3 -W ignore -c " + tminQuote(body) + " " + target.path,
			"fused code":      "python3 -c" + tminQuote(body) + " " + target.path,
			"env path":        "/usr/bin/env python3.12 -c " + tminQuote(body) + " " + target.path,
			"nohup":           "nohup " + child + " " + target.path,
			"command":         "command " + child + " " + target.path,
			"sudo -u":         "sudo -n -u nobody " + child + " " + target.path,
			"bash -lc":        "bash -lc " + tminQuote(child+" "+target.path),
			"command subst":   child + ` "$(echo ` + target.path + `)"`,
			"code variable":   `code=1; python3 -c "$code" ` + target.path,
			"cd and list":     "cd " + dir + "; " + child + " " + name,
			"cd and and":      "cd " + dir + " && true && " + child + " " + name,
			"two calls":       "python3 -c 'print(1)'; " + child + " " + target.path,
		} {
			rows = append(rows, tminRow{target.tag, spelling, command, target.state})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].group != rows[j].group {
			return rows[i].group < rows[j].group
		}
		return rows[i].name < rows[j].name
	})
	tminRun(t, h, rows)
}
