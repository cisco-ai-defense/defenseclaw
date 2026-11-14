// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"sort"
	"strings"
	"testing"
)

// rel-1-0-10:GAP-0657 to GAP-0663 (lane s7-tmin2, review s7-tminrev of
// s7/tamper-min). Rows are built in code from the shapes of the s7-tmin
// fixtures; payload text stays out of reports (rows are named by id).
//
// The verdicts, in 5 tiers (default, permissive, strict, managed, managed
// strict):
//   - tmin2Block: DefenseClaw state written by code that names a write call
//     blocks in every tier;
//   - tmin2Tier: the unknown tier, which is what an agent hook config gets
//     for any possible write: an alert in the default pack, a block in the
//     strict pack, and what the same file written by truncate gets in the
//     other tiers (the control row);
//   - tmin2Allow: no tamper rule.
type tmin2Want uint8

const (
	tmin2Allow tmin2Want = iota
	tmin2Tier
	tmin2Block
	// tmin2Allowed: the action is allow. A detection-only finding of rel's own
	// (a loop whose path only a runner knows) may stay.
	tmin2Allowed
)

type tmin2Row struct {
	group, name, command string
	want                 tmin2Want
}

func tmin2Run(t *testing.T, h gap0048Home, rows []tmin2Row) {
	t.Helper()
	logOnly := os.Getenv("TMIN_LOG") != ""
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].group != rows[j].group {
			return rows[i].group < rows[j].group
		}
		return rows[i].name < rows[j].name
	})
	for _, tier := range boundedTestTiers {
		t.Run(tier.name, func(t *testing.T) {
			api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
			control, _ := tminDecide(t, api, h, "truncate -s 0 ~/.claude/settings.json")
			for _, row := range rows {
				action, findings := tminDecide(t, api, h, row.command)
				rules := tminRules(findings)
				if logOnly {
					t.Logf("TMIN2\t%s\t%s\t%s\taction=%s\trules=%s", tier.name, row.group, row.name, action, rules)
					continue
				}
				want := ""
				switch row.want {
				case tmin2Allow:
					if rules != "" {
						t.Errorf("%s %s %s: names %s (action %s): %v", tier.name, row.group, row.name, rules, action, findings)
					}
					continue
				case tmin2Allowed:
					if action != "allow" {
						t.Errorf("%s %s %s: action %q (%s), want allow: %v", tier.name, row.group, row.name, action, rules, findings)
					}
					continue
				case tmin2Block:
					want = "block"
				case tmin2Tier:
					switch tier.name {
					case "default":
						want = "alert"
					case "strict":
						want = "block"
					default:
						want = control
					}
				}
				if action != want || want != "allow" && rules == "" {
					t.Errorf("%s %s %s: action %q rules %q, want %q: %v", tier.name, row.group, row.name, action, rules, want, findings)
				}
			}
		})
	}
}

// tmin2Targets are the two protected files the rows hand to code: DefenseClaw
// state (a write of it blocks) and an agent hook config (the unknown tier).
var tmin2Targets = []struct {
	tag, dir, name, path string
	block                tmin2Want
}{
	{"state", "~/.defenseclaw", "config.yaml", "~/.defenseclaw/config.yaml", tmin2Block},
	{"hookcfg", "~/.claude", "settings.json", "~/.claude/settings.json", tmin2Tier},
}

// tmin2Reads are bodies a read grammar proves read-only (python only).
var tmin2Reads = []tminCode{
	{"py-read-open", "python3 -c", `import sys; print(open(sys.argv[1]).read())`},
	{"py-read-json", "python3 -c", `import json, sys; print(json.load(open(sys.argv[1])))`},
	{"py-read-path", "python3 -c", `from pathlib import Path; import sys; print(Path(sys.argv[1]).read_text())`},
}

// tmin2Unknown are bodies that are no proven read and name no write: node,
// ruby and php have no read grammar, and python outside the grammar.
var tmin2Unknown = []tminCode{
	{"py-unknown-stat", "python3 -c", `import os, sys; print(os.stat(sys.argv[1]).st_size)`},
	{"py-unknown-loop", "python3 -c", `import sys
for line in open(sys.argv[1]): print(line)`},
	{"node-read", "node -e", `console.log(require("fs").readFileSync(process.argv[1], "utf8"))`},
	{"ruby-read", "ruby -e", `puts File.read(ARGV[0])`},
	{"php-read", "php -r", `echo file_get_contents($argv[1]);`},
}

// rel-1-0-10:GAP-0657: inline code that is proven read-only is no write of
// the file it is handed, whatever runner hands it; code that is no proven
// read gets the unknown tier, not a block of the state in every pack.
func TestTMin2ReadOnlyInlineCodeIsNoWrite(t *testing.T) {
	h := tminHome(t)
	// A hook config reached through a loop or a variable alerts on rel for any
	// inline code (the shared registration reader): only the runners rel
	// allows are rows of the proven-read group there.
	hookRunners := map[string]bool{"direct": true, "sudo": true, "env": true, "nice": true, "timeout": true,
		"sh -c": true, "sh -c nested": true, "parallel :::": true, "find exec": true}
	var rows []tmin2Row
	for _, target := range tmin2Targets {
		for _, code := range tmin2Reads {
			child := code.run + " " + tminQuote(code.code)
			for runner, command := range tminRunners(child, target.dir, target.name, target.path) {
				if target.tag == "hookcfg" && !hookRunners[runner] {
					continue
				}
				// rel blocks these find -exec spellings of any python (the
				// find reader has no proof of the code behind env or sh -c).
				if target.tag == "state" && (runner == "find exec env" || runner == "find exec for" || runner == "find exec sh") {
					continue
				}
				rows = append(rows, tmin2Row{target.tag + "-reads", code.id + " " + runner, command, tmin2Allowed})
			}
		}
		for _, code := range tmin2Unknown {
			child := code.run + " " + tminQuote(code.code)
			for runner, command := range tminRunners(child, target.dir, target.name, target.path) {
				want := tmin2Tier
				// A find -exec or xargs child that is no proven reader of the
				// state it is handed keeps rel's block (find reader).
				if target.tag == "state" && (strings.HasPrefix(runner, "find exec") || runner == "xargs -0") {
					want = tmin2Block
				}
				rows = append(rows, tmin2Row{target.tag + "-unknown", code.id + " " + runner, command, want})
			}
		}
	}
	tmin2Run(t, h, rows)
}

// A code variable that no word binds is code the reader cannot see: the
// unknown tier. One bound to a proven read is that read.
func TestTMin2CodeFromAVariable(t *testing.T) {
	h := tminHome(t)
	var rows []tmin2Row
	for _, target := range tmin2Targets {
		rows = append(rows,
			tmin2Row{target.tag, "code from a file", `code=$(cat /var/tmp/tmin.py); python3 -c "$code" ` + target.path, tmin2Tier},
		)
	}
	tmin2Run(t, h, rows)
}

// rel-1-0-10:GAP-0365 residual (GAP-0658): a find -exec child that is an
// inline interpreter handed a fixed path as a plain argument (not {}) is
// handed it exactly as a direct call is.
func TestTMin2FindExecInlineCodeFixedPath(t *testing.T) {
	h := tminHome(t)
	var rows []tmin2Row
	bodies := []tminCode{tminCodes[4], tminCodes[5], tminCodes[6], tminCodes[7]} // python, node, ruby, php write bodies
	for _, target := range tmin2Targets {
		for _, code := range bodies {
			child := code.run + " " + tminQuote(code.code) + " " + target.path
			for name, command := range map[string]string{
				"exec":          `find /tmp -name p -exec ` + child + ` \;`,
				"execdir":       `find /tmp -name p -execdir ` + child + ` \;`,
				"ok":            `find /tmp -name p -ok ` + child + ` \;`,
				"exec plus":     `find /tmp -name p -exec ` + child + ` +`,
				"exec env":      `find /tmp -name p -exec env ` + child + ` \;`,
				"exec sudo":     `find /tmp -name p -exec sudo ` + child + ` \;`,
				"exec nice":     `find /tmp -name p -exec nice -n 5 ` + child + ` \;`,
				"exec timeout":  `find /tmp -name p -exec timeout 5 ` + child + ` \;`,
				"exec sh -c":    `find /tmp -name p -exec sh -c ` + tminQuote(child) + ` \;`,
				"exec bash -c":  `find /tmp -name p -exec bash -c ` + tminQuote(child) + ` \;`,
				"exec two":      `find /tmp -name p -exec true \; -exec ` + child + ` \;`,
				"sudo find":     `sudo find /tmp -name p -exec ` + child + ` \;`,
				"find in sh -c": `sh -c ` + tminQuote(`find /tmp -name p -exec `+child+` \;`),
			} {
				rows = append(rows, tmin2Row{target.tag, code.id + " " + name, command, target.block})
			}
		}
		// A project path as the plain argument stays what it was.
		for _, code := range tmin2Reads {
			rows = append(rows, tmin2Row{"benign-" + target.tag, code.id + " project", `find . -name '*.txt' -exec ` + code.run + ` ` + tminQuote(code.code) + ` notes.txt \;`, tmin2Allow})
		}
	}
	tmin2Run(t, h, rows)
}

// rel-1-0-10:GAP-0142 residual (GAP-0659): a member below a registered agent
// folder is not a registered file, and no member holds one.
func TestTMin2ArchiveMemberBelowARegisteredFolder(t *testing.T) {
	h := tminHome(t)
	var rows []tmin2Row
	for _, member := range []string{
		".config/x.yaml", ".local/share/x", ".claude/notes.txt", ".codex/notes.txt", ".cursor/rules/a.mdc",
		".config/gh/hosts.yml", ".config/nvim/init.lua", ".claude/projects/a/b.json", ".codex/prompts/p.md",
	} {
		for name, template := range map[string]string{
			"tar -C ~":        `tar -xf /tmp/tmin.tar -C ~ M`,
			"tar --directory": `tar -xf /tmp/tmin.tar --directory ~ M`,
			"tar gz":          `tar -xzf /tmp/tmin.tgz -C ~ M`,
			"unzip -d":        `unzip -o /tmp/tmin.zip M -d ~`,
			"unzip -d before": `unzip -d ~ /tmp/tmin.zip M`,
			"tar sudo":        `sudo tar -xf /tmp/tmin.tar -C ~ M`,
			"tar in sh -c":    `sh -c 'tar -xf /tmp/tmin.tar -C ~ M'`,
			"tar -C attached": `tar -xf /tmp/tmin.tar -C$HOME M`,
		} {
			rows = append(rows, tmin2Row{"benign", name + " " + member, strings.ReplaceAll(template, "M", member), tmin2Allow})
		}
	}
	// A direct write of the same paths was never judged either.
	rows = append(rows,
		tmin2Row{"benign", "cp", `cp /tmp/a ~/.config/gh/hosts.yml`, tmin2Allow},
		tmin2Row{"benign", "touch", `touch ~/.claude/notes.txt`, tmin2Allow},
	)
	// The registered file and a member that holds it still are.
	for name, command := range map[string]string{
		"hook file":   `tar -xf /tmp/tmin.tar -C ~ .claude/settings.json`,
		"codex file":  `tar -xf /tmp/tmin.tar -C ~ .codex/config.toml`,
		"folder held": `tar -xf /tmp/tmin.tar -C ~ .claude`,
		"unzip file":  `unzip -o /tmp/tmin.zip .claude/settings.json -d ~`,
	} {
		rows = append(rows, tmin2Row{"registered", name, command, tmin2Tier})
	}
	tmin2Run(t, h, rows)
}

// rel-1-0-10:GAP-0501 hook config twin (GAP-0660): a find child that writes a
// file or runs a program through an option, or changes the file it is handed,
// is no reader of a hook config either; the plain readers stay allowed.
func TestTMin2FindChildOnAHookConfig(t *testing.T) {
	h := tminHome(t)
	var rows []tmin2Row
	find := func(child string) string { return `find ~/.claude -name settings.json -exec ` + child + ` \;` }
	for name, child := range map[string]string{
		"rg --pre":       "rg --pre ./hook.sh token {}",
		"rg -z":          "rg -iz token {}",
		"sort -o":        "sort -o {} {}",
		"sort --out":     "sort --out {} {}",
		"less -o":        "less -o /var/tmp/tmin-out {}",
		"less +command":  "less '+!touch /var/tmp/tmin-x' {}",
		"file -C":        "file -C -m {}",
		"file --comp":    "file --comp -m {}",
		"touch":          "touch {}",
		"chmod":          "chmod 666 {}",
		"chown":          "chown nobody {}",
		"chgrp":          "chgrp nogroup {}",
		"env chmod":      "env chmod 666 {}",
		"absolute chmod": "/bin/chmod 666 {}",
		"sort compress":  "sort --compress-prog=./hook.sh {}",
	} {
		rows = append(rows, tmin2Row{"hook-write", name, find(child), tmin2Tier})
	}
	for name, child := range map[string]string{
		"rg": "rg token {}", "rg -n -i": "rg -n -i token {}", "file": "file {}", "file -b": "file -b -i {}",
		"less": "less {}", "sort": "sort {}", "sort -u": "sort -u -k 1 {}", "cat": "cat {}", "grep": "grep token {}",
		"head": "head -n 3 {}", "jq": "jq . {}", "wc": "wc -l {}", "stat": "stat {}",
	} {
		rows = append(rows, tmin2Row{"hook-read", name, find(child), tmin2Allow})
	}
	tmin2Run(t, h, rows)
}

// rel-1-0-10:GAP-0142 residual spellings (GAP-0661): getopt_long takes any
// unambiguous prefix of a tar long option.
func TestTMin2TarLongOptionPrefixes(t *testing.T) {
	h := tminHome(t)
	var rows []tmin2Row
	for _, target := range []struct {
		tag, member string
		want        tmin2Want
	}{{"state", ".defenseclaw/config.yaml", tmin2Block}, {"hookcfg", ".claude/settings.json", tmin2Tier}} {
		for name, template := range map[string]string{
			"--ext --dir":     `tar --ext -f /tmp/tmin.tar --dir ~ M`,
			"--extr --dir=":   `tar --extr -f /tmp/tmin.tar --dir={H} M`,
			"--ex? --direc":   `tar --extract --file /tmp/tmin.tar --direc ~ M`,
			"--get --directo": `tar --get --file=/tmp/tmin.tar --directo={H} M`,
			"-x --dir":        `tar -xf /tmp/tmin.tar --dir ~ M`,
			"--ext sudo":      `sudo tar --ext -f /tmp/tmin.tar --dir ~ M`,
			"--ext in sh -c":  `sh -c 'tar --ext -f /tmp/tmin.tar --dir ~ M'`,
		} {
			rows = append(rows, tmin2Row{target.tag, name, strings.NewReplacer("M", target.member, "{H}", h.home).Replace(template), target.want})
		}
	}
	tmin2Run(t, h, rows)
}

// rel-1-0-10:GAP-0365 residual spellings (GAP-0662): inline code read from
// stdin, a launcher, an environment variable, an out=PATH or brace word, and
// an sh -c body that is handed the path as $0 or $1.
func TestTMin2HandOffSpellings(t *testing.T) {
	h := tminHome(t)
	var rows []tmin2Row
	write := tminCodes[4] // python: open(sys.argv[1], "w")
	for _, target := range tmin2Targets {
		child := write.run + " " + tminQuote(write.code)
		dir, name := target.dir, target.name
		for label, command := range map[string]string{
			"su -c":           `su -c ` + tminQuote(child+" "+target.path) + ` nobody`,
			"su -c user":      `su nobody -c ` + tminQuote(child+" "+target.path),
			"script -c":       `script -c ` + tminQuote(child+" "+target.path) + ` /dev/null`,
			"script -qc":      `script -qc ` + tminQuote(child+" "+target.path) + ` /dev/null`,
			"ssh":             `ssh localhost ` + child + ` ` + target.path,
			"ssh option":      `ssh -p 22 localhost ` + child + ` ` + target.path,
			"uv run":          `uv run ` + child + ` ` + target.path,
			"uv run opt":      `uv run --no-project ` + child + ` ` + target.path,
			"poetry run":      `poetry run ` + child + ` ` + target.path,
			"watch":           `watch -n 1 ` + child + ` ` + target.path,
			"sh -c $0":        `sh -c ` + tminQuote(child+` "$0"`) + ` ` + target.path,
			"sh -c $1":        `sh -c ` + tminQuote(child+` "$1"`) + ` sh ` + target.path,
			"bash -c $1":      `bash -c ` + tminQuote(child+` "$1"`) + ` bash ` + target.path,
			"brace list":      child + ` {` + target.path + `,/tmp/x}`,
			"brace -exec":     `find /tmp -name p -exec ` + child + ` {` + target.path + `,/tmp/x} \;`,
			"out= word":       child + ` out=` + target.path,
			"cd and relative": `cd ` + dir + `; ` + child + ` ` + name,
		} {
			rows = append(rows, tmin2Row{target.tag + "-write", label, command, target.block})
		}
		// Code the words do not carry: the unknown tier.
		for label, command := range map[string]string{
			"python stdin heredoc": "python3 - " + target.path + " <<'EOF'\nimport os\nEOF",
			"python stdin pipe":    `echo 'print(1)' | python3 - ` + target.path,
			"python stdin xargs":   `echo ` + target.path + ` | xargs python3 -`,
			"node stdin":           `echo 'console.log(1)' | node - ` + target.path,
			"ruby stdin":           `echo 'puts 1' | ruby - ` + target.path,
			"environment variable": `P=` + target.path + ` python3 -c ` + tminQuote(`import os; print(os.environ["P"])`),
			"env assignment":       `env P=` + target.path + ` python3 -c ` + tminQuote(`import os; print(os.environ["P"])`),
		} {
			rows = append(rows, tmin2Row{target.tag + "-unknown", label, command, tmin2Tier})
		}
	}
	// Scripts and modules run files, not inline code; plain programs and the
	// readers are what they were.
	for _, target := range tmin2Targets {
		for label, command := range map[string]string{
			// Owner-trace shapes (w448, 71): a script on stdin handed variables,
			// in a call that runs a hook script of the home and names the config.
			"stdin script variables": "OUT=$(mktemp); python3 - \"$OUT\" <<'PY'\nimport sys\nprint(sys.argv[1])\nPY\ncat " + target.path + " > /dev/null",
			"stdin script two vars":  "a=$(cat " + target.path + "); python3 - \"$a\" \"$b\" <<'PY'\nimport sys\nPY",
			"script file":            `python3 /tmp/s.py ` + target.path,
			"module":                 `python3 -m json.tool ` + target.path,
			"here string":            `python3 - <<< 'print(1)'`,
			"uv run tool":            `uv run ruff check .`,
		} {
			rows = append(rows, tmin2Row{"benign-" + target.tag, label, command, tmin2Allow})
		}
	}
	tmin2Run(t, h, rows)
}

// rel-1-0-10:GAP-0501 residual (GAP-0660): a find child that names a protected
// file in its own option or operand (sort -o FILE {}, install {} FILE, an
// sh -c body that redirects to it) reaches it as it would run directly.
func TestTMin2FindChildNamesTheFile(t *testing.T) {
	h := tminHome(t)
	var rows []tmin2Row
	for _, target := range tmin2Targets {
		find := func(child string) string { return `find /tmp -name p -exec ` + child + ` \;` }
		for name, child := range map[string]string{
			"sort -o":        "sort -o " + target.path + " {}",
			"sort --output=": "sort --output=" + target.path + " {}",
			"sort timeout":   "timeout 5 sort -o " + target.path + " {}",
			"install":        "install {} " + target.path,
			"cp":             "cp {} " + target.path,
			"tee":            "tee " + target.path,
		} {
			if target.tag == "hookcfg" && strings.HasPrefix(name, "sort") {
				continue // GAP-0506: no registered-file reader names sort a writer, direct or under find
			}
			rows = append(rows, tmin2Row{target.tag + "-names", name, find(child), target.block})
		}
		for name, child := range map[string]string{
			"sort -o project": "sort -o out.txt {}",
			"cp project":      "cp {} ./backup/",
			"sh -c project":   "sh -c " + tminQuote("cat {} > ./all.txt"),
			"grep":            "grep token {}",
		} {
			rows = append(rows, tmin2Row{"benign-" + target.tag, name, find(child), tmin2Allow})
		}
	}
	tmin2Run(t, h, rows)
}

// rel-1-0-10:GAP-0142 residual (GAP-0661): an extraction whose members the
// words do not tell (a glob, a list file, a rename) may write any file below
// its folder; so may a 7z or busybox spelling and find -exec tar.
func TestTMin2ArchiveMembersTheWordsDoNotTell(t *testing.T) {
	h := tminHome(t)
	var rows []tmin2Row
	for _, target := range []struct {
		tag, member, glob string
		want              tmin2Want
	}{
		{"state", ".defenseclaw/config.yaml", ".defense*/config.yaml", tmin2Block},
		{"hookcfg", ".claude/settings.json", ".claud*/settings.json", tmin2Tier},
	} {
		known := tmin2Block
		if target.tag == "hookcfg" {
			known = tmin2Tier
		}
		for name, template := range map[string]string{
			"tar glob member":      `tar -xf /tmp/tmin.tar -C ~ --wildcards 'G'`,
			"tar glob member bare": `tar -xf /tmp/tmin.tar -C ~ 'G'`,
			"unzip glob member":    `unzip -o -d ~ /tmp/tmin.zip 'G'`,
			"tar -T list":          `tar -xf /tmp/tmin.tar -C ~ -T /tmp/list.txt`,
			"tar --files-from":     `tar -xf /tmp/tmin.tar -C ~ --files-from=/tmp/list.txt`,
			"tar --transform":      `tar -xf /tmp/tmin.tar -C ~ --transform 's,^,x/,' proj/a.txt`,
			"bsdtar -s":            `bsdtar -xf /tmp/tmin.tar -C ~ -s ',^,x/,' proj/a.txt`,
			"tar in sh -c":         `sh -c "tar -xf /tmp/tmin.tar -C ~ -T /tmp/list.txt"`,
		} {
			// An unknown member list is the unknown tier, not a proven write.
			want := tmin2Tier
			rows = append(rows, tmin2Row{target.tag + "-unknown", name, strings.ReplaceAll(template, "G", target.glob), want})
		}
		for name, template := range map[string]string{
			"7z x member":      `7z x /tmp/tmin.7z -o` + h.home + ` @M@`,
			"busybox tar":      `busybox tar -xf /tmp/tmin.tar -C ~ @M@`,
			"busybox unzip":    `busybox unzip /tmp/tmin.zip @M@ -d ~`,
			"find -exec tar":   `find /tmp -name tmin.tar -exec tar -xf {} -C ~ @M@ \;`,
			"find -exec unzip": `find /tmp -name tmin.zip -exec unzip -o {} @M@ -d ~ \;`,
		} {
			rows = append(rows, tmin2Row{target.tag + "-known", name, strings.ReplaceAll(template, "@M@", target.member), known})
		}
	}
	// Folders the state is not below, and plain project members.
	for name, command := range map[string]string{
		"glob in a scratch folder":   `tar -xf /tmp/tmin.tar -C /var/tmp/tmin --wildcards '*.md'`,
		"list into a scratch folder": `tar -xf /tmp/tmin.tar -C /var/tmp/tmin -T /tmp/list.txt`,
		"transform in /var/tmp":      `tar -xf /tmp/tmin.tar -C /var/tmp/tmin --transform 's,^,x/,' a.txt`,
		"unzip glob in /var/tmp":     `unzip -o -d /var/tmp/tmin /tmp/tmin.zip '*.py'`,
		"7z project member":          `7z x /tmp/tmin.7z -o` + h.home + `/proj proj/a.txt`,
		"busybox tar project":        `busybox tar -xf /tmp/tmin.tar -C ~/proj a.txt`,
		"find -exec tar project":     `find /tmp -name tmin.tar -exec tar -xf {} -C ~/proj a.txt \;`,
	} {
		rows = append(rows, tmin2Row{"benign", name, command, tmin2Allow})
	}
	tmin2Run(t, h, rows)
}
