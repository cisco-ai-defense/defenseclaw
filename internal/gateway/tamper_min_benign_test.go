// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"sort"
	"testing"
)

// The 1.0.10 lead's benign bar for s7/tamper-min: ordinary archive extraction
// into a project folder and ordinary inline python on project files and on
// stdin name no tamper rule, in every tier (TMIN_LOG=1 prints the verdicts so
// the same rows are compared against rel).
func TestTMinExplicitBenignRowsStayAllowed(t *testing.T) {
	h := tminHome(t)
	const code = `'import sys; print(open(sys.argv[1]).read())'`
	const stdin = `'import sys; print(sys.stdin.read())'`
	rows := map[string]string{
		"tar -C ./build":               `tar -xf /tmp/tmin.tar -C ./build`,
		"tar -C ./build members":       `tar -xf /tmp/tmin.tar -C ./build src/main.go docs/readme.md`,
		"tar --directory ./build":      `tar --extract --file /tmp/tmin.tar --directory ./build src/main.go`,
		"tar -xzf -C ./build":          `tar -xzf /tmp/tmin.tgz -C ./build pkg/lib.a`,
		"tar -C ./build attached":      `tar -xf /tmp/tmin.tar -C./build src/main.go`,
		"tar dotted member in project": `tar -xf /tmp/tmin.tar -C ./build .gitignore .claude-notes.md`,
		"unzip -d ./vendor":            `unzip -o /tmp/tmin.zip -d ./vendor`,
		"unzip -d ./vendor members":    `unzip -o /tmp/tmin.zip lib/a.js lib/b.js -d ./vendor`,
		"unzip -d ./vendor -x":         `unzip -q /tmp/tmin.zip -x 'test/*' -d ./vendor`,
		"unzip -d attached ./vendor":   `unzip -o /tmp/tmin.zip lib/a.js -d./vendor`,
		"sudo unzip ./vendor":          `sudo unzip -o /tmp/tmin.zip lib/a.js -d ./vendor`,
		"python -c project file":       `python3 -c ` + code + ` ./notes.txt`,
		"python -c project file abs":   `python3 -c ` + code + ` ~/proj/notes.txt`,
		"python -c json project":       `python3 -c 'import json,sys; print(json.load(open(sys.argv[1])))' ./package.json`,
		"python -c stdin pipe":         `cat notes.txt | python3 -c ` + stdin,
		"python -c stdin redirect":     `python3 -c ` + stdin + ` < notes.txt`,
		"python -c stdin here-string":  `python3 -c ` + stdin + ` <<< hello`,
		"python -c stdin dash":         `echo hello | python3 -c ` + stdin + ` -`,
		"python - heredoc":             "python3 - <<'PY'\nprint(1)\nPY",
		"python -c xargs project":      `ls *.txt | xargs python3 -c ` + code,
		"python -c xargs -n1 project":  `echo notes.txt other.txt | xargs -n1 python3 -c ` + code,
		"python -c xargs -I project":   `echo notes.txt | xargs -I{} python3 -c ` + code + ` {}`,
		"python -c for loop project":   `for f in notes.txt other.txt; do python3 -c ` + code + ` "$f"; done`,
		"python -c for loop glob":      `for f in ./src/*.py; do python3 -c ` + code + ` "$f"; done`,
		"python -c for loop abs":       `for f in ~/proj/a.txt ~/proj/b.txt; do python3 -c ` + code + ` "$f"; done`,
		"python -c while read project": `ls ./src | while read f; do python3 -c ` + code + ` ./src/"$f"; done`,
	}
	names := make([]string, 0, len(rows))
	for name := range rows {
		names = append(names, name)
	}
	sort.Strings(names)
	logOnly := os.Getenv("TMIN_LOG") != ""
	for _, tier := range boundedTestTiers {
		t.Run(tier.name, func(t *testing.T) {
			api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
			for _, name := range names {
				action, findings := tminDecide(t, api, h, rows[name])
				rules := tminRules(findings)
				if logOnly {
					t.Logf("TMIN\t%s\tbenign2\t%s\taction=%s\trules=%s", tier.name, name, action, rules)
				} else if rules != "" {
					t.Errorf("%s %s: names %s (action %s): %v", tier.name, name, rules, action, findings)
				}
			}
		})
	}
}
