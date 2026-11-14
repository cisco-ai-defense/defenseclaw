// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// TestBoundRuleSedBackupUnresolved: an in-place editor backup the reader
// cannot name in full is at least the unknown tier of the pack in all five
// tiers (an alert in the default, permissive and managed default packs, a
// block in the strict packs), a backup the words name in full that reaches a
// protected file blocks in all five, and an ordinary call is not changed
// (rel-1-0-10:GAP-0540, GAP-0541, GAP-0542, GAP-0543; case ids SFXREV-* are
// those of the s7-sfxrev review of s7/sed-suffix a5f2fa3c39). {keys} is the
// protected folder, {home} the home.
func TestBoundRuleSedBackupUnresolved(t *testing.T) {
	env := sedBackupTierFixture(t)
	keys := filepath.Join(env.home, ".ssh")
	for _, name := range []string{"authorized_", "known_hosts"} {
		if err := os.WriteFile(filepath.Join(keys, name), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"f", "authorized_keys"} {
		if err := os.WriteFile(filepath.Join(env.cwd, name), []byte("x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range map[string]string{"lnk": "authorized_keys", "alnk": filepath.Join(keys, "authorized_"), "lnk2": "f"} {
		if err := os.Symlink(target, filepath.Join(env.cwd, link)); err != nil {
			t.Fatal(err)
		}
	}
	const (
		allow      = "allow"
		block      = "block"
		unresolved = "unresolved"
	)
	cases := []struct{ id, command, want string }{
		// GAP-0540
		{"SFXREV-script-var", `sed -i{keys}/* "s/x/$USER/" authorized_keys`, block},
		{"SFXREV-env-var", `sed -i"$SFX" s/x/y/ authorized_keys`, unresolved},
		{"SFXREV-env-var-long", `sed --in-place="$SFX" s/x/y/ authorized_keys`, unresolved},
		{"SFXREV-bsd-var-next", `sed -i "$SFX" s/x/y/ authorized_keys`, unresolved},
		{"SFXREV-operand-var", `sed -i{keys}/* s/x/y/ "$F"`, unresolved},
		{"SFXREV-env-C", "env -C {home} sed -i.ssh/* s/x/y/ authorized_keys", block},
		{"SFXREV-env-chdir", "env --chdir={home} sed -i.ssh/* s/x/y/ authorized_keys", block},
		{"SFXREV-xargs", "echo authorized_keys | xargs sed -i{keys}/* s/x/y/", unresolved},
		{"SFXREV-xargs-I", "echo authorized_keys | xargs -I@ sed -i{keys}/* s/x/y/ @", unresolved},
		{"SFXREV-find-exec", `find authorized_keys -exec sed -i{keys}/* s/x/y/ {} \;`, unresolved},
		{"SFXREV-find-exec-plus", "find . -name authorized_keys -exec sed -i{keys}/* s/x/y/ {} +", unresolved},
		{"SFXREV-find-execdir", `find . -name authorized_keys -execdir sed -i{keys}/* s/x/y/ {} \;`, unresolved},
		// GAP-0541
		{"SFXREV-follow-rel-link-star", "sed --follow-symlinks -i../.ssh/* s/x/y/ lnk", block},
		{"SFXREV-follow-rel-link-star-abbrev", "sed --follow -i../.ssh/* s/x/y/ lnk", block},
		{"SFXREV-follow-abs-link-plain", "sed --follow-symlinks -ikeys s/x/y/ alnk", block},
		{"SFXREV-nofollow-rel-link-star-ctl", "sed -i../.ssh/* s/x/y/ lnk", allow},
		{"SFXREV-nofollow-abs-link-plain-ctl", "sed -ikeys s/x/y/ alnk", allow},
		{"SFXREV-follow-missing", "sed --follow-symlinks -i.bak s/x/y/ nosuchfile", unresolved},
		// GAP-0542
		{"SFXREV-heredoc-bash", "bash <<'EOF'\nsed -i{keys}/* s/x/y/ authorized_keys\nEOF", block},
		{"SFXREV-pipe-bash", "echo 'sed -i{keys}/* s/x/y/ authorized_keys' | bash", block},
		{"SFXREV-cd-dash", "cd - && sed -i.ssh/* s/x/y/ authorized_keys", unresolved},
		{"SFXREV-cd-dyn", `cd "$D" && sed -i.ssh/* s/x/y/ authorized_keys`, unresolved},
		// GAP-0543
		{"SFXREV-perl-star", "perl -pi{keys}/* -e 1 authorized_keys", block},
		{"SFXREV-perl-star-rel", "perl -i../.ssh/* -pe 1 authorized_keys", block},
		{"SFXREV-perl-star-var", `perl -pi{keys}/* -e 1 "$F"`, unresolved},
		// Ordinary calls keep their verdict.
		{"SFXREV-B-ord-bak", "sed -i.bak s/x/y/ f", allow},
		{"SFXREV-B-ord-bsd-empty", "sed -i '' s/x/y/ f", allow},
		{"SFXREV-B-dyn-operand-bak", `sed -i.bak s/x/y/ "$F"`, allow},
		{"SFXREV-B-dyn-script", `sed -i "s/$A/$B/" f`, allow},
		{"SFXREV-B-cd-dyn-plain", `cd "$D" && sed -i.bak s/x/y/ f`, allow},
		{"SFXREV-B6", "find . -name '*.go' -exec sed -i 's/foo/bar/g' {} +", allow},
		{"SFXREV-B12", "git ls-files -z | xargs -0 sed -i 's/a/b/'", allow},
		{"SFXREV-B-perl-ord", "perl -pi.bak -e 1 f", allow},
		{"SFXREV-B-follow-ord", "sed --follow-symlinks -i.bak s/x/y/ lnk2", allow},
	}
	for _, tier := range boundedTestTiers {
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		floor := bounded.Unknown(tier.tier)
		for _, tc := range cases {
			command := strings.NewReplacer("{keys}", keys, "{home}", env.home).Replace(tc.command)
			action, findings := boundedDecideClaudeCode(t, api, env, boundedShellCommand(command))
			got := boundedParse(action)
			switch tc.want {
			case block:
				if got != bounded.Block {
					t.Errorf("%s in tier %s: action = %q, want block", tc.id, tier.name, action)
				}
			case unresolved:
				if got < floor {
					t.Errorf("%s in tier %s: action = %q, want at least %s (the unknown tier); findings=%v", tc.id, tier.name, action, floor, findings)
				}
				if !boundedHasLimit(findings, bounded.Paths, true) && got < bounded.Block {
					t.Errorf("%s in tier %s: no evaluation-limit finding naming the cap: %v", tc.id, tier.name, findings)
				}
			default:
				if action != "allow" {
					t.Errorf("%s in tier %s: action = %q, want allow; findings=%v", tc.id, tier.name, action, findings)
				}
			}
		}
	}
}
