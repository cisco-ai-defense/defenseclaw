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
	env, keys := sedBackupBoundEnv(t)
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
		// The keys folder rule blocks this one too (GAP-0669).
		{"SFXREV-nofollow-rel-link-star-ctl", "sed -i../.ssh/* s/x/y/ lnk", block},
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
	runSedBackupTierRows(t, env, keys, cases)
}

// runSedBackupTierRows judges each row in the five tiers: block is a block,
// unresolved is at least the unknown tier of the pack with the evaluation-limit
// finding, allow is an allow.
func runSedBackupTierRows(t *testing.T, env boundedEnv, keys string, cases []struct{ id, command, want string }) {
	t.Helper()
	const (
		allow      = "allow"
		block      = "block"
		unresolved = "unresolved"
	)
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

// sedBackupBoundEnv is the fixture of the tier rows: the keys folder with a
// decoy backup target, a project folder with the files and links the rows use.
func sedBackupBoundEnv(t *testing.T) (boundedEnv, string) {
	t.Helper()
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
	return env, keys
}

// TestBoundRuleSedBackupBoundRows: the rows of the second review of
// s7/sedbak-bound (s7-sbrev; rel-1-0-10:GAP-0667, GAP-0668, GAP-0669,
// GAP-0670) in all five tiers. A backup the words name in full that reaches a
// protected file blocks whatever the spelling of the program word; one the
// reader cannot name in full is at least the unknown tier of the pack; the
// ordinary call is unchanged. The rows of the GAP-0667 spellings name the
// keys folder by a relative path, so no row has the text sed or perl in it.
func TestBoundRuleSedBackupBoundRows(t *testing.T) {
	env, keys := sedBackupBoundEnv(t)
	const (
		allow      = "allow"
		block      = "block"
		unresolved = "unresolved"
	)
	runSedBackupTierRows(t, env, keys, []struct{ id, command, want string }{
		// GAP-0667
		{"SFXREV-split-prog", "s''ed -i../.ssh/* s/x/y/ authorized_keys", block},
		{"SBREV2-split-sed", "s''ed -i{keys}/* s/x/y/ authorized_keys", block},
		{"SBREV2-bs-sed", `s\ed -i../.ssh/* s/x/y/ authorized_keys`, block},
		{"SBREV2-dq-sed", `"s"ed -i../.ssh/* s/x/y/ authorized_keys`, block},
		{"SBREV2-split-gsed", "gs''ed -i../.ssh/* s/x/y/ authorized_keys", block},
		{"SBREV2-split-perl", "p''erl -pi../.ssh/* -e 1 authorized_keys", block},
		{"SBREV2-split-sed-unres", `s''ed -i"$X" s/x/y/ authorized_keys`, unresolved},
		{"SBREV2-split-sed-envC", "env -C {home} s''ed -i.ssh/* s/x/y/ authorized_keys", block},
		{"SBREV2-split-sed-xargs", "echo authorized_keys | xargs s''ed -i../.ssh/* s/x/y/", unresolved},
		{"SBREV2-C-split-sed-bak", "s''ed -i.bak s/x/y/ f", allow},
		// GAP-0668
		{"SBREV-xargs-maxargs-sep", "echo authorized_keys | xargs --max-args 1 sed -i{keys}/* s/x/y/", unresolved},
		{"SBREV-xargs-delim-sep", "echo authorized_keys | xargs --delimiter , sed -i{keys}/* s/x/y/", unresolved},
		{"SBREV-xargs-bsd-J", "echo authorized_keys | xargs -J % sed -i{keys}/* s/x/y/ %", unresolved},
		{"SBREV-xargs-cluster", "echo authorized_keys | xargs -0rn1 sed -i{keys}/* s/x/y/", unresolved},
		{"SBREV-xargs-unknown-option", "echo authorized_keys | xargs --no-such-option 3 sed -i{keys}/* s/x/y/", unresolved},
		{"SBREV-C-xargs-maxargs", "echo f | xargs --max-args 1 sed -i.bak s/x/y/", allow},
		{"SBREV-C-xargs-bsd-J", "echo f | xargs -J % sed -i.bak s/x/y/ %", allow},
		// GAP-0669
		{"SBREV-brace-suffix", "sed -i{.bak,{keys}/*} s/x/y/ authorized_keys", block},
		{"SBREV-brace-suffix-first", "sed -i{{keys}/*,.bak} s/x/y/ authorized_keys", allow},
		{"SBREV-brace-option-word", "sed {-n,-i{keys}/*} s/x/y/ authorized_keys", block},
		{"SBREV-brace-overflow-suffix", "sed -i{.bak,x}{1..999} s/x/y/ f", unresolved},
		{"SBREV-brace-overflow-option", "sed {-i,-n}{1..999} s/x/y/ f", unresolved},
		{"SBREV-C-brace-suffix-plain", "sed -i{.bak,.orig} s/x/y/ f", allow},
		{"SBREV-C-brace-operand-overflow", "sed -i.bak s/x/y/ file{1..999}", allow},
		// GAP-0670
		{"SBREV-heredoc-dev-stdin", "bash /dev/stdin <<'EOF'\nsed -i{keys}/* s/x/y/ authorized_keys\nEOF", block},
		{"SBREV-source-stdin", "source /dev/stdin <<'EOF'\nsed -i{keys}/* s/x/y/ authorized_keys\nEOF", block},
		{"SBREV-pipe-chain", "echo 'sed -i{keys}/* s/x/y/ authorized_keys' | cat | bash", block},
		{"SBREV-pipe-block", "{ echo 'sed -i{keys}/* s/x/y/ authorized_keys'; } | bash", block},
		{"SBREV-perl-versioned", "perl5.38.2 -pi{keys}/* -e 1 authorized_keys", block},
		{"SBREV-sudo-D", "sudo -D {home} sed -i.ssh/* s/x/y/ authorized_keys", block},
		{"SBREV-sudo-chdir", "sudo --chdir={home} sed -i.ssh/* s/x/y/ authorized_keys", block},
		{"SBREV-cd-tilde-minus", "cd ~- && sed -i.ssh/* s/x/y/ authorized_keys", unresolved},
		{"SBREV-func-args", `f(){ sed "$@"; }; f -i{keys}/* s/x/y/ authorized_keys`, unresolved},
		{"SBREV-C-func-args-inplace", `f(){ sed -i.bak "$@"; }; f s/x/y/ file`, allow},
		{"SBREV-C-pipe-chain-ord", "echo 'sed -i.bak s/x/y/ f' | cat | bash", allow},
		{"SBREV-C-heredoc-dev-stdin-ord", "bash /dev/stdin <<'EOF'\nsed -i.bak s/x/y/ f\nEOF", allow},
	})
}
