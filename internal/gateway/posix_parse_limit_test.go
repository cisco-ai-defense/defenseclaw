// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// A POSIX call whose analysis stops at a byte bound is TRUNCATED when the
// bound hides code the local shell runs (rel-1-0-10:GAP-0382): an alert in
// the default and permissive packs (a managed install's included), a block in
// the strict pack, never an allow. A word past the bound that the local shell
// only passes on to a program is DATA: the call keeps the verdict of its twin
// (the same call with the word shortened) and the word leaves a
// detection-only record. The row ids are the case ids of the proof.
func TestPosixInputBytesAreTruncatedInEveryTier(t *testing.T) {
	word := func(n int) string { return strings.Repeat("a", n) }
	type row struct {
		id, command string
		truncated   bool
	}
	rows := []row{
		// Just under the word bound is read in full; over it, the position decides.
		{"word-under-4096", "eval " + word(4096), false},
		{"code-eval-word-over-4097", "eval " + word(4097), true},
		{"code-eval-words-several-over", "eval " + word(5000) + " " + word(6000) + " " + word(7000), true},
		{"code-word-over-in-pipeline", "true | eval " + word(4097) + " | cat", true},
		{"code-sh-c-body", "sh -c '" + word(4200) + "'", true},
		{"code-bash-c-nested-echo", "bash -c 'echo " + word(4200) + "'", true},
		{"code-source-word", "source " + word(4200), true},
		{"code-env-sh-c", "env FOO=1 sh -c '" + word(4200) + "'", true},
		{"code-sudo-sh-c", "sudo sh -c '" + word(4200) + "'", true},
		{"code-timeout-wraps-sh-c", "timeout 5 sh -c '" + word(4200) + "'", true},
		{"code-python-c", "python3 -c '" + word(4200) + "'", true},
		{"code-node-e", "node -e '" + word(4200) + "'", true},
		{"code-perl-e", "perl -e '" + word(4200) + "'", true},
		{"code-awk-program", "awk '" + word(4200) + "' file", true},
		{"code-xargs-command", "xargs " + word(4200), true},
		{"code-command-name", word(4200) + " arg", true},
		{"code-redirect-target", "echo hi > /tmp/" + word(4200), true},
		{"code-ssh-option-before-destination", "ssh -o 'ProxyCommand=" + word(4200) + "' host true", true},
		{"code-timeout-own-operand", "timeout " + word(4200) + " true", true},
		{"code-data-and-code-mixed", "dcx - '" + word(4200) + "'; sh -c '" + word(4200) + "'", true},
		{"code-call-over-64k-many-words", "echo" + strings.Repeat(" "+word(2000), 33), true},
		{"code-heredoc-call-over-64k", "cat <<EOF\n" + word(70000) + "\nEOF\n", true},
		{"code-word-over-256k", "eval " + word(262144+5), true},
		// A command named through a variable is read by the program the text
		// shows it to be; one the text does not show stays unknown.
		{"code-variable-name-unbound", "$CMD - '" + word(4200) + "'", true},
		{"code-variable-name-is-a-shell", "S=/bin/sh; $S -c '" + word(4200) + "'", true},
		{"code-variable-name-rebound", "D=/opt/tools/dcx; read D; $D - '" + word(4200) + "'", true},
		{"code-variable-name-set-twice", "D=/opt/tools/dcx; D=/bin/sh; $D -c '" + word(4200) + "'", true},
		{"code-redirect-target-after-quote-slip", "dcx - '" + word(100) + "'oops <in>'" + word(4200) + "'", true},
		{"code-word-over-before-seen-write", "eval " + word(4097) + "; " + boundedShellSeen, true},
		// DATA: the plain operand of a program that runs it elsewhere, or none.
		{"data-dcx-quoted-script", "dcx - '" + word(4200) + "'", false},
		{"data-ssh-remote-script", "ssh host '" + word(4200) + "'", false},
		{"data-ssh-options-then-remote-script", "ssh -p 22 -i key host '" + word(4200) + "'", false},
		{"data-docker-exec-sh-c", "docker exec c sh -c '" + word(4200) + "'", false},
		{"data-echo-word", "echo " + word(4200), false},
		{"data-echo-words-several", "echo " + word(5000) + " " + word(6000), false},
		{"data-double-quoted", "dcx - \"" + word(4200) + "\"", false},
		{"data-flag-attached", "dcx --script='" + word(4200) + "'", false},
		{"data-command-in-variable", "D=/opt/tools/dcx; $D - '" + word(4200) + "'", false},
		{"data-command-in-quoted-variable", "D=/opt/tools/dcx; \"$D\" - '" + word(4200) + "'", false},
		{"data-command-in-variable-directory", "K=/opt/tools; $K/dcx - '" + word(4200) + "'", false},
		{"data-wrapped-by-timeout", "timeout 5 dcx - '" + word(4200) + "'", false},
		{"data-command-substitution", "echo $(dcx - '" + word(4200) + "')", false},
		{"data-in-pipeline", "dcx - '" + word(4200) + "' | cat", false},
		{"data-two-words-two-calls", "dcx - '" + word(4200) + "'; ssh host '" + word(4200) + "'", false},
		{"data-whitespace-padded-call-over-64k", "echo ok" + strings.Repeat(" ", 70000), true}, // past MaxCommandBytes: the psf2 byte floor (GAP-0611, GAP-0748)
		{"data-heredoc-body-over-4k-is-not-a-word", "cat <<EOF\n" + word(8000) + "\nEOF\n", false},
		{"data-word-then-seen-write", "dcx - '" + word(4200) + "'; " + boundedShellSeen, false},
		{"data-seen-write-then-word", boundedShellSeen + "; dcx - '" + word(4200) + "'", false},
		{"data-in-sh-c-body-under-4k-stays-read", "sh -c 'dcx x " + word(300) + "'", false},
	}
	env := boundedLaneEnv(t)
	for _, tier := range boundedTestTiers {
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		floor := bounded.Unknown(tier.tier)
		for _, r := range rows {
			action, findings := boundedDecideClaudeCode(t, api, env, boundedShellCommand(r.command))
			limited := boundedHasLimit(findings, bounded.Bytes, true)
			isWrite := strings.Contains(r.command, boundedShellSeen)
			switch {
			case r.truncated:
				if !limited {
					t.Errorf("%s/%s: not truncated (action %s, findings %v)", tier.name, r.id, action, findings)
				}
				if boundedParse(action) < floor {
					t.Errorf("%s/%s: action %s is below the unknown tier %s", tier.name, r.id, action, floor)
				}
			case isWrite:
				// A proven write beside a data word keeps its tier verdict
				// (alert, block in strict).
				if boundedParse(action) != gap0747StateWriteAction(tier.tier) {
					t.Errorf("%s/%s: a proven write beside a data word must be %s, got %s", tier.name, r.id, gap0747StateWriteAction(tier.tier), action)
				}
			default:
				if strings.HasPrefix(r.id, "data-") && boundedParse(action) != bounded.Allow &&
					r.id != "data-in-sh-c-body-under-4k-stays-read" {
					t.Errorf("%s/%s: a data word keeps the verdict of its twin (allow), got %s (%v)", tier.name, r.id, action, findings)
				}
				if r.id == "word-under-4096" && limited {
					t.Errorf("%s/%s: a word under the bound is read in full (%v)", tier.name, r.id, findings)
				}
			}
			if r.id == "code-word-over-before-seen-write" && boundedParse(action) != gap0747StateWriteAction(tier.tier) {
				t.Errorf("%s/%s: a proven write before the bound must keep its verdict %s, got %s", tier.name, r.id, gap0747StateWriteAction(tier.tier), action)
			}
		}
	}
}

// A data word leaves a detection-only record: the finding names the cap and
// the call is not raised by it.
func TestPosixDataWordLeavesADetectionOnlyRecord(t *testing.T) {
	env := boundedLaneEnv(t)
	command := "dcx - '" + strings.Repeat("a", 4200) + "'"
	for _, tier := range boundedTestTiers {
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		action, findings := boundedDecideClaudeCode(t, api, env, boundedShellCommand(command))
		if boundedParse(action) != bounded.Allow {
			t.Errorf("%s: a data word raised the call to %s (%v)", tier.name, action, findings)
		}
	}
}

// A count bound is not a byte bound: a statement of more argv words than the
// analysis keeps stays with the operand bound.
func TestShellInputPastByteBoundIgnoresCounts(t *testing.T) {
	if actionfacts.ShellInputPastByteBound("ls"+strings.Repeat(" ox", 600), 0) {
		t.Fatal("600 short words are a count, not a byte bound")
	}
	if !actionfacts.ShellInputPastByteBound("echo "+strings.Repeat("a", 4097), 0) {
		t.Fatal("a word of 4097 bytes is past the word bound")
	}
}

// The detection-only record a data word leaves is not a cap
// (rel-1-0-10:GAP-0760): only an enforcing cap or a truncated reading makes a
// call capped. boundedLimitIndex skips the record, so no cap logic (the cap
// floor of s7/cap-floor counts any limit finding there as a cap the call hit,
// then judges its pieces and reports the piece it leaves unjudged) reads it
// as one, and a real cap of the call adds its own enforcing finding instead of
// raising the record. Merged with the cap floor before this, the owner
// traces moved 215 calls (a dcx script word naming a state path beside
// another statement or behind a variable) from allow to the unknown tier.
func TestPosixDataWordRecordIsNotACap(t *testing.T) {
	record := withPosixDataWordRecord(nil)
	if len(record) != 1 || !record[0].boundRecord || record[0].contributesToEnforcement() {
		t.Fatalf("want one detection-only data-word record, got %+v", record)
	}
	if guardrailSeverityRank(record[0].Severity) != severityNone {
		t.Fatalf("the data-word record carries severity %s onto an allowed call", record[0].Severity)
	}
	if boundedLimitIndex(record) != -1 {
		t.Fatal("the data-word record counts as a limit the call hit")
	}
	if again := withPosixDataWordRecord(record); len(again) != 1 {
		t.Fatalf("a second record was added: %v", FindingStrings(again))
	}
	for _, tier := range boundedTestTiers {
		strictPack := tier.tier == bounded.TierStrict
		request := trustedActionRequest{StrictPolicy: strictPack, ManagedInstall: tier.managed, EnforcementCapable: true}
		capped := withBoundedTruncation(record, bounded.Of(bounded.Bytes), request)
		records, caps := 0, 0
		for _, f := range capped {
			switch {
			case f.boundRecord:
				records++
				if f.contributesToEnforcement() || f.contributesToAlertOnly() || f.Title != posixDataWordTitle {
					t.Errorf("%s: a real cap raised the record: %+v", tier.name, f)
				}
			case f.RuleID == evaluationLimitRuleID:
				caps++
			}
		}
		if records != 1 || caps != 1 {
			t.Errorf("%s: %d records and %d cap findings, want 1 and 1 (%v)", tier.name, records, caps, FindingStrings(capped))
		}
		got, _ := bounded.ParseAction(guardrailActionForProfile(capped, false, func() bool { return strictPack }, boundedTestActionFor))
		if got != bounded.Unknown(tier.tier) {
			t.Errorf("%s: a real cap beside the record is %s, want the unknown tier %s", tier.name, got, bounded.Unknown(tier.tier))
		}
	}

	// End to end, the call shapes of the owner traces: a data word whose text
	// names a state or profile path, beside other statements or behind a
	// variable command path, keeps the verdict of its twin in every tier; a
	// here-document beside it is code and stays truncated.
	env := boundedLaneEnv(t)
	pad := strings.Repeat("a", 5000)
	names := "cat ~/.defenseclaw/config.yaml; " + pad
	rows := []struct {
		id, command string
		truncated   bool
	}{
		{"data-dcx-names-state", "dcx - '" + names + "'", false},
		{"data-dcx-names-profile", "dcx - 'grep -n PATH ~/.zprofile ~/.bashrc; " + pad + "'", false},
		{"data-var-dcx-names-state", "K=/opt/x\n\"$K\"/dcx - '" + names + "'", false},
		{"data-dcx-names-state-beside-statements", "ls; dcx - '" + names + "'; echo done", false},
		{"data-ssh-names-state", "ssh host '" + names + "'", false},
		{"code-heredoc-beside-data-word", "cat > f <<'E'\n" + names + "\nE\ndcx - '" + pad + "'", true},
	}
	for _, tier := range boundedTestTiers {
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		for _, r := range rows {
			action, findings := boundedDecideClaudeCode(t, api, env, boundedShellCommand(r.command))
			want := bounded.Allow
			if r.truncated {
				want = bounded.Unknown(tier.tier)
			}
			if got := boundedParse(action); got != want {
				t.Errorf("%s/%s: %s, want %s (%v)", tier.name, r.id, got, want, findings)
			}
		}
	}
}

// The bound-rule lane of the POSIX byte bounds (TestBoundRuleEveryLaneCap),
// registered here so it stays with this lane when the property test is split.
func init() {
	registerBoundedLane(
		// The byte bounds of the analysis (a word past 4 KiB, the call past
		// 64 KiB, the arguments past 256 KiB) end the POSIX analysis with
		// limit_exceeded/input_limit and no command: the call is truncated,
		// never a clean allow (rel-1-0-10:GAP-0382).
		boundedLaneCap{lane: "shell-parse input bytes", cap: bounded.Bytes, limit: analysisLimit(boundedOneWord, 1<<20),
			gen:  boundedShellLane(boundedOneWord, boundedWordThenStatements),
			seen: boundedShellSeenCall},
	)
}

// boundedOneWord is one literal word of size bytes.
func boundedOneWord(size int) string { return "eval " + strings.Repeat("a", size) }

// boundedWordThenStatements is the multi-cap shape of the input bytes lane:
// the oversize word comes first, because the analysis stops at the first
// limit it meets (behind a list of statements past its fact limit it never
// reaches the word), then a list of statements past the statement budget.
func boundedWordThenStatements(size int) string {
	return boundedOneWord(size) + "; " + gap0568Assignments(2*boundedShellStatements)
}

// analysisLimit is the largest size up to max for which the analysis of the
// call of fill reads it to the end (no limit status).
func analysisLimit(fill func(int) string, max int) int {
	for low, high := 1, max; ; {
		if low >= high {
			return low
		}
		mid := (low + high + 1) / 2
		args, _ := json.Marshal(map[string]string{"command": fill(mid)})
		if actionfacts.Analyze(actionfacts.Input{Tool: "Bash", Args: args}).Parse.Status != actionfacts.StatusLimitExceeded {
			low = mid
		} else {
			high = mid - 1
		}
	}
}
