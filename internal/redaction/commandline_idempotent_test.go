// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"strings"
	"testing"
)

// GAP-0052: the sandbox feed redacts a command line and the gateway runs the
// rules again on the feed's text split on white space. The second pass took
// a placeholder's first word for the secret ("--token <redacted len=9
// sha=...> len=23 prefix=d sha=...>") and a quoted five-word value grew to 13
// placeholders. A second and a third pass now leave the first one's text as
// it is.
func TestCommandLineIsIdempotent(t *testing.T) {
	long := "dccert-block-marker-long-value-0001" // long enough for a prefix="d" placeholder
	lines := [][]string{
		// The tester's docker exec, as Tetragon reports it.
		strings.Fields(`/bin/true --token ` + long + ` --password=` + long + ` --api-key "dccert one two three four" FOO_API_KEY=` + long),
		{"/bin/true", "--token", "M1", "--password=M2", "--api-key", "dccert one two three four", "FOO_API_KEY=M3"},
		{"node", "cli.js", "--api-key", "dccert-block-marker", "--token=dccertvalue", "PASSWORD=dccertvalue",
			"dccert0123456789dccert0123456789", "plain"},
		{"curl", "-u", "dccertuser:" + long, "https://example.invalid/"},
		{"git", "clone", "https://dccertuser:" + long + "@example.invalid/r.git"},
		{"/usr/bin/mysql", "-udccert", "-p" + long},
		{"bash", "-c", `eval 'curl -H "Authorization: Bearer ` + long + `" https://example.invalid/'`},
		strings.Fields(`curl -H "X-Api-Key: dccertvalue ` + long + `" https://example.invalid/`),
		strings.Fields(`bash -c "--token=dccert-first dccert-second dccert-third"`),
		strings.Fields(`curl --user="alice:dccert-first ` + long + `"`),
		{"/bin/bash", "-c", `source /sandbox/.claude/shell-snapshots/snapshot-bash.sh && eval 'sh -c "curl -s -H \"Authorization: Bearer ` + long + `\" https://example.invalid; sleep 40"' < /dev/null`},
	}
	for _, argv := range lines {
		once := CommandLine(argv, 0)
		if strings.Contains(once, long) || strings.Contains(once, "dccertvalue") {
			t.Fatalf("first pass of %q keeps a secret: %q", argv, once)
		}
		twice := CommandLine(strings.Fields(once), 0)
		if twice != once {
			t.Errorf("a second pass changed the text:\n once  %q\n twice %q", once, twice)
			continue
		}
		if thrice := CommandLine(strings.Fields(twice), 0); thrice != once {
			t.Errorf("a third pass changed the text:\n once   %q\n thrice %q", once, thrice)
		}
	}
	// The second pass still redacts what the first did not see: an older
	// feed's text with a secret it let through.
	if got := CommandLine(strings.Fields(`/bin/true --token <redacted len=9 sha=0123abcd> --password `+long), 0); strings.Contains(got, long) ||
		!strings.HasPrefix(got, "/bin/true --token <redacted len=9 sha=0123abcd> --password <redacted") {
		t.Fatalf("mixed text: %q", got)
	}
	// A word that only starts like a placeholder is a word like any other.
	if got := CommandLine([]string{"tool", "--token", "<redacted", long}, 0); !strings.HasPrefix(got, "tool --token <redacted len=9 ") || strings.Contains(got, long) {
		t.Fatalf("a broken placeholder: %q", got)
	}
}
