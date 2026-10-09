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

// GAP-0062: a word that held placeholder-shaped text next to a secret
// ("--secret=VALUE<redacted len=1 sha=abcd1234>") was left as it was, so the
// value reached the process tree, the audit log and telemetry. Only a value
// that is nothing but placeholders is already redacted; text next to one goes
// through the rules, in an argument vector and in a text line split on white
// space alike.
func TestCommandLineRedactsTextNextToAPlaceholder(t *testing.T) {
	const fake = "<redacted len=1 sha=abcd1234>"
	cases := []struct {
		argv   []string
		secret string
	}{
		{[]string{"/bin/true", "--secret=dccert-smuggle-secret-AAAA1111" + fake}, "AAAA1111"},
		{[]string{"/bin/true", "SMUGGLE_API_KEY=dccert-smuggle-secret-BBBB2222" + fake}, "BBBB2222"},
		{[]string{"/bin/true", "--token", "dccert-smuggle-secret-CCCC3333 " + fake}, "CCCC3333"},
		{[]string{"git", "clone", "https://dccertuser:dccert-smuggle-secret-DDDD4444" + fake + "@example.invalid/r.git"}, "DDDD4444"},
		{[]string{"curl", "-u", "dccertuser:dccert-smuggle-secret-EEEE5555" + fake, "https://example.invalid/"}, "EEEE5555"},
		{[]string{"/usr/bin/mysql", "-udccert", "-pdccert-smuggle-secret-FFFF6666" + fake}, "FFFF6666"},
		{[]string{"tool", "dccert0123456789dccert0123GGGG7777" + fake}, "GGGG7777"},
		{[]string{"/bin/bash", "-c", "eval '/bin/true --secret=dccert-smuggle-secret-HHHH8888" + fake + "'"}, "HHHH8888"},
		{[]string{"curl", "-H", "Authorization: Bearer dccert-smuggle-secret-JJJJ9999" + fake}, "JJJJ9999"},
	}
	for _, c := range cases {
		for _, argv := range [][]string{c.argv, strings.Fields(strings.Join(c.argv, " "))} {
			once := CommandLine(argv, 0)
			if strings.Contains(once, c.secret) {
				t.Errorf("%q keeps the secret next to a placeholder: %q", argv, once)
				continue
			}
			if twice := CommandLine(strings.Fields(once), 0); twice != once {
				t.Errorf("a second pass changed the text:\n once  %q\n twice %q", once, twice)
			}
		}
	}
	// GAP-0064: an argument of several words with a placeholder in it
	// panicked (index out of range in redactWords).
	for _, script := range []string{
		"eval '/bin/true --secret=X" + fake + "'",
		"echo " + fake + " " + fake + " done",
		"echo <redacted  len=1 sha=abcd1234> done",
		"echo <redacted len=1 sha=abcd1234 done",
	} {
		_ = CommandLine([]string{"/bin/bash", "-c", script}, 0)
		_ = CommandLine(strings.Fields("/bin/bash -c "+script), 0)
	}
	// A key, a flag's value or a user's password that is only a placeholder
	// is already redacted and stays as it is.
	for _, line := range []string{
		"/bin/true --token=" + fake,
		"/bin/true --api-key " + fake,
		"curl -u dccertuser:" + fake + " https://example.invalid/",
		"git clone https://dccertuser:" + fake + "@example.invalid/r.git",
		"/usr/bin/mysql -p" + fake,
		fake,
	} {
		if got := CommandLine(strings.Fields(line), 0); got != line {
			t.Errorf("an already redacted line changed:\n in  %q\n out %q", line, got)
		}
	}
}

// FuzzCommandLine: no command line makes the redaction panic, as an argument
// vector or as a text line split on white space (GAP-0064).
func FuzzCommandLine(f *testing.F) {
	for _, s := range []string{
		"eval '/bin/true --secret=X<redacted len=1 sha=abcd1234>'",
		"--token <redacted len=23 prefix=\"d\" sha=5f84a2a8> x",
		"echo <redacted  len=1 sha=abcd1234> <redacted len=5>",
		"curl -H \"Authorization: Bearer <redacted len=9 sha=0123abcd>\" https://u:<redacted len=3>@h/",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_ = CommandLine([]string{"/bin/bash", "-c", s}, 0)
		_ = CommandLine(strings.Fields(s), 0)
	})
}
