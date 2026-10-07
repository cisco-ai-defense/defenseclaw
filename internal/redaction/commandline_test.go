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
	"unicode/utf8"
)

func TestCommandLineRedactsSecrets(t *testing.T) {
	got := CommandLine([]string{"node", "cli.js", "--api-key", "dccert-block-marker", "--token=dccertvalue",
		"PASSWORD=dccertvalue", "dccert0123456789dccert0123456789", "/sandbox/work/a-very-long-path-name-0123456789/x", "plain"}, 1024)
	for _, leak := range []string{" dccert-block-marker", "=dccertvalue", "dccert0123456789dccert0123456789"} {
		if strings.Contains(got, leak) {
			t.Fatalf("cmdline %q keeps %q", got, leak)
		}
	}
	for _, kept := range []string{"node cli.js --api-key <redacted", "--token=<redacted", "PASSWORD=<redacted", "/sandbox/work/a-very-long-path-name-0123456789/x", "plain"} {
		if !strings.Contains(got, kept) {
			t.Fatalf("cmdline %q lacks %q", got, kept)
		}
	}
	// Passwords in URLs, in user:password arguments and attached to a
	// MySQL client's -p.
	for _, argv := range [][]string{
		{"curl", "-u", "dccertuser:dccertpass", "https://example.invalid/"},
		{"curl", "--user=dccertuser:dccertpass", "https://example.invalid/"},
		{"git", "clone", "https://dccertuser:dccertpass@example.invalid/r.git"},
		{"psql", "postgresql://dccert:dccertpass@db.invalid/x"},
		{"/usr/bin/mysql", "-udccert", "-pdccertpass"},
	} {
		got := CommandLine(argv, 1024)
		if strings.Contains(got, "dccertpass") || !strings.Contains(got, "dccert") || !strings.Contains(got, "<redacted") {
			t.Fatalf("cmdline %q of %q keeps the password", got, argv)
		}
	}
	// Look-alikes stay as they are.
	for _, argv := range [][]string{
		{"python3", "-u", "main.py"}, {"ssh", "-p", "2222", "host"}, {"tar", "-pxf", "a.tar"},
		{"curl", "https://example.invalid:8443/path"}, {"psql", "-U", "dccert"},
	} {
		if got := CommandLine(argv, 1024); got != strings.Join(argv, " ") {
			t.Fatalf("cmdline %q of %q", got, argv)
		}
	}
}

func TestCommandLineBound(t *testing.T) {
	if long := CommandLine([]string{strings.Repeat("a ", 2000)}, 1024); len(long) > 1024 {
		t.Fatalf("cmdline of %d bytes", len(long))
	}
	// The cut never splits a UTF-8 sequence.
	got := CommandLine([]string{strings.Repeat("é", 600)}, 1023)
	if len(got) > 1023 || !utf8.ValidString(got) {
		t.Fatalf("cut to %d bytes, valid %v", len(got), utf8.ValidString(got))
	}
	if whole := strings.Repeat("x", 5000); CommandLine([]string{whole}, 0) != whole {
		t.Fatal("max 0 bounded the line")
	}
}
