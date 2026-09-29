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

package image

import (
	"fmt"
	"strings"
	"testing"
)

// TestOutputTailIsBounded: whatever docker writes, and in whatever pieces,
// the tail is at most 40 whole lines and 8 KiB, and ends with the last
// line written.
func TestOutputTailIsBounded(t *testing.T) {
	for name, write := range map[string]func(tail *outputTail, data string){
		"one write":  func(tail *outputTail, data string) { _, _ = tail.Write([]byte(data)) },
		"odd pieces": writeInPieces(7),
		"lines":      writeInPieces(0),
	} {
		t.Run(name, func(t *testing.T) {
			var b strings.Builder
			for i := 1; i <= 3000; i++ {
				fmt.Fprintf(&b, "#%d step %d of the build é\n", i, i)
			}
			b.WriteString(strings.Repeat("x", 300) + "\nERROR: failed to build\n")
			tail := &outputTail{}
			write(tail, b.String())
			if len(tail.buf) > 2*buildTailBytes {
				t.Fatalf("the tail holds %d bytes", len(tail.buf))
			}
			got := tail.String()
			lines := strings.Split(got, "\n")
			if len(lines) > buildTailLines || len(got) > buildTailBytes || lines[len(lines)-1] != "ERROR: failed to build" {
				t.Fatalf("tail = %d lines, %d bytes, ending %q", len(lines), len(got), lines[len(lines)-1])
			}
			if !strings.HasPrefix(lines[0], "#") || !strings.HasSuffix(lines[0], "of the build é") {
				t.Fatalf("the tail starts with a fragment: %q", lines[0])
			}
		})
	}
	short := &outputTail{}
	_, _ = short.Write([]byte("\n\nstep 1\n\n  \nERROR: boom\n"))
	if got := short.String(); got != "step 1\nERROR: boom" {
		t.Fatalf("short tail = %q", got)
	}
}

// writeInPieces writes data n bytes at a time, or a line at a time for 0.
func writeInPieces(n int) func(*outputTail, string) {
	return func(tail *outputTail, data string) {
		for data != "" {
			k := n
			if n == 0 {
				k = strings.IndexByte(data, '\n') + 1
			}
			if k <= 0 || k > len(data) {
				k = len(data)
			}
			_, _ = tail.Write([]byte(data[:k]))
			data = data[k:]
		}
	}
}

// TestSafeOutput: terminal escapes and control characters are dropped,
// credential-shaped strings are redacted, and a build's ordinary output
// (digests, COPY lines, registry errors in prose) is kept as it is.
func TestSafeOutput(t *testing.T) {
	digest := "sha256:" + strings.Repeat("0123456789abcdef", 4)
	for _, tc := range []struct{ in, want string }{
		{"#7 [3/9] COPY --chown=1000:1000 --chmod=0755 files/usr/local/lib/defenseclaw/hooks/pre /usr/local/lib/defenseclaw/hooks/pre",
			"#7 [3/9] COPY --chown=1000:1000 --chmod=0755 files/usr/local/lib/defenseclaw/hooks/pre /usr/local/lib/defenseclaw/hooks/pre"},
		{"#3 resolve ghcr.io/nvidia/openshell-community/sandboxes/base@" + digest + " done",
			"#3 resolve ghcr.io/nvidia/openshell-community/sandboxes/base@" + digest + " done"},
		{"ERROR: failed to authorize: failed to fetch oauth token: unexpected status: 401 Unauthorized",
			"ERROR: failed to authorize: failed to fetch oauth token: unexpected status: 401 Unauthorized"},
		{"the --chmod option requires BuildKit. Refer to https://docs.docker.com/go/buildkit/ to learn how",
			"the --chmod option requires BuildKit. Refer to https://docs.docker.com/go/buildkit/ to learn how"},
		{"\x1b[31;1mERROR\x1b[0m: \x1b]8;;https://x.example\x07link\x1b]8;;\x07 done\a\x00", "ERROR: link done"},
		{"tab\there \u202eevil\u202c", "tab here evil"},
		{"GET https://bob:s3cretPassw0rd@registry.example/v2/", "GET https://bob:[redacted]@registry.example/v2/"},
		{"Authorization: Bearer abcdefABCDEF0123456789", "Authorization: Bearer [redacted]"},
		{"auth: Basic Ym9iOnMzY3JldA==", "auth: Basic [redacted]"},
		{"npm ERR! NPM_TOKEN=abc123def and GITHUB_TOKEN='ghp_" + strings.Repeat("a1", 18) + "'",
			"npm ERR! NPM_TOKEN=[redacted] and GITHUB_TOKEN='[redacted]'"},
		{"https://host/x?access_token=0123456789abcdef&page=2", "https://host/x?access_token=[redacted]&page=2"},
		{"key sk-ant-api03-" + strings.Repeat("Ab9_", 10) + " end", "key [redacted] end"},
		{"aws AKIAIOSFODNN7EXAMPLE end", "aws [redacted] end"},
		{"jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U end", "jwt [redacted] end"},
		{`"password": "Tr0ub4dor3xyzabcdefg"`, `"password": "[redacted]"`},
	} {
		if got := safeOutput(tc.in, buildTailLines); got != tc.want {
			t.Errorf("safeOutput(%q)\n got %q\nwant %q", tc.in, got, tc.want)
		}
	}
}
