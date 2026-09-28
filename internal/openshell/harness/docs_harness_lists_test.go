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

package harness

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
)

var (
	docsCodeSpanRE      = regexp.MustCompile("`([^`]+)`")
	docsConnectorLinkRE = regexp.MustCompile(`\(/docs/connectors/([a-z0-9-]+)#`)
)

// TestDocsListEveryHarness keeps the prose harness lists in step with the
// registry (the capability matrix is checked by
// TestDocsCapabilityMatrixSandboxColumn): the contributor guide's build
// status, the sandbox CLI reference's harness names and the connectors
// overview each name every registered harness and no other, and say which
// ones are unverified.
func TestDocsListEveryHarness(t *testing.T) {
	var names, commands, unverified, verified []string
	unverifiedDisplay := map[string]bool{}
	for _, name := range Names() {
		spec, _ := Get(name)
		names = append(names, name)
		commands = append(commands, spec.Command)
		if spec.Verification().Status == Unverified {
			unverified = append(unverified, name)
			unverifiedDisplay[spec.DisplayName] = true
		} else {
			verified = append(verified, name)
		}
	}

	// docs/SANDBOX.md: "`a`, `b` ... have harness specs and sandbox
	// artifacts. The `x` and `y` images stay unverified ...".
	bullet := docsBullet(t, docsFile(t, "docs", "SANDBOX.md"), "- **Harnesses.**")
	listed, rest, ok := strings.Cut(bullet, "have harness specs")
	unverifiedPart, _, ok2 := strings.Cut(rest, "images stay unverified")
	if !ok || !ok2 {
		t.Fatalf("docs/SANDBOX.md: the Harnesses bullet no longer reads \"... have harness specs ... images stay unverified\":\n%s", bullet)
	}
	docsSameSet(t, "docs/SANDBOX.md harnesses", docsCodeSpans(listed), names)
	docsSameSet(t, "docs/SANDBOX.md unverified harnesses", docsCodeSpans(unverifiedPart), unverified)

	// The CLI reference: "named by the command you type (`a`, `b`, ...)",
	// and a sentence naming the unverified harnesses by display name.
	bullet = docsBullet(t, docsFile(t, "docs-site", "content", "docs", "reference", "sandbox-cli.mdx"), "- **Harness names.**")
	_, afterOpen, ok := strings.Cut(bullet, "the command you type (")
	typed, _, ok2 := strings.Cut(afterOpen, ")")
	if !ok || !ok2 {
		t.Fatalf("sandbox-cli.mdx: the Harness names bullet no longer lists \"the command you type (...)\":\n%s", bullet)
	}
	docsSameSet(t, "sandbox-cli.mdx harness commands", docsCodeSpans(typed), commands)
	head, _, ok := strings.Cut(bullet, " not verified end to end")
	if !ok {
		t.Fatalf("sandbox-cli.mdx: the Harness names bullet no longer says which harnesses are \"not verified end to end\":\n%s", bullet)
	}
	sentence := head[strings.LastIndex(head, ". ")+1:]
	for _, name := range Names() {
		spec, _ := Get(name)
		if named := strings.Contains(sentence, spec.DisplayName); named != unverifiedDisplay[spec.DisplayName] {
			t.Errorf("sandbox-cli.mdx: %s is unverified=%v, but the not-verified sentence names it=%v: %q",
				spec.DisplayName, unverifiedDisplay[spec.DisplayName], named, sentence)
		}
	}

	// The connectors overview links each harness's sandbox section, in
	// "Run today" or "Cannot run yet".
	index := docsFile(t, "docs-site", "content", "docs", "connectors", "index.mdx")
	docsSameSet(t, "connectors overview: run today", docsLinkedConnectors(docsBullet(t, index, "- **Run today:**")), verified)
	docsSameSet(t, "connectors overview: cannot run yet", docsLinkedConnectors(docsBullet(t, index, "- **Cannot run yet:**")), unverified)
}

// docsFile reads a file by its path from the repository root.
func docsFile(t *testing.T, elem ...string) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	path := filepath.Join(append([]string{filepath.Dir(filename), "..", "..", ".."}, elem...)...)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// docsBullet returns the top-level list item that starts with prefix,
// joined with its indented continuation lines.
func docsBullet(t *testing.T, text, prefix string) string {
	t.Helper()
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		out := []string{line}
		for _, next := range lines[i+1:] {
			if !strings.HasPrefix(next, "  ") {
				break
			}
			out = append(out, strings.TrimSpace(next))
		}
		return strings.Join(out, " ")
	}
	t.Fatalf("no list item starting %q", prefix)
	return ""
}

func docsCodeSpans(s string) []string {
	var out []string
	for _, m := range docsCodeSpanRE.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	return out
}

func docsLinkedConnectors(s string) []string {
	var out []string
	for _, m := range docsConnectorLinkRE.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	return out
}

// docsSameSet reports the names a docs list lacks and the ones it has that
// the registry does not.
func docsSameSet(t *testing.T, what string, got, want []string) {
	t.Helper()
	for _, w := range want {
		if !slices.Contains(got, w) {
			t.Errorf("%s: missing %s (listed: %q)", what, w, got)
		}
	}
	for _, g := range got {
		if !slices.Contains(want, g) {
			t.Errorf("%s: %s is not in the registry's list %q", what, g, want)
		}
	}
}
