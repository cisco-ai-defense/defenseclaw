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

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// The sandbox CLI reference page holds one generated block per command of
// the pinned `sandbox` tree (testdata/sandbox_commands.json): a flag table,
// or for a command group its subcommands. Everything else on the page is
// prose.
const (
	sandboxDocsPage       = "sandbox-cli.mdx"
	sandboxDocsBeginMark  = "{/* AUTOGEN-BEGIN: sandbox-flags "
	sandboxDocsMarkSuffix = " */}"
	sandboxDocsEndMark    = "{/* AUTOGEN-END: sandbox-flags */}"
)

// sandboxDocsSpecial are the characters MDX reads as markup in table text.
var sandboxDocsSpecial = regexp.MustCompile(`[<>{}$]`)

// sandboxDocsFlagValue describes what a flag takes, by its pflag type.
var sandboxDocsFlagValue = map[string]string{
	"bool":        "switch",
	"string":      "text",
	"int":         "number",
	"uint64":      "number",
	"stringArray": "text, repeatable",
	"stringSlice": "text, repeatable or comma-separated",
	"intSlice":    "port, repeatable or comma-separated",
}

// sandboxDocsText turns a cobra usage or short string into table text:
// a capital first letter, a closing period, pipes escaped, and every word
// that holds MDX markup characters in code.
func sandboxDocsText(s string) string {
	words := strings.Fields(s)
	for i, w := range words {
		if !sandboxDocsSpecial.MatchString(w) {
			continue
		}
		lead := len(w) - len(strings.TrimLeft(w, "("))
		core := strings.TrimLeft(w, "(")
		trail := core[len(strings.TrimRight(core, ").,;:")):]
		core = strings.TrimRight(core, ").,;:")
		words[i] = w[:lead] + "`" + core + "`" + trail
	}
	out := strings.Join(words, " ")
	out = strings.ReplaceAll(out, "|", `\|`)
	if out != "" && out[0] >= 'a' && out[0] <= 'z' {
		out = strings.ToUpper(out[:1]) + out[1:]
	}
	if out != "" && !strings.HasSuffix(out, ".") {
		out += "."
	}
	return out
}

// sandboxDocsBlock renders the generated block of one command.
func sandboxDocsBlock(t *testing.T, path string) string {
	t.Helper()
	cmd, _, err := sandboxCmd.Find(strings.Fields(path))
	if err != nil || cmd == sandboxCmd {
		t.Fatalf("sandbox %s: not in the command tree: %v", path, err)
	}
	var b strings.Builder
	var subs []*cobra.Command
	for _, sub := range cmd.Commands() {
		if !sub.Hidden && sub.Name() != "help" {
			subs = append(subs, sub)
		}
	}
	if len(subs) > 0 {
		b.WriteString("| Subcommand | Purpose |\n| --- | --- |\n")
		for _, sub := range subs {
			fmt.Fprintf(&b, "| [`sandbox %s %s`](#sandbox-%s-%s) | %s |\n", path, sub.Name(),
				strings.ReplaceAll(path, " ", "-"), sub.Name(), sandboxDocsText(sub.Short))
		}
		return b.String()
	}
	var flags []*pflag.Flag
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		if f.Name != "help" {
			flags = append(flags, f)
		}
	})
	if len(flags) == 0 {
		return "This command has no flags.\n"
	}
	b.WriteString("| Flag | Takes | Default | Description |\n| --- | --- | --- | --- |\n")
	for _, f := range flags {
		value, ok := sandboxDocsFlagValue[f.Value.Type()]
		if !ok {
			t.Fatalf("sandbox %s --%s: no docs wording for flag type %q", path, f.Name, f.Value.Type())
		}
		name := "`--" + f.Name + "`"
		if f.Shorthand != "" {
			name = "`-" + f.Shorthand + "`, " + name
		}
		def := ""
		switch f.DefValue {
		case "", "false", "[]":
		default:
			def = "`" + f.DefValue + "`"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", name, value, def, sandboxDocsText(f.Usage))
	}
	return b.String()
}

// TestSandboxCLIReferenceDocs keeps the sandbox CLI reference page a
// checked projection of the pinned command tree: every command has its own
// section (a "### `sandbox <path>`" heading, a shell example that runs the
// command, and the generated block), and the page documents no command or
// flag the tree lacks. DEFENSECLAW_UPDATE_GOLDEN=1 rewrites the generated
// blocks from the tree.
func TestSandboxCLIReferenceDocs(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	page := filepath.Join(filepath.Dir(filename), "..", "..", "docs-site", "content", "docs", "reference", sandboxDocsPage)
	raw, err := os.ReadFile(page)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)

	want := map[string]bool{}
	var order []string
	for _, m := range sandboxManifest(sandboxCmd) {
		path := strings.TrimPrefix(m.Path, "sandbox ")
		want[path] = true
		order = append(order, path)
	}

	// Rewrite or compare each generated block.
	var out strings.Builder
	seen := map[string]bool{}
	rest := text
	for {
		i := strings.Index(rest, sandboxDocsBeginMark)
		if i < 0 {
			out.WriteString(rest)
			break
		}
		out.WriteString(rest[:i])
		rest = rest[i:]
		eol := strings.Index(rest, sandboxDocsMarkSuffix+"\n")
		if eol < 0 {
			t.Fatalf("%s: unterminated generated-block marker", sandboxDocsPage)
		}
		path := strings.TrimSpace(rest[len(sandboxDocsBeginMark):eol])
		begin := rest[:eol+len(sandboxDocsMarkSuffix)+1]
		rest = rest[len(begin):]
		end := strings.Index(rest, sandboxDocsEndMark)
		if end < 0 {
			t.Fatalf("%s: block %q has no %s", sandboxDocsPage, path, sandboxDocsEndMark)
		}
		got := rest[:end]
		rest = rest[end:]
		if !want[path] {
			t.Errorf("%s documents `sandbox %s`, which the command tree does not have", sandboxDocsPage, path)
			out.WriteString(begin + got)
			continue
		}
		if seen[path] {
			t.Errorf("%s has two generated blocks for `sandbox %s`", sandboxDocsPage, path)
		}
		seen[path] = true
		block := sandboxDocsBlock(t, path)
		if got != block && os.Getenv("DEFENSECLAW_UPDATE_GOLDEN") != "1" {
			t.Errorf("%s: the generated block for `sandbox %s` is out of date; run DEFENSECLAW_UPDATE_GOLDEN=1 go test ./internal/cli -run TestSandboxCLIReferenceDocs\n got:\n%s\nwant:\n%s",
				sandboxDocsPage, path, got, block)
		}
		out.WriteString(begin + block)
	}

	for _, path := range order {
		if !seen[path] {
			t.Errorf("%s has no generated block for `sandbox %s`; add %s%s%s … %s under its heading",
				sandboxDocsPage, path, sandboxDocsBeginMark, path, sandboxDocsMarkSuffix, sandboxDocsEndMark)
			continue
		}
		section, ok := sandboxDocsSection(text, path)
		if !ok {
			t.Errorf("%s has no \"### `sandbox %s`\" heading", sandboxDocsPage, path)
			continue
		}
		if !strings.Contains(section, sandboxDocsBeginMark+path+sandboxDocsMarkSuffix) {
			t.Errorf("%s: the generated block for `sandbox %s` is not in its section", sandboxDocsPage, path)
		}
		if !sandboxDocsHasExample(section, path) {
			t.Errorf("%s: the `sandbox %s` section has no bash example running `defenseclaw sandbox %s`", sandboxDocsPage, path, path)
		}
	}

	if os.Getenv("DEFENSECLAW_UPDATE_GOLDEN") == "1" && out.String() != text {
		if err := os.WriteFile(page, []byte(out.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// sandboxDocsSection returns the page text from a command's heading to the
// next heading of the same or a higher level.
func sandboxDocsSection(text, path string) (string, bool) {
	heading := "### `sandbox " + path + "`\n"
	i := strings.Index(text, heading)
	if i < 0 {
		return "", false
	}
	body := text[i+len(heading):]
	for _, next := range []string{"\n### ", "\n## "} {
		if j := strings.Index(body, next); j >= 0 {
			body = body[:j]
		}
	}
	return body, true
}

// sandboxDocsHasExample reports whether a section has a bash fence with a
// line that runs `defenseclaw sandbox <path>`.
func sandboxDocsHasExample(section, path string) bool {
	prefix := "defenseclaw sandbox " + path
	inFence := false
	for _, line := range strings.Split(section, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "```bash"):
			inFence = true
		case strings.HasPrefix(trimmed, "```"):
			inFence = false
		case inFence && (trimmed == prefix || strings.HasPrefix(trimmed, prefix+" ")):
			return true
		}
	}
	return false
}
