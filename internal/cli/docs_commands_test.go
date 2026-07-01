// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestDocumentedGatewayCommandsParse keeps public MDX, active operator guides,
// and runnable examples in supporting docs attached to the real Cobra tree. It
// parses command paths, flags, and positional arguments without executing
// PersistentPreRunE or any command callback, so no operator config, database,
// or daemon state is touched.
func TestDocumentedGatewayCommandsParse(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
	docRoots := []string{
		filepath.Join(repoRoot, "docs-site", "content", "docs"),
		filepath.Join(repoRoot, "docs"),
		filepath.Join(repoRoot, "README.md"),
	}

	var commands []documentedGatewayCommand
	for _, docsRoot := range docRoots {
		found, err := documentedGatewayCommands(docsRoot, repoRoot)
		if err != nil {
			t.Fatal(err)
		}
		commands = append(commands, found...)
	}
	if len(commands) == 0 {
		t.Fatal("no documented defenseclaw-gateway commands found")
	}

	for _, documented := range commands {
		documented := documented
		t.Run(fmt.Sprintf("%s:%d", documented.path, documented.line), func(t *testing.T) {
			fields := strings.Fields(documented.command)
			if len(fields) < 1 || fields[0] != "defenseclaw-gateway" {
				t.Fatalf("invalid extracted command %q", documented.command)
			}
			if documented.inline {
				validateDocumentedGatewayPath(t, fields[1:], documented.command)
				return
			}
			for i := 1; i < len(fields); i++ {
				if isDocumentedShellRedirection(fields[i]) {
					fields = fields[:i]
					break
				}
				fields[i] = representativeDocumentedGatewayField(fields[i])
			}

			cmd, args, err := rootCmd.Find(fields[1:])
			if err != nil {
				t.Fatalf("find command for %q: %v", documented.command, err)
			}
			if err := cmd.ParseFlags(args); err != nil {
				t.Fatalf("parse flags for %q: %v", documented.command, err)
			}
			positional := cmd.Flags().Args()
			if cmd.Args != nil {
				if err := cmd.Args(cmd, positional); err != nil {
					t.Fatalf("parse arguments for %q: %v", documented.command, err)
				}
			}
		})
	}

	t.Logf("validated %d documented defenseclaw-gateway commands", len(commands))
}

func TestRepresentativeDocumentedGatewayField(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"<path>":                  ".",
		"<connector>":             "codex",
		"<event>":                 "PreToolUse",
		"<severity>":              "high",
		"--connector=<name>":      "--connector=example",
		"<observe|action>":        "observe",
		"REQUEST_ID":              "example",
		"--request-id=REQUEST_ID": "--request-id=example",
		"...":                     "example",
		"…":                       "example",
		"literal":                 "literal",
	}
	for input, want := range tests {
		input, want := input, want
		t.Run(input, func(t *testing.T) {
			t.Parallel()
			if got := representativeDocumentedGatewayField(input); got != want {
				t.Fatalf("representativeDocumentedGatewayField(%q) = %q, want %q", input, got, want)
			}
		})
	}
}

func TestIsDocumentedShellRedirection(t *testing.T) {
	t.Parallel()
	for _, field := range []string{"2>&1", ">", ">>"} {
		if !isDocumentedShellRedirection(field) {
			t.Errorf("isDocumentedShellRedirection(%q) = false, want true", field)
		}
	}
	for _, field := range []string{"<path>", "--output", "literal"} {
		if isDocumentedShellRedirection(field) {
			t.Errorf("isDocumentedShellRedirection(%q) = true, want false", field)
		}
	}
}

func TestTruncateDocumentedGatewayConsumerSyntax(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"defenseclaw-gateway scan <observe|action> | jq":                     "defenseclaw-gateway scan <observe|action>",
		"defenseclaw-gateway audit export # JSONL":                           "defenseclaw-gateway audit export",
		"defenseclaw-gateway proxy --url https://example.invalid/api#status": "defenseclaw-gateway proxy --url https://example.invalid/api#status",
		"defenseclaw-gateway status":                                         "defenseclaw-gateway status",
	}
	for input, want := range tests {
		if got := truncateDocumentedGatewayConsumerSyntax(input); got != want {
			t.Errorf("truncateDocumentedGatewayConsumerSyntax(%q) = %q, want %q", input, got, want)
		}
	}
}

type documentedGatewayCommand struct {
	path    string
	line    int
	command string
	inline  bool
}

// representativeDocumentedGatewayField turns documentation notation into one
// concrete value so Cobra validates required positional arguments and flags.
// Truncating at the first placeholder would let missing arguments pass unseen.
func representativeDocumentedGatewayField(field string) string {
	result := field
	for {
		start := strings.Index(result, "<")
		if start < 0 {
			break
		}
		endOffset := strings.Index(result[start+1:], ">")
		if endOffset < 0 {
			break
		}
		end := start + 1 + endOffset
		label := strings.TrimSpace(result[start+1 : end])
		choice := strings.Split(label, "|")[0]
		value := "example"
		switch strings.ToLower(choice) {
		case "path", "file", "dir", "directory":
			value = "."
		case "connector":
			value = "codex"
		case "event":
			value = "PreToolUse"
		case "severity":
			value = "high"
		default:
			if strings.Contains(label, "|") {
				value = choice
			}
		}
		result = result[:start] + value + result[end+1:]
	}
	if result == "..." || result == "…" {
		return "example"
	}
	if key, value, ok := strings.Cut(result, "="); ok && isUppercaseDocumentedPlaceholder(value) {
		return key + "=example"
	}
	if isUppercaseDocumentedPlaceholder(result) {
		return "example"
	}
	return result
}

func isUppercaseDocumentedPlaceholder(field string) bool {
	if !strings.Contains(field, "_") || field != strings.ToUpper(field) {
		return false
	}
	for _, r := range field {
		if (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' {
			return false
		}
	}
	return true
}

func isDocumentedShellRedirection(field string) bool {
	trimmed := strings.TrimLeft(field, "0123456789")
	return strings.HasPrefix(trimmed, ">") ||
		(strings.HasPrefix(trimmed, "<") && !strings.Contains(trimmed, ">"))
}

// truncateDocumentedGatewayConsumerSyntax removes shell consumers and comments
// while preserving choice pipes inside compact placeholders such as
// <observe|action>.
func truncateDocumentedGatewayConsumerSyntax(text string) string {
	for index := 0; index < len(text); index++ {
		if text[index] == '<' {
			if offset := strings.IndexByte(text[index+1:], '>'); offset >= 0 {
				end := index + 1 + offset
				if !strings.ContainsAny(text[index+1:end], " \t") {
					index = end
					continue
				}
			}
		}
		isComment := text[index] == '#' &&
			(index == 0 || text[index-1] == ' ' || text[index-1] == '\t')
		if text[index] == '|' || isComment {
			return strings.TrimSpace(text[:index])
		}
	}
	return strings.TrimSpace(text)
}

func validateDocumentedGatewayPath(t *testing.T, fields []string, documented string) {
	t.Helper()
	cmd := rootCmd
	for _, field := range fields {
		if strings.HasPrefix(field, "-") || strings.ContainsAny(field, "<>[]{}|/*") || strings.Contains(field, "...") || strings.Contains(field, "…") {
			break
		}
		var childName string
		for _, child := range cmd.Commands() {
			if child.Name() == field || child.HasAlias(field) {
				childName = child.Name()
				cmd = child
				break
			}
		}
		if childName == "" {
			if cmd.HasSubCommands() {
				t.Fatalf("unknown command path component %q in %q", field, documented)
			}
			break
		}
	}
}

func checkInlineGatewayCommands(path, repoRoot string) bool {
	publicRoot := filepath.Join(repoRoot, "docs-site", "content", "docs")
	if rel, err := filepath.Rel(publicRoot, path); err == nil && rel != "." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return true
	}
	docsRoot := filepath.Join(repoRoot, "docs")
	return filepath.Dir(path) == docsRoot || path == filepath.Join(repoRoot, "README.md")
}

func documentedGatewayCommands(root, repoRoot string) ([]documentedGatewayCommand, error) {
	var commands []documentedGatewayCommand
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		ext := filepath.Ext(path)
		if entry.IsDir() || (ext != ".mdx" && ext != ".md") {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		shellFence := false
		lineNumber := 0
		logicalStart := 0
		var logical []string
		flush := func() {
			if len(logical) == 0 {
				return
			}
			text := strings.TrimSpace(strings.Join(logical, " "))
			logical = nil
			if !strings.HasPrefix(text, "defenseclaw-gateway ") && text != "defenseclaw-gateway" {
				return
			}
			// Everything after a shell pipeline or comment belongs to the
			// consumer, not the gateway invocation. Choice pipes inside an
			// angle-bracket placeholder remain part of the invocation.
			text = truncateDocumentedGatewayConsumerSyntax(text)
			rel, _ := filepath.Rel(repoRoot, path)
			commands = append(commands, documentedGatewayCommand{path: rel, line: logicalStart, command: text})
		}

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			lineNumber++
			trimmed := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(trimmed, "```") {
				if shellFence {
					flush()
					shellFence = false
					continue
				}
				lang := strings.TrimSpace(strings.TrimPrefix(trimmed, "```"))
				shellFence = lang == "bash" || lang == "sh" || lang == "shell" || lang == "zsh" || lang == "console"
				continue
			}
			if !shellFence {
				if checkInlineGatewayCommands(path, repoRoot) {
					parts := strings.Split(scanner.Text(), "`")
					for index := 1; index < len(parts); index += 2 {
						text := strings.TrimSpace(strings.SplitN(parts[index], `\n`, 2)[0])
						if text != "defenseclaw-gateway" && !strings.HasPrefix(text, "defenseclaw-gateway ") {
							continue
						}
						rel, _ := filepath.Rel(repoRoot, path)
						commands = append(commands, documentedGatewayCommand{path: rel, line: lineNumber, command: text, inline: true})
					}
				}
				continue
			}

			if len(logical) == 0 {
				logicalStart = lineNumber
			}
			if strings.HasSuffix(trimmed, "\\") {
				logical = append(logical, strings.TrimSpace(strings.TrimSuffix(trimmed, "\\")))
				continue
			}
			logical = append(logical, trimmed)
			flush()
		}
		return scanner.Err()
	})
	return commands, err
}
