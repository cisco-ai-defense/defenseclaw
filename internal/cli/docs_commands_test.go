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
			for i, field := range fields {
				if i > 0 && strings.ContainsAny(field, "<>") {
					fields = fields[:i]
					break
				}
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

type documentedGatewayCommand struct {
	path    string
	line    int
	command string
	inline  bool
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
			// consumer, not the gateway invocation. The documented gateway
			// flags themselves do not contain either character.
			if idx := strings.IndexAny(text, "|#"); idx >= 0 {
				text = strings.TrimSpace(text[:idx])
			}
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
