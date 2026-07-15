// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"text/template"
)

func TestGoReleaserHooksUseCanonicalWindowsTarget(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", ".."))
	contents, err := os.ReadFile(filepath.Join(repositoryRoot, ".goreleaser.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	var commands []string
	scanner := bufio.NewScanner(bytes.NewReader(contents))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "- cmd: ") && strings.Contains(line, "./internal/tools/windowsresources") {
			commands = append(commands, strings.TrimPrefix(line, "- cmd: "))
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(commands) != 2 {
		t.Fatalf("GoReleaser Windows resource hook count = %d, want 2", len(commands))
	}

	data := struct {
		Os      string
		Arch    string
		Target  string
		Path    string
		Version string
	}{
		Os:      "windows",
		Arch:    "amd64",
		Target:  "windows_amd64_v1",
		Path:    `C:\dist\defenseclaw.exe`,
		Version: "1.2.3",
	}
	components := map[string]int{"gateway": 0, "hook": 0}
	for index, command := range commands {
		parsed, err := template.New("hook").Option("missingkey=error").Parse(command)
		if err != nil {
			t.Fatalf("parse hook %d: %v", index, err)
		}
		var rendered strings.Builder
		if err := parsed.Execute(&rendered, data); err != nil {
			t.Fatalf("render hook %d: %v", index, err)
		}
		actual := rendered.String()
		if strings.Contains(actual, data.Target) {
			t.Fatalf("hook %d passed GoReleaser target suffix to the resource tool: %s", index, actual)
		}
		if !strings.Contains(actual, "-target windows_amd64 ") {
			t.Fatalf("hook %d did not pass the canonical OS/architecture target: %s", index, actual)
		}
		matches := 0
		for component := range components {
			if strings.Contains(actual, "-component "+component+" ") {
				components[component]++
				matches++
			}
		}
		if matches != 1 {
			t.Fatalf("hook %d selected %d supported components, want 1: %s", index, matches, actual)
		}
	}
	for component, count := range components {
		if count != 1 {
			t.Errorf("GoReleaser resource hooks for component %q = %d, want 1", component, count)
		}
	}
}
