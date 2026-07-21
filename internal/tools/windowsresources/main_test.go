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

	"github.com/defenseclaw/defenseclaw/internal/windowsresources"
)

func TestClassifyTargetFailsClosedForWindowsValues(t *testing.T) {
	for _, test := range []struct {
		value     string
		want      windowsresources.Target
		isWindows bool
		wantError bool
	}{
		{value: "windows_amd64", want: windowsresources.TargetWindowsAMD64, isWindows: true},
		{value: " WINDOWS_ARM64 ", want: windowsresources.TargetWindowsARM64, isWindows: true},
		{value: "linux_amd64"},
		{value: "linux_arm64"},
		{value: "darwin_amd64"},
		{value: "darwin_arm64"},
		{value: "", wantError: true},
		{value: "linux_386", wantError: true},
		{value: "windows", wantError: true},
		{value: "windows_386", wantError: true},
		{value: "windows_x64", wantError: true},
		{value: "windows_amd64_v1", wantError: true},
		{value: "windows_arm64_v8.0", wantError: true},
		{value: "windowsill_amd64", wantError: true},
	} {
		target, isWindows, err := classifyTarget(test.value)
		if (err != nil) != test.wantError {
			t.Errorf("classifyTarget(%q) error = %v, wantError %v", test.value, err, test.wantError)
			continue
		}
		if isWindows != test.isWindows {
			t.Errorf("classifyTarget(%q) Windows = %v, want %v", test.value, isWindows, test.isWindows)
		}
		if target != test.want {
			t.Errorf("classifyTarget(%q) target = %q, want %q", test.value, target, test.want)
		}
	}
}

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

	for _, architecture := range []string{"amd64", "arm64"} {
		t.Run(architecture, func(t *testing.T) {
			data := struct {
				Os      string
				Arch    string
				Target  string
				Path    string
				Version string
			}{
				Os:      "windows",
				Arch:    architecture,
				Target:  "windows_" + architecture + "_v1",
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
				if !strings.Contains(actual, "-target windows_"+architecture+" ") {
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
		})
	}
}
