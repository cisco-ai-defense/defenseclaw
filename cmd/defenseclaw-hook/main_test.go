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

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"testing"
)

// Package init is paid on every agent tool call. The hook links neither the
// gateway server nor the telemetry catalogs (TestSlimHookLinksNoGatewayPackages);
// what it still links, observability through internal/config, must not
// compile catalogs in package init either.
func TestHookStartupInitBudget(t *testing.T) {
	if os.Getenv("DEFENSECLAW_HOOK_STARTUP_HELPER") == "1" {
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "-test.run=^TestHookStartupInitBudget$")
	cmd.Env = append(os.Environ(), "DEFENSECLAW_HOOK_STARTUP_HELPER=1", "GODEBUG=inittrace=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("hook startup helper: %v\n%s", err, output)
	}
	if gone := regexp.MustCompile(`(?m)^init github\.com/defenseclaw/defenseclaw/internal/(gateway|telemetry) @`).Find(output); gone != nil {
		t.Fatalf("the hook runs gateway or telemetry package init: %s", gone)
	}
	lines := regexp.MustCompile(`(?m)^init github\.com/defenseclaw/defenseclaw/internal/[a-z0-9/]+ @[^\n]*?, ([0-9]+) bytes,`)
	var total int64
	matches := lines.FindAllSubmatch(output, -1)
	if len(matches) == 0 {
		t.Fatalf("no DefenseClaw package init trace in the helper output: GODEBUG=inittrace=1 did not report\n%s", output)
	}
	for _, match := range matches {
		bytes, err := strconv.ParseInt(string(match[1]), 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		total += bytes
	}
	t.Logf("defenseclaw package init: %d bytes", total)
	if total > 20<<20 {
		t.Fatalf("hook imports allocate %d bytes in DefenseClaw package init, want at most 20 MiB", total)
	}
}

func TestIsHookEntrypoint(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{name: "hook", args: []string{"hook", "--connector", "codex"}, want: true},
		{name: "notify", args: []string{"notify", `{}`}, want: true},
		{name: "empty", want: false},
		{name: "daemon command", args: []string{"start"}, want: false},
		{name: "global flag", args: []string{"--version"}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isHookEntrypoint(tt.args); got != tt.want {
				t.Fatalf("isHookEntrypoint(%q) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}

func TestIdentityEntrypointRequiresExactArgument(t *testing.T) {
	if !isIdentityEntrypoint([]string{"--version-json"}) {
		t.Fatal("exact identity argument was not recognized")
	}
	for _, args := range [][]string{nil, {"--version-json", "extra"}, {"hook", "--version-json"}} {
		if isIdentityEntrypoint(args) {
			t.Fatalf("identity mode accepted %q", args)
		}
	}
}

func TestMachineIdentityReportsLinkedBuild(t *testing.T) {
	originalVersion, originalCommit, originalDate := version, commit, date
	t.Cleanup(func() { version, commit, date = originalVersion, originalCommit, originalDate })
	version = "1.2.3"
	commit = "0123456789abcdef0123456789abcdef01234567"
	date = "2026-07-15T00:00:00Z"
	var output bytes.Buffer
	if err := writeMachineIdentity(&output); err != nil {
		t.Fatalf("writeMachineIdentity: %v", err)
	}
	var report struct {
		SchemaVersion int    `json:"schema_version"`
		Name          string `json:"name"`
		Version       string `json:"version"`
		Commit        string `json:"commit"`
		Built         string `json:"built"`
	}
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatalf("decode identity: %v", err)
	}
	if report.SchemaVersion != 1 || report.Name != "defenseclaw-hook" ||
		report.Version != version || report.Commit != commit || report.Built != date {
		t.Fatalf("unexpected identity report: %+v", report)
	}
}
