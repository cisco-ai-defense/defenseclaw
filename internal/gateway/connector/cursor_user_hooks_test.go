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

package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

type cursorUserHooksFixture struct {
	home      string
	dataDir   string
	workspace string
	hooksPath string
}

func newCursorUserHooksFixture(t *testing.T) cursorUserHooksFixture {
	t.Helper()
	root := t.TempDir()
	f := cursorUserHooksFixture{
		home:      filepath.Join(root, "profile"),
		dataDir:   filepath.Join(root, "profile", ".defenseclaw"),
		workspace: filepath.Join(root, "workspace"),
	}
	f.hooksPath = filepath.Join(f.home, ".cursor", "hooks.json")
	for _, dir := range []string{filepath.Join(f.dataDir, "hooks"), f.workspace} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	previous := CursorHooksPathOverride
	CursorHooksPathOverride = ""
	t.Cleanup(func() { CursorHooksPathOverride = previous })
	return f
}

// setupPerUser writes the per-user DefenseClaw Cursor registration the way
// per-user setup does and returns the command it registered.
func (f cursorUserHooksFixture) setupPerUser(t *testing.T) string {
	t.Helper()
	c := NewCursorConnector()
	opts := SetupOpts{DataDir: f.dataDir}
	if err := WithUserHomeDir(f.home, func() error {
		return c.patchConfig(opts, c.hookCommand(opts))
	}); err != nil {
		t.Fatalf("per-user Cursor setup: %v", err)
	}
	command := shellWord(c.hookCommand(opts))
	cfg, err := readJSONObject(f.hooksPath)
	if err != nil {
		t.Fatal(err)
	}
	entries, _ := cfg["hooks"].(map[string]interface{})["preToolUse"].([]interface{})
	for _, entry := range entries {
		if fields, _ := entry.(map[string]interface{}); fields["command"] == command {
			return command
		}
	}
	t.Fatalf("per-user setup preToolUse entries = %#v, want one running %q", entries, command)
	return ""
}

func (f cursorUserHooksFixture) remove(t *testing.T, data []byte) ([]byte, []CursorUserHookRemoval, error) {
	t.Helper()
	var out []byte
	var removed []CursorUserHookRemoval
	var removeErr error
	if err := WithUserHomeDir(f.home, func() error {
		out, removed, removeErr = RemoveCursorPerUserHookRegistrations(data, CursorPerUserInstall{DataDir: f.dataDir})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out, removed, removeErr
}

type cursorUserHooksGateway struct{ requests int }

func (g *cursorUserHooksGateway) RoundTrip(*http.Request) (*http.Response, error) {
	g.requests++
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"action":"allow","hook_output":{"permission":"allow"}}`)),
	}, nil
}

// managedPreToolUse runs the managed Cursor preToolUse hook for the fixture's
// user and returns Cursor's permission and the number of gateway requests.
func (f cursorUserHooksFixture) managedPreToolUse(t *testing.T) (string, int, string) {
	t.Helper()
	gateway := &cursorUserHooksGateway{}
	payload, err := json.Marshal(map[string]interface{}{
		"hook_event_name": "preToolUse",
		"cursor_version":  "3.9.0",
		"workspace_roots": []string{f.workspace},
		"tool_name":       "Shell",
		"tool_input":      map[string]interface{}{"command": "echo ORIGINAL"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	token := "managed-token"
	hookexec.Run(context.Background(), hookexec.Options{
		Connector:                 "cursor",
		APIAddr:                   "127.0.0.1:8787",
		Home:                      f.dataDir,
		HookDir:                   filepath.Join(f.dataDir, "hooks"),
		ManagedEnterprise:         true,
		StrictAvailability:        true,
		FailMode:                  "closed",
		AuthenticatedManagedToken: &token,
		ForeignHookHomes:          []string{f.home},
		Getenv:                    func(string) string { return "" },
		Stdin:                     bytes.NewReader(payload),
		Stdout:                    &stdout,
		Stderr:                    &stderr,
		HTTPClient:                &http.Client{Transport: gateway},
	})
	var response map[string]interface{}
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &response); err != nil {
		t.Fatalf("managed hook output is not a Cursor response: %q (stderr %q)", stdout.String(), stderr.String())
	}
	permission, _ := response["permission"].(string)
	message, _ := response["user_message"].(string)
	return permission, gateway.requests, message
}

func cursorUserHooksJSONString(t *testing.T, value string) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

// The managed Cursor hook denies every tool call while the per-user
// registration is in the user's hooks.json, and allows once it is removed.
func TestManagedCursorCheckAllowsOnceThePerUserRegistrationsAreRemoved(t *testing.T) {
	f := newCursorUserHooksFixture(t)
	f.setupPerUser(t)
	cfg, err := readJSONObject(f.hooksPath)
	if err != nil {
		t.Fatal(err)
	}
	hooks := cfg["hooks"].(map[string]interface{})
	hooks["stop"] = append(hooks["stop"].([]interface{}), map[string]interface{}{"command": "notify.sh"})
	if err := writeJSONObject(f.hooksPath, cfg); err != nil {
		t.Fatal(err)
	}

	permission, requests, message := f.managedPreToolUse(t)
	if permission != "deny" || requests != 0 || !strings.Contains(message, f.hooksPath) {
		t.Fatalf("before removal: permission=%q gateway requests=%d message=%q, want a denial naming %s",
			permission, requests, message, f.hooksPath)
	}

	original, err := os.ReadFile(f.hooksPath)
	if err != nil {
		t.Fatal(err)
	}
	cleaned, removed, err := f.remove(t, original)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != len(cursorHookEvents) {
		t.Fatalf("removed %d registrations, want one per event (%d): %#v", len(removed), len(cursorHookEvents), removed)
	}
	if err := os.WriteFile(f.hooksPath, cleaned, 0o600); err != nil {
		t.Fatal(err)
	}
	permission, requests, message = f.managedPreToolUse(t)
	if permission != "allow" || requests != 1 {
		t.Fatalf("after removal: permission=%q gateway requests=%d message=%q, want allow after one gateway request",
			permission, requests, message)
	}
	after, err := readJSONObject(f.hooksPath)
	if err != nil {
		t.Fatal(err)
	}
	stop := after["hooks"].(map[string]interface{})["stop"].([]interface{})
	if len(stop) != 1 || stop[0].(map[string]interface{})["command"] != "notify.sh" {
		t.Fatalf("stop entries after removal = %#v, want only the user's own hook", stop)
	}
}

// Only DefenseClaw's own entries go; every other byte of the file stays.
func TestRemoveCursorPerUserHookRegistrationsKeepsEveryOtherByte(t *testing.T) {
	f := newCursorUserHooksFixture(t)
	perUser := f.setupPerUser(t)
	command := cursorUserHooksJSONString(t, perUser)
	original := "{\n" +
		"  \"version\": 1,\n" +
		"  \"hooks\": {\n" +
		"    \"preToolUse\": [\n" +
		"      { \"command\": \"node   audit.js\", \"timeout\": 5.0 },\n" +
		"      {\"type\":\"command\",\"command\":" + command + ",\"timeout\":30,\"failClosed\":false},\n" +
		"      {\"command\": \"\\u0065cho keep\"}\n" +
		"    ],\n" +
		"    \"stop\": [ {\"type\": \"command\", \"command\": " + command + "} ],\n" +
		"    \"afterFileEdit\": [{\"command\":" + command + "},{\"command\":\"fmt.sh \\\"],[\\\"\"}],\n" +
		"    \"sessionEnd\": [{\"command\":\"first.sh\"},\t{\"command\":" + command + "}  ],\n" +
		"    \"beforeShellExecution\": []\n" +
		"  },\n" +
		"  \"editor\": {\"x\": [1, 2e0, " + command + "]}\n" +
		"}\n"
	want := "{\n" +
		"  \"version\": 1,\n" +
		"  \"hooks\": {\n" +
		"    \"preToolUse\": [\n" +
		"      { \"command\": \"node   audit.js\", \"timeout\": 5.0 },\n" +
		"      {\"command\": \"\\u0065cho keep\"}\n" +
		"    ],\n" +
		"    \"stop\": [],\n" +
		"    \"afterFileEdit\": [{\"command\":\"fmt.sh \\\"],[\\\"\"}],\n" +
		"    \"sessionEnd\": [{\"command\":\"first.sh\"}  ],\n" +
		"    \"beforeShellExecution\": []\n" +
		"  },\n" +
		"  \"editor\": {\"x\": [1, 2e0, " + command + "]}\n" +
		"}\n"
	got, removed, err := f.remove(t, []byte(original))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("cleaned file:\n%s\nwant:\n%s", got, want)
	}
	var events []string
	for _, removal := range removed {
		if removal.Command != perUser {
			t.Fatalf("removal names command %q, want the per-user command %q", removal.Command, perUser)
		}
		events = append(events, removal.Event)
	}
	if wantEvents := []string{"preToolUse", "stop", "afterFileEdit", "sessionEnd"}; !reflect.DeepEqual(events, wantEvents) {
		t.Fatalf("removed events = %v, want %v", events, wantEvents)
	}
	again, removed, err := f.remove(t, got)
	if err != nil || len(removed) != 0 || !bytes.Equal(again, got) {
		t.Fatalf("second removal = (%q, %v, %v), want the cleaned file unchanged", again, removed, err)
	}
}

// The direct native commands of earlier Windows releases are per-user
// setup's too; the same command for another executable, or the managed
// registration form, is not.
func TestRemoveCursorPerUserHookRegistrationsRemovesOlderNativeCommands(t *testing.T) {
	f := newCursorUserHooksFixture(t)
	var legacy []string
	if err := WithUserHomeDir(f.home, func() error {
		legacy = legacyCursorNativeHookCommands()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(legacy) == 0 {
		t.Fatal("no legacy Cursor native commands")
	}
	var entries []interface{}
	for _, command := range legacy {
		entries = append(entries, map[string]interface{}{"type": "command", "command": command})
	}
	foreign := []interface{}{
		map[string]interface{}{"command": `"C:\Tools\defenseclaw-gateway.exe" hook --connector cursor`},
		map[string]interface{}{"command": legacy[0] + " --enterprise-managed"},
	}
	entries = append(entries, foreign...)
	data, err := json.Marshal(map[string]interface{}{
		"version": 1,
		"hooks":   map[string]interface{}{"preToolUse": entries},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, removed, err := f.remove(t, data)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != len(legacy) {
		t.Fatalf("removed %#v, want the %d legacy commands", removed, len(legacy))
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(got, &cfg); err != nil {
		t.Fatal(err)
	}
	if kept := cfg["hooks"].(map[string]interface{})["preToolUse"]; !reflect.DeepEqual(kept, foreign) {
		t.Fatalf("kept entries = %#v, want %#v", kept, foreign)
	}
}

// The guardian removes the per-user entries while it impersonates the user,
// but the connector's Known Folder lookups use the process token, which is
// LocalSystem's there. The direct native commands under the user's
// LocalAppData and per-user Programs folders are therefore matched from the
// folders the caller resolves for the user.
func TestRemoveCursorPerUserHookRegistrationsRemovesOlderNativeCommandsInTheUsersFolders(t *testing.T) {
	f := newCursorUserHooksFixture(t)
	localAppData := filepath.Join(f.home, "AppData", "Local")
	programs := filepath.Join(localAppData, "Programs")
	native := func(binary string) string {
		return `"` + binary + `" hook --connector cursor`
	}
	owned := []string{
		native(filepath.Join(localAppData, "DefenseClaw", "HookRuntime", "defenseclaw-hook.exe")),
		native(filepath.Join(programs, "DefenseClaw", "bin", "defenseclaw-hook.exe")),
		native(filepath.Join(programs, "DefenseClaw", "bin", "defenseclaw-gateway.exe")),
	}
	foreign := []interface{}{
		map[string]interface{}{"command": native(filepath.Join(programs, "Other", "bin", "defenseclaw-hook.exe"))},
		map[string]interface{}{"command": owned[0] + " --enterprise-managed"},
	}
	var entries []interface{}
	for _, command := range owned {
		entries = append(entries, map[string]interface{}{"type": "command", "command": command})
	}
	data, err := json.Marshal(map[string]interface{}{
		"version": 1,
		"hooks":   map[string]interface{}{"preToolUse": append(entries, foreign...)},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Without the user's folders, as when they are resolved from the
	// process token, these entries are not recognized.
	if got, removed, err := f.remove(t, data); err != nil || len(removed) != 0 || !bytes.Equal(got, data) {
		t.Fatalf("without the user's folders: (%q, %#v, %v), want the input unchanged", got, removed, err)
	}

	var got []byte
	var removed []CursorUserHookRemoval
	if err := WithUserHomeDir(f.home, func() error {
		got, removed, err = RemoveCursorPerUserHookRegistrations(data, CursorPerUserInstall{
			DataDir:          f.dataDir,
			LocalAppData:     localAppData,
			UserProgramFiles: programs,
		})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var commands []string
	for _, removal := range removed {
		commands = append(commands, removal.Command)
	}
	if !reflect.DeepEqual(commands, owned) {
		t.Fatalf("removed %v, want %v", commands, owned)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(got, &cfg); err != nil {
		t.Fatal(err)
	}
	if kept := cfg["hooks"].(map[string]interface{})["preToolUse"]; !reflect.DeepEqual(kept, foreign) {
		t.Fatalf("kept entries = %#v, want %#v", kept, foreign)
	}
}

func TestRemoveCursorPerUserHookRegistrationsLeavesFilesWithoutThem(t *testing.T) {
	f := newCursorUserHooksFixture(t)
	command := f.setupPerUser(t)
	otherUser := strings.Replace(command, "profile", "other-profile", 1)
	if otherUser == command {
		t.Fatalf("test command %q does not name the profile folder", command)
	}
	for name, data := range map[string]string{
		"empty":                            "",
		"whitespace":                       " \n",
		"empty object":                     "{}",
		"no hooks":                         `{"version":1}`,
		"null hooks":                       `{"version":1,"hooks":null}`,
		"hooks array":                      `{"version":1,"hooks":[` + cursorUserHooksJSONString(t, command) + `]}`,
		"empty hooks":                      `{"version":1,"hooks":{}}`,
		"only foreign entries":             `{"version":1,"hooks":{"preToolUse":[{"command":"node audit.js"}]}}`,
		"another user's registration":      `{"version":1,"hooks":{"preToolUse":[{"command":` + cursorUserHooksJSONString(t, otherUser) + `}]}}`,
		"event value is not an array":      `{"version":1,"hooks":{"preToolUse":{"command":` + cursorUserHooksJSONString(t, command) + `}}}`,
		"registration outside hooks":       `{"version":1,"preToolUse":[{"command":` + cursorUserHooksJSONString(t, command) + `}]}`,
		"registration in a grouped entry":  `{"version":1,"hooks":{"preToolUse":[{"matcher":"*","hooks":[{"command":` + cursorUserHooksJSONString(t, command) + `}]}]}}`,
		"command with surrounding context": `{"version":1,"hooks":{"preToolUse":[{"command":` + cursorUserHooksJSONString(t, command+" && echo") + `}]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			got, removed, err := f.remove(t, []byte(data))
			if err != nil {
				t.Fatal(err)
			}
			if len(removed) != 0 || string(got) != data {
				t.Fatalf("got (%q, %#v), want the input unchanged", got, removed)
			}
		})
	}
}

func TestRemoveCursorPerUserHookRegistrationsRefusesFilesItCannotEditExactly(t *testing.T) {
	f := newCursorUserHooksFixture(t)
	command := cursorUserHooksJSONString(t, f.setupPerUser(t))
	entry := `{"command":` + command + `}`
	for name, data := range map[string]string{
		"invalid JSON":        `{"hooks":{"preToolUse":[` + entry + `]}`,
		"trailing data":       `{"hooks":{"preToolUse":[` + entry + `]}} {}`,
		"top-level array":     `[{"hooks":{"preToolUse":[` + entry + `]}}]`,
		"repeated hooks key":  `{"hooks":{},"hooks":{"preToolUse":[` + entry + `]}}`,
		"repeated event key":  `{"hooks":{"preToolUse":[],"preToolUse":[` + entry + `]}}`,
		"trailing comma":      `{"hooks":{"preToolUse":[` + entry + `,]}}`,
		"comment in the file": "{\"hooks\":{\"preToolUse\":[" + entry + "]} // per-user\n}",
	} {
		t.Run(name, func(t *testing.T) {
			got, removed, err := f.remove(t, []byte(data))
			if err == nil || got != nil || removed != nil {
				t.Fatalf("got (%q, %#v, %v), want an error and no output", got, removed, err)
			}
		})
	}
	if _, _, err := RemoveCursorPerUserHookRegistrations([]byte(`{}`), CursorPerUserInstall{DataDir: " "}); err == nil {
		t.Fatal("an empty data directory was accepted")
	}
}

func TestRemoveCursorPerUserHookRegistrationsKeepsTheByteOrderMark(t *testing.T) {
	f := newCursorUserHooksFixture(t)
	command := cursorUserHooksJSONString(t, f.setupPerUser(t))
	data := "\xef\xbb\xbf{\"version\":1,\"hooks\":{\"preToolUse\":[{\"command\":" + command + "},{\"command\":\"a.sh\"}]}}"
	got, removed, err := f.remove(t, []byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if want := "\xef\xbb\xbf{\"version\":1,\"hooks\":{\"preToolUse\":[{\"command\":\"a.sh\"}]}}"; string(got) != want || len(removed) != 1 {
		t.Fatalf("got (%q, %#v), want %q and one removal", got, removed, want)
	}
}

// The managed deployment's uninstall does not put the removed entries back.
// A user who returns to per-user DefenseClaw runs per-user setup again, which
// registers them again beside the user's own entries, and per-user teardown
// of a cleaned file keeps those entries.
func TestPerUserCursorSetupAndTeardownWorkOnACleanedFile(t *testing.T) {
	f := newCursorUserHooksFixture(t)
	f.setupPerUser(t)
	cfg, err := readJSONObject(f.hooksPath)
	if err != nil {
		t.Fatal(err)
	}
	hooks := cfg["hooks"].(map[string]interface{})
	hooks["preToolUse"] = append(hooks["preToolUse"].([]interface{}), map[string]interface{}{"command": "node audit.js"})
	if err := writeJSONObject(f.hooksPath, cfg); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(f.hooksPath)
	if err != nil {
		t.Fatal(err)
	}
	cleaned, _, err := f.remove(t, original)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.hooksPath, cleaned, 0o600); err != nil {
		t.Fatal(err)
	}

	c := NewCursorConnector()
	opts := SetupOpts{DataDir: f.dataDir}
	if err := WithUserHomeDir(f.home, func() error {
		return c.removeConfigEntries(f.hooksPath, c.hookCommand(opts), opts)
	}); err != nil {
		t.Fatalf("per-user teardown of the cleaned file: %v", err)
	}
	torn, err := readJSONObject(f.hooksPath)
	if err != nil {
		t.Fatal(err)
	}
	if kept := torn["hooks"].(map[string]interface{})["preToolUse"]; !reflect.DeepEqual(kept, []interface{}{map[string]interface{}{"command": "node audit.js"}}) {
		t.Fatalf("preToolUse after per-user teardown = %#v, want the user's own hook", kept)
	}

	current := f.setupPerUser(t)
	again, err := readJSONObject(f.hooksPath)
	if err != nil {
		t.Fatal(err)
	}
	owned := newCursorHookCommandMatcher(append([]string{current}, cursorOwnedHookCommands(opts)...))
	if !cursorHookContractPresent(again["hooks"].(map[string]interface{}), current, owned, c.effectiveFailClosed(opts)) {
		t.Fatal("per-user setup did not register its complete Cursor contract again")
	}
	entries := again["hooks"].(map[string]interface{})["preToolUse"].([]interface{})
	if len(entries) != 2 || !reflect.DeepEqual(entries[0], map[string]interface{}{"command": "node audit.js"}) {
		t.Fatalf("preToolUse after per-user setup = %#v, want the user's hook and the registration", entries)
	}
}
