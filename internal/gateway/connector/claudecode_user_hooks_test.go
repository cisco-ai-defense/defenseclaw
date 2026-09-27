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
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type claudeCodeUserHooksFixture struct {
	cursor       cursorUserHooksFixture
	home         string
	localAppData string
	programs     string
	launcher     string
	settingsPath string
}

func newClaudeCodeUserHooksFixture(t *testing.T) claudeCodeUserHooksFixture {
	t.Helper()
	cursor := newCursorUserHooksFixture(t)
	f := claudeCodeUserHooksFixture{
		cursor:       cursor,
		home:         cursor.home,
		localAppData: filepath.Join(cursor.home, "AppData", "Local"),
		settingsPath: filepath.Join(cursor.home, ".claude", "settings.json"),
	}
	f.programs = filepath.Join(f.localAppData, "Programs")
	// The launcher per-user setup registers on Windows.
	f.launcher = filepath.Join(f.localAppData, "DefenseClaw", "HookRuntime", windowsHookBinaryName)
	return f
}

func (f claudeCodeUserHooksFixture) install() ClaudeCodePerUserInstall {
	return ClaudeCodePerUserInstall{LocalAppData: f.localAppData, UserProgramFiles: f.programs}
}

func (f claudeCodeUserHooksFixture) remove(t *testing.T, data []byte, install ClaudeCodePerUserInstall) ([]byte, []ClaudeCodeUserHookRemoval, error) {
	t.Helper()
	var out []byte
	var removed []ClaudeCodeUserHookRemoval
	var removeErr error
	if err := WithUserHomeDir(f.home, func() error {
		out, removed, removeErr = RemoveClaudeCodePerUserHookRegistrations(data, install)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out, removed, removeErr
}

// handler is the JSON of the handler per-user setup on Windows writes for
// the fixture's launcher.
func (f claudeCodeUserHooksFixture) handler(t *testing.T) string {
	t.Helper()
	return `{"type":"command","command":` + cursorUserHooksJSONString(t, f.launcher) +
		`,"args":["hook","--connector","claudecode"],"timeout":30}`
}

// perUserHooks returns the hooks object per-user Claude Code setup on
// Windows writes for launcher: the matrix of appendClaudeCodeHookMatrixForSetup
// with the arguments of claudeCodeHookInvocation.
func perUserClaudeCodeHooks(t *testing.T, launcher string) map[string]interface{} {
	t.Helper()
	hooks := map[string]interface{}{}
	if err := appendClaudeCodeHookMatrixForSetup(hooks, launcher, claudeCodePerUserHookArgs[:], SetupOpts{}); err != nil {
		t.Fatal(err)
	}
	return hooks
}

func decodeClaudeCodeTestJSON(t *testing.T, data []byte) interface{} {
	t.Helper()
	var value interface{}
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatalf("%v: %s", err, data)
	}
	return value
}

// The managed Cursor hook denies every tool call while per-user Claude Code
// setup's registrations are in the user's ~/.claude/settings.json, and allows
// once they are removed. The user's own hooks and settings stay.
func TestManagedCursorCheckAllowsOnceThePerUserClaudeCodeRegistrationsAreRemoved(t *testing.T) {
	f := newClaudeCodeUserHooksFixture(t)
	hooks := perUserClaudeCodeHooks(t, f.launcher)
	own := map[string]interface{}{"hooks": []interface{}{map[string]interface{}{"type": "command", "command": "notify.cmd"}}}
	stop, _ := hooks["Stop"].([]interface{})
	hooks["Stop"] = append(stop, own)
	env := map[string]interface{}{"OTEL_LOGS_EXPORTER": "otlp"}
	body, err := json.MarshalIndent(map[string]interface{}{"model": "opus", "env": env, "hooks": hooks}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(f.settingsPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.settingsPath, body, 0o600); err != nil {
		t.Fatal(err)
	}

	permission, requests, message := f.cursor.managedPreToolUse(t)
	if permission != "deny" || requests != 0 || !strings.Contains(message, f.settingsPath) {
		t.Fatalf("before removal: permission=%q gateway requests=%d message=%q, want a denial naming %s",
			permission, requests, message, f.settingsPath)
	}

	cleaned, removed, err := f.remove(t, body, f.install())
	if err != nil {
		t.Fatal(err)
	}
	groups, err := claudeCodeHookGroupsForSetup(SetupOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != len(groups) {
		t.Fatalf("removed %d registrations, want one per group (%d): %#v", len(removed), len(groups), removed)
	}
	for _, removal := range removed {
		if removal.Command != f.launcher {
			t.Fatalf("removal %#v does not name the launcher %q", removal, f.launcher)
		}
	}
	if err := os.WriteFile(f.settingsPath, cleaned, 0o600); err != nil {
		t.Fatal(err)
	}
	permission, requests, message = f.cursor.managedPreToolUse(t)
	if permission != "allow" || requests != 1 {
		t.Fatalf("after removal: permission=%q gateway requests=%d message=%q, want allow after one gateway request",
			permission, requests, message)
	}
	after := decodeClaudeCodeTestJSON(t, cleaned).(map[string]interface{})
	if !reflect.DeepEqual(after["env"], env) || after["model"] != "opus" {
		t.Fatalf("settings after removal = %#v, want env and model kept", after)
	}
	kept := after["hooks"].(map[string]interface{})
	for event, value := range kept {
		want := []interface{}{}
		if event == "Stop" {
			want = []interface{}{own}
		}
		if !reflect.DeepEqual(value, want) {
			t.Fatalf("%s after removal = %#v, want %#v", event, value, want)
		}
	}
}

// Only DefenseClaw's own handlers, and the groups they leave empty, go;
// every other byte of the file stays.
func TestRemoveClaudeCodePerUserHookRegistrationsKeepsEveryOtherByte(t *testing.T) {
	f := newClaudeCodeUserHooksFixture(t)
	owned := f.handler(t)
	launcher := cursorUserHooksJSONString(t, f.launcher)
	audit := `{ "matcher": "Bash", "hooks": [ {"type": "command", "command": "audit.cmd", "timeout": 5.0} ] }`
	echo := `{"type":"command","command":"echo \"],[\""}`
	repeated := `{"matcher":"a","matcher":"b","hooks":[{"type":"command","command":"x.cmd"}]}`
	env := `"env": {"OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:4318", "x": [1, 2e0, ` + launcher + `]}`
	original := "{\r\n" +
		"  \"model\": \"opus\",\r\n" +
		"  \"hooks\": {\r\n" +
		"    \"PreToolUse\": [\r\n" +
		"      {\"matcher\": \"*\", \"hooks\": [" + owned + "]},\r\n" +
		"      " + audit + "\r\n" +
		"    ],\r\n" +
		"    \"PostToolUse\": [{\"matcher\":\"*\",\"hooks\":[{\"type\":\"command\",\"command\":\"log.cmd\"},\t" + owned + "  ]}],\r\n" +
		"    \"Stop\": [ {\"hooks\": [" + owned + "]} ],\r\n" +
		"    \"Notification\": [{\"hooks\":[" + owned + "," + echo + "]}],\r\n" +
		"    \"SessionStart\": [" + repeated + "],\r\n" +
		"    \"SessionEnd\": []\r\n" +
		"  },\r\n" +
		"  " + env + "\r\n" +
		"}\r\n"
	want := "{\r\n" +
		"  \"model\": \"opus\",\r\n" +
		"  \"hooks\": {\r\n" +
		"    \"PreToolUse\": [\r\n" +
		"      " + audit + "\r\n" +
		"    ],\r\n" +
		"    \"PostToolUse\": [{\"matcher\":\"*\",\"hooks\":[{\"type\":\"command\",\"command\":\"log.cmd\"}  ]}],\r\n" +
		"    \"Stop\": [],\r\n" +
		"    \"Notification\": [{\"hooks\":[" + echo + "]}],\r\n" +
		"    \"SessionStart\": [" + repeated + "],\r\n" +
		"    \"SessionEnd\": []\r\n" +
		"  },\r\n" +
		"  " + env + "\r\n" +
		"}\r\n"
	got, removed, err := f.remove(t, []byte(original), f.install())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("cleaned file:\n%s\nwant:\n%s", got, want)
	}
	var events []string
	for _, removal := range removed {
		if removal.Command != f.launcher {
			t.Fatalf("removal names command %q, want the launcher %q", removal.Command, f.launcher)
		}
		events = append(events, removal.Event)
	}
	if wantEvents := []string{"PreToolUse", "PostToolUse", "Stop", "Notification"}; !reflect.DeepEqual(events, wantEvents) {
		t.Fatalf("removed events = %v, want %v", events, wantEvents)
	}
	again, removed, err := f.remove(t, got, f.install())
	if err != nil || len(removed) != 0 || !bytes.Equal(again, got) {
		t.Fatalf("second removal = (%q, %v, %v), want the cleaned file unchanged", again, removed, err)
	}
}

// Per-user setup's handlers for each of DefenseClaw's executables go, in the
// current command-and-args form and the earlier one-string form. The managed
// registration, other arguments, other executables, a bare name and other
// spellings stay.
func TestRemoveClaudeCodePerUserHookRegistrationsMatchesOnlyPerUserSetupCommands(t *testing.T) {
	f := newClaudeCodeUserHooksFixture(t)
	exec := func(command string, args ...interface{}) map[string]interface{} {
		return map[string]interface{}{"type": "command", "command": command, "args": args, "timeout": 30}
	}
	single := func(command string) map[string]interface{} {
		return map[string]interface{}{"type": "command", "command": command, "timeout": 30}
	}
	var binaries []string
	if err := WithUserHomeDir(f.home, func() error {
		binaries = uniqueNonEmptyStrings(append(legacyNativeHookBinaries(), nativeHookBinariesInUserFolders(f.localAppData, f.programs)...))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var owned []interface{}
	var commands []string
	for _, binary := range binaries {
		if !filepath.IsAbs(binary) {
			continue
		}
		shell := `"` + binary + `" hook --connector claudecode`
		owned = append(owned, exec(binary, "hook", "--connector", "claudecode"), single(shell))
		commands = append(commands, binary, shell)
	}
	if len(owned) < 2*3 {
		t.Fatalf("matched executables = %v, want at least the three in the user's folders", binaries)
	}
	foreign := []interface{}{
		exec(f.launcher, "hook", "--connector", "claudecode", "--enterprise-managed"),
		exec(f.launcher, "hook", "--connector", "cursor"),
		exec(f.launcher, "hook", "--connector"),
		exec(f.launcher, "hook", "--connector", 7),
		exec(filepath.Join(f.programs, "Other", "bin", windowsHookBinaryName), "hook", "--connector", "claudecode"),
		exec(windowsHookBinaryName, "hook", "--connector", "claudecode"),
		single(`"` + f.launcher + `" hook --connector claudecode --enterprise-managed`),
		single(`& "` + f.launcher + `" hook --connector claudecode`),
		single(f.launcher + " hook --connector claudecode"),
		single(`"` + f.launcher + `"`),
		map[string]interface{}{"type": "http", "command": f.launcher, "args": []interface{}{"hook", "--connector", "claudecode"}},
		map[string]interface{}{"command": f.launcher, "args": []interface{}{"hook", "--connector", "claudecode"}},
		map[string]interface{}{"type": "command", "command": f.launcher, "args": "hook --connector claudecode"},
	}
	group := func(handlers []interface{}) map[string]interface{} {
		return map[string]interface{}{"matcher": "*", "hooks": handlers}
	}
	data, err := json.Marshal(map[string]interface{}{
		"hooks": map[string]interface{}{"PreToolUse": []interface{}{group(owned), group(foreign)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, removed, err := f.remove(t, data, f.install())
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, removal := range removed {
		names = append(names, removal.Command)
	}
	if !reflect.DeepEqual(names, commands) {
		t.Fatalf("removed %v, want %v", names, commands)
	}
	want, err := json.Marshal(map[string]interface{}{
		"hooks": map[string]interface{}{"PreToolUse": []interface{}{group(foreign)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decodeClaudeCodeTestJSON(t, got), decodeClaudeCodeTestJSON(t, want)) {
		t.Fatalf("cleaned file = %s, want %s", got, want)
	}

	// The executables in the user's folders are recognized only from the
	// folders the caller resolves for the user.
	users, err := json.Marshal(map[string]interface{}{
		"hooks": map[string]interface{}{"PreToolUse": []interface{}{group([]interface{}{
			exec(f.launcher, "hook", "--connector", "claudecode"),
			single(`"` + filepath.Join(f.programs, "DefenseClaw", "bin", windowsGatewayBinaryName) + `" hook --connector claudecode`),
		})}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, removed, err := f.remove(t, users, ClaudeCodePerUserInstall{}); err != nil || len(removed) != 0 || !bytes.Equal(got, users) {
		t.Fatalf("without the user's folders: (%q, %#v, %v), want the input unchanged", got, removed, err)
	}
}

func TestRemoveClaudeCodePerUserHookRegistrationsLeavesFilesWithoutThem(t *testing.T) {
	f := newClaudeCodeUserHooksFixture(t)
	handler := f.handler(t)
	otherUser := strings.Replace(handler, "profile", "other-profile", 1)
	if otherUser == handler {
		t.Fatalf("test handler %s does not name the profile folder", handler)
	}
	group := `{"matcher":"*","hooks":[` + handler + `]}`
	for name, data := range map[string]string{
		"empty":                       "",
		"whitespace":                  " \n",
		"empty object":                "{}",
		"no hooks":                    `{"model":"opus"}`,
		"null hooks":                  `{"hooks":null}`,
		"hooks array":                 `{"hooks":[` + group + `]}`,
		"empty hooks":                 `{"hooks":{}}`,
		"only foreign handlers":       `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"audit.cmd"}]}]}}`,
		"another user's registration": `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[` + otherUser + `]}]}}`,
		"event value is not an array": `{"hooks":{"PreToolUse":` + group + `}}`,
		"registration outside hooks":  `{"PreToolUse":[` + group + `]}`,
		"handler outside a group":     `{"hooks":{"PreToolUse":[` + handler + `]}}`,
		"group hooks is not an array": `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":` + handler + `}]}}`,
		"registration in env":         `{"env":{"hooks":{"PreToolUse":[` + group + `]}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			got, removed, err := f.remove(t, []byte(data), f.install())
			if err != nil {
				t.Fatal(err)
			}
			if len(removed) != 0 || string(got) != data {
				t.Fatalf("got (%q, %#v), want the input unchanged", got, removed)
			}
		})
	}
}

func TestRemoveClaudeCodePerUserHookRegistrationsRefusesFilesItCannotEditExactly(t *testing.T) {
	f := newClaudeCodeUserHooksFixture(t)
	handler := f.handler(t)
	group := `{"matcher":"*","hooks":[` + handler + `]}`
	for name, data := range map[string]string{
		"invalid JSON":                    `{"hooks":{"PreToolUse":[` + group + `]}`,
		"trailing data":                   `{"hooks":{"PreToolUse":[` + group + `]}} {}`,
		"top-level array":                 `[{"hooks":{"PreToolUse":[` + group + `]}}]`,
		"top-level null":                  `null`,
		"repeated hooks key":              `{"hooks":{},"hooks":{"PreToolUse":[` + group + `]}}`,
		"repeated event key":              `{"hooks":{"PreToolUse":[],"PreToolUse":[` + group + `]}}`,
		"repeated key in an edited group": `{"hooks":{"PreToolUse":[{"hooks":[],"hooks":[` + handler + `]}]}}`,
		"trailing comma":                  `{"hooks":{"PreToolUse":[` + group + `,]}}`,
		"comment in the file":             "{\"hooks\":{\"PreToolUse\":[" + group + "]} // per-user\n}",
		"over the size limit":             `{"hooks":{"PreToolUse":[` + group + `]},"pad":"` + strings.Repeat("x", int(claudeCodeSettingsReadLimit)) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			got, removed, err := f.remove(t, []byte(data), f.install())
			if err == nil || got != nil || removed != nil {
				t.Fatalf("got (%.200q, %#v, %v), want an error and no output", got, removed, err)
			}
		})
	}
}

func TestRemoveClaudeCodePerUserHookRegistrationsKeepsTheByteOrderMark(t *testing.T) {
	f := newClaudeCodeUserHooksFixture(t)
	own := `{"type":"command","command":"a.cmd"}`
	data := "\xef\xbb\xbf{\"hooks\":{\"PreToolUse\":[{\"hooks\":[" + f.handler(t) + "," + own + "]}]}}"
	got, removed, err := f.remove(t, []byte(data), f.install())
	if err != nil {
		t.Fatal(err)
	}
	if want := "\xef\xbb\xbf{\"hooks\":{\"PreToolUse\":[{\"hooks\":[" + own + "]}]}}"; string(got) != want || len(removed) != 1 {
		t.Fatalf("got (%q, %#v), want %q and one removal", got, removed, want)
	}
}

// The check that the result is the original document without the removed
// handlers runs on the user's own file in the LocalSystem guardian, so its
// cost stays in proportion to the file's size: kept numbers are compared as
// they are written.
func TestRemoveClaudeCodePerUserHookRegistrationsKeepsNumbersOfAnySize(t *testing.T) {
	f := newClaudeCodeUserHooksFixture(t)
	handler := f.handler(t)
	for name, numbers := range map[string]string{
		"exponents beyond an exact fraction": "1e1000001, -2.5E-1000001",
		"many large exponents":               strings.TrimSuffix(strings.Repeat("1e999999, ", 300), ", "),
	} {
		t.Run(name, func(t *testing.T) {
			kept := `{"type":"command","command":"a.cmd","limits":[` + numbers + `]}`
			data := `{"limits":[` + numbers + `],"hooks":{"PreToolUse":[{"hooks":[` + handler + `,` + kept + `]}]}}`
			want := `{"limits":[` + numbers + `],"hooks":{"PreToolUse":[{"hooks":[` + kept + `]}]}}`
			started := time.Now()
			got, removed, err := f.remove(t, []byte(data), f.install())
			elapsed := time.Since(started)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != want || len(removed) != 1 {
				t.Fatalf("got (%q, %#v), want the numbers kept as written and one removal", got, removed)
			}
			if elapsed > 2*time.Second {
				t.Fatalf("removal took %v for a %d-byte file", elapsed, len(data))
			}
		})
	}
}
