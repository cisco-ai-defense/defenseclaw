// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// testdata/hook_registration_every_connector.json holds the agent hook files
// per-user Setup writes for every built-in hook connector, at user and at
// workspace scope, and the Windows render of the Antigravity hooks.json.
// cli/tests/test_hook_registration_every_connector.py reads it: status,
// quickstart and doctor must all call each of these files registered. Status
// read only a top-level hooks key, so the Antigravity hooks.json (one
// defenseclaw-antigravity-<event> key per event) and the Devin workspace
// hooks.v1.json (events at the root) looked unregistered right after Setup
// while doctor passed them (GAP-0489).
//
// Regenerate after a deliberate change to what Setup writes:
//
//	DEFENSECLAW_UPDATE_GOLDEN=1 go test ./internal/gateway/connector -run TestEveryHookConnectorSetupMatchesTheSharedGolden
const hookRegistrationGolden = "testdata/hook_registration_every_connector.json"

type hookRegistrationFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type hookRegistrationCase struct {
	Connector string                 `json:"connector"`
	Scope     string                 `json:"scope"`
	OS        string                 `json:"os"`
	Files     []hookRegistrationFile `json:"files"`
}

type hookRegistrationGoldenFile struct {
	About string                 `json:"about"`
	Cases []hookRegistrationCase `json:"cases"`
}

// Connectors with no 1.0.2 support (OmniGent and OpenHands are deprecated) or
// no agent hook file (the OpenClaw and ZeptoClaw proxies).
var hookRegistrationGoldenSkipped = map[string]bool{"omnigent": true, "openhands": true}

// The OpenCode user plugin is identical on both POSIX hosts. Check its
// shared registration fixture on macOS too, where the all-connector Linux
// golden test is skipped. The same UPDATE_GOLDEN command can regenerate
// just this case without rewriting any other connector's fixture.
func TestOpenCodeHookRegistrationMatchesSharedGolden(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("this case holds the POSIX user plugin")
	}
	setHookBinaryOverride(t, "/opt/defenseclaw/bin/defenseclaw-gateway")
	data, err := os.ReadFile(hookRegistrationGolden)
	if err != nil {
		t.Fatal(err)
	}
	var golden hookRegistrationGoldenFile
	if err := json.Unmarshal(data, &golden); err != nil {
		t.Fatal(err)
	}
	var conn Connector
	for _, candidate := range newBuiltinConnectors() {
		if candidate.Name() == "opencode" {
			conn = candidate
			break
		}
	}
	if conn == nil {
		t.Fatal("OpenCode connector is missing")
	}
	matched := false
	for i, expected := range golden.Cases {
		if expected.Connector != "opencode" || expected.OS != "posix" {
			continue
		}
		matched = true
		actual, ok := hookRegistrationSetupCase(t, conn, expected.Scope)
		if !ok {
			t.Fatal("OpenCode did not register its plugin")
		}
		if os.Getenv("DEFENSECLAW_UPDATE_GOLDEN") == "1" {
			golden.Cases[i] = actual
		} else if !reflect.DeepEqual(actual, expected) {
			t.Fatalf("OpenCode %s registration is stale; regenerate with DEFENSECLAW_UPDATE_GOLDEN=1", expected.Scope)
		}
	}
	if !matched {
		t.Fatal("the shared golden has no POSIX OpenCode registration")
	}
	if os.Getenv("DEFENSECLAW_UPDATE_GOLDEN") == "1" {
		data, err := json.MarshalIndent(golden, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(hookRegistrationGolden, append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestEveryHookConnectorSetupMatchesTheSharedGolden(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the golden holds the POSIX Setup output, rendered on linux")
	}
	setHookBinaryOverride(t, "/opt/defenseclaw/bin/defenseclaw-gateway")
	golden := hookRegistrationGoldenFile{
		About: "Agent hook files per-user Setup writes, by connector and scope; {home} and {data_dir} stand for the " +
			"account home and DefenseClaw data directory, {otlp_token} and {digest} for per-run values. Written by TestEveryHookConnectorSetupMatchesTheSharedGolden " +
			"(internal/gateway/connector); read by cli/tests/test_hook_registration_every_connector.py (GAP-0489).",
	}
	for _, conn := range newBuiltinConnectors() {
		if hookRegistrationGoldenSkipped[conn.Name()] {
			continue
		}
		user, ok := hookRegistrationSetupCase(t, conn, "user")
		if !ok {
			continue
		}
		golden.Cases = append(golden.Cases, user)
		// A workspace case is kept only where Setup writes other files for it.
		if workspace, _ := hookRegistrationSetupCase(t, conn, "workspace"); !reflect.DeepEqual(workspace.Files, user.Files) {
			golden.Cases = append(golden.Cases, workspace)
		}
	}
	golden.Cases = append(golden.Cases, antigravityWindowsRegistrationCase(t))
	sort.SliceStable(golden.Cases, func(i, j int) bool {
		a, b := golden.Cases[i], golden.Cases[j]
		if a.Connector != b.Connector {
			return a.Connector < b.Connector
		}
		if a.OS != b.OS {
			return a.OS < b.OS
		}
		return a.Scope < b.Scope
	})
	got, err := json.MarshalIndent(golden, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	if os.Getenv("DEFENSECLAW_UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(hookRegistrationGolden, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(hookRegistrationGolden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is not what Setup writes now (first difference: %s); if the change is deliberate, regenerate it "+
			"(DEFENSECLAW_UPDATE_GOLDEN=1, see the test comment) and run cli/tests/test_hook_registration_every_connector.py",
			hookRegistrationGolden, firstLineDifference(want, got))
	}
	for _, name := range []string{"antigravity", "devin"} {
		found := false
		for _, c := range golden.Cases {
			found = found || c.Connector == name
		}
		if !found {
			t.Errorf("the golden has no %s case", name)
		}
	}
}

func hookRegistrationSetupCase(t *testing.T, conn Connector, scope string) (hookRegistrationCase, bool) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	dataDir := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	opts := SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: "golden-token"}
	if scope == "workspace" {
		opts.WorkspaceDir = filepath.Join(home, "ws")
		if err := os.MkdirAll(opts.WorkspaceDir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	paths := HookConfigPathsForConnector(conn, opts)
	if len(paths) == 0 {
		return hookRegistrationCase{}, false
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("%s %s Setup: %v", conn.Name(), scope, err)
	}
	c := hookRegistrationCase{Connector: conn.Name(), Scope: scope, OS: "posix"}
	for _, path := range HookConfigPathsForConnector(conn, opts) {
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		c.Files = append(c.Files, hookRegistrationFile{
			Path:    hookRegistrationTemplate(path, home, dataDir),
			Content: hookRegistrationTemplate(string(data), home, dataDir),
		})
	}
	if len(c.Files) == 0 {
		t.Fatalf("%s %s Setup wrote none of its hook config paths %v", conn.Name(), scope, paths)
	}
	return c, true
}

// antigravityWindowsRegistrationCase renders the hooks.json per-user Windows
// Setup writes: each command names the launcher only inside its PowerShell
// -EncodedCommand.
func antigravityWindowsRegistrationCase(t *testing.T) hookRegistrationCase {
	t.Helper()
	setHookBinaryOverride(t, `C:\Users\dcuser\.local\bin\defenseclaw-hook.exe`)
	t.Setenv("SystemRoot", `C:\Windows`)
	path := filepath.Join(t.TempDir(), "hooks.json")
	if err := patchAntigravityHooksForOS(path, "", "windows"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return hookRegistrationCase{
		Connector: "antigravity",
		Scope:     "user",
		OS:        "windows",
		Files:     []hookRegistrationFile{{Path: "{home}/.gemini/config/hooks.json", Content: string(data)}},
	}
}

// The OTLP bearer token and the Codex trusted hashes (which hash the absolute
// config path) differ on every run.
var (
	hookRegistrationBearer = regexp.MustCompile(`Bearer [0-9a-f]{64}`)
	hookRegistrationDigest = regexp.MustCompile(`sha256:[0-9a-f]{64}`)
)

func hookRegistrationTemplate(text, home, dataDir string) string {
	text = strings.ReplaceAll(strings.ReplaceAll(text, dataDir, "{data_dir}"), home, "{home}")
	text = hookRegistrationBearer.ReplaceAllString(text, "Bearer {otlp_token}")
	return hookRegistrationDigest.ReplaceAllString(text, "sha256:{digest}")
}

func firstLineDifference(want, got []byte) string {
	wantLines, gotLines := strings.Split(string(want), "\n"), strings.Split(string(got), "\n")
	for i := 0; i < len(wantLines) || i < len(gotLines); i++ {
		var w, g string
		if i < len(wantLines) {
			w = wantLines[i]
		}
		if i < len(gotLines) {
			g = gotLines[i]
		}
		if w != g {
			return fmt.Sprintf("line %d: golden %q, Setup %q", i+1, w, g)
		}
	}
	return "none"
}
