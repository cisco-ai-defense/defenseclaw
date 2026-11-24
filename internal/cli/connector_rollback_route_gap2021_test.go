// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// rel-1-0-10 GAP-2021: a user on 1.0.10 with their own Codex model_provider
// (Bedrock) and no Codex hook upgraded, ran setup codex and routing enable
// --connector codex (route-only replaces model_provider), then `defenseclaw
// rollback`. The rollback swapped the data folder, so the route-only record
// that knew the user's value stayed with the newer install; the prune after
// the swap tore Codex down with no record and deleted the model_provider
// line. Codex then started at the OpenAI sign-in. The fixtures carry
// comments, single quotes and an inline comment: restore is byte for byte.

const gap2021CodexWithProvider = `# my Codex settings
model = "gpt-5.6-luna"
model_provider = 'bedrock-luna'   # Bedrock, not the OpenAI login
approval_policy = "on-request"

[model_providers.bedrock-luna]
name = "Bedrock Luna"
base_url = "https://bedrock-runtime.us-east-1.amazonaws.com/openai/v1"
wire_api = "responses"
env_key = "AWS_BEARER_TOKEN_BEDROCK"
`

const gap2021CodexNoProvider = `# my Codex settings
model = "gpt-5"

[profiles.fast]
model = "gpt-5-mini"
`

const gap2021ClaudeWithBaseURL = `{
  "env": {
    "ANTHROPIC_BASE_URL": "https://llm-proxy.example.internal/anthropic",
    "OPERATOR_FLAG": "1"
  },
  "model": "sonnet"
}
`

type gap2021Home struct {
	root, dataDir, codexPath, claudePath string
}

func newGAP2021Home(t *testing.T) gap2021Home {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("uses the POSIX hook layout and the install.sh data swap")
	}
	root := testenv.PrivateTempDir(t)
	testenv.SetHome(t, root)
	h := gap2021Home{
		root:       root,
		dataDir:    filepath.Join(root, ".defenseclaw"),
		codexPath:  filepath.Join(root, ".codex", "config.toml"),
		claudePath: filepath.Join(root, ".claude", "settings.json"),
	}
	for _, dir := range []string{h.dataDir, filepath.Dir(h.codexPath), filepath.Dir(h.claudePath)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	previousCodex := connector.CodexConfigPathOverride
	connector.CodexConfigPathOverride = h.codexPath
	previousClaude := connector.ClaudeCodeSettingsPathOverride
	connector.ClaudeCodeSettingsPathOverride = h.claudePath
	t.Cleanup(func() {
		connector.CodexConfigPathOverride = previousCodex
		connector.ClaudeCodeSettingsPathOverride = previousClaude
	})
	return h
}

func (h gap2021Home) write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (h gap2021Home) read(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (h gap2021Home) opts(route *connector.RouteOnlySetup) connector.SetupOpts {
	return connector.SetupOpts{DataDir: h.dataDir, APIAddr: "127.0.0.1:18970", APIToken: "test-token", RouteOnly: route}
}

func gap2021Route(name string) *connector.RouteOnlySetup {
	return &connector.RouteOnlySetup{BaseURL: "http://127.0.0.1:18970/r/" + name, Token: "dcr1-test-route-" + name}
}

// setUp runs `defenseclaw setup <name>`, then, with route, routing enable:
// the gateway reload runs Setup again with the route (codex.go Setup ends in
// ApplyRouteOnly). It returns the agent file as setup alone left it.
func (h gap2021Home) setUp(t *testing.T, conn connector.Connector, path string, route *connector.RouteOnlySetup) []byte {
	t.Helper()
	if err := conn.Setup(context.Background(), h.opts(nil)); err != nil {
		t.Fatalf("%s setup: %v", conn.Name(), err)
	}
	afterSetup := h.read(t, path)
	if route != nil {
		if err := conn.Setup(context.Background(), h.opts(route)); err != nil {
			t.Fatalf("%s setup with route-only: %v", conn.Name(), err)
		}
		if routed := h.read(t, path); !bytes.Contains(routed, []byte("/r/"+conn.Name())) {
			t.Fatalf("%s route-only render missing:\n%s", conn.Name(), routed)
		}
	}
	return afterSetup
}

// upgrade keeps the data of the install being replaced in previous/data, as
// install.sh does before it installs the newer release.
func (h gap2021Home) upgrade(t *testing.T) {
	t.Helper()
	slot := filepath.Join(h.root, "upgrade-snapshot")
	if err := copyGAP2021Tree(h.dataDir, slot); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(h.dataDir, "previous"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(slot, filepath.Join(h.dataDir, "previous", "data")); err != nil {
		t.Fatal(err)
	}
}

// rollback runs what `defenseclaw rollback` runs around the data swap
// (install.sh: convert_hooks_for_rollback, swap_with_previous,
// prune_orphaned_hooks); configured is the connector the install brought
// back configures.
// It returns what prepare-rollback printed.
func (h gap2021Home) rollback(t *testing.T, toVersion, configured string) string {
	t.Helper()
	restore := withConnectorState(t, h.dataDir, "codex")
	prepared, stderr, exitCode := runConnectorCmd(t, "prepare-rollback", "--data-dir", h.dataDir, "--to-version", toVersion)
	restore()
	if exitCode != 0 || strings.TrimSpace(stderr) != "" {
		t.Fatalf("prepare-rollback: exit=%d stderr=%q", exitCode, stderr)
	}
	newer := filepath.Join(h.root, "newer-data")
	if err := os.Rename(h.dataDir, newer); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(newer, "previous", "data"), h.dataDir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(h.dataDir, "previous"), 0o700); err != nil {
		t.Fatal(err)
	}
	saved := filepath.Join(h.dataDir, "previous", "data")
	if err := os.Rename(newer, saved); err != nil {
		t.Fatal(err)
	}
	defer withConnectorState(t, h.dataDir, configured)()
	_, stderr, exitCode = runConnectorCmd(t, "prune-orphans", "--data-dir", h.dataDir, "--rollback-backups-dir", saved)
	if exitCode != 0 || strings.Contains(stderr, "could not") {
		t.Fatalf("prune-orphans: exit=%d stderr=%q", exitCode, stderr)
	}
	return prepared
}

func copyGAP2021Tree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.MkdirAll(target, info.Mode().Perm())
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, raw, info.Mode().Perm())
	})
}

func assertGAP2021Bytes(t *testing.T, what string, got []byte, want string) {
	t.Helper()
	if string(got) != want {
		t.Fatalf("%s is not the user's file byte for byte:\n--- got ---\n%s\n--- want ---\n%s", what, got, want)
	}
}

// The user's model_provider comes back after setup codex, route-only and a
// rollback to 1.0.10, and a user with none ends with none.
func TestGAP2021RollbackPutsBackTheUserCodexModelProvider(t *testing.T) {
	for _, tc := range []struct{ name, asFound string }{
		{"own model_provider", gap2021CodexWithProvider},
		{"no model_provider", gap2021CodexNoProvider},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newGAP2021Home(t)
			h.write(t, h.codexPath, tc.asFound)
			h.upgrade(t) // 1.0.10 had no Codex hook
			h.setUp(t, connector.NewCodexConnector(), h.codexPath, gap2021Route("codex"))
			prepared := h.rollback(t, "1.0.10", "claudecode")
			assertGAP2021Bytes(t, "config.toml after the rollback", h.read(t, h.codexPath), tc.asFound)
			if raw, err := os.ReadFile(filepath.Join(h.dataDir, "active_connector.json")); err == nil && bytes.Contains(raw, []byte("codex")) {
				t.Fatalf("the rollback left a codex entry in the restored connector state: %s", raw)
			}
			if !strings.Contains(prepared, "codex: put back the model settings") || strings.Contains(prepared, "claudecode: put back") {
				t.Fatalf("prepare-rollback does not name exactly the routed connector: %q", prepared)
			}
		})
	}
}

// routing disable (connector route-restore) puts the user's value back and
// leaves setup's own changes; setup --remove (teardown) then returns the file
// the user had.
func TestGAP2021RoutingDisableAndTeardownPutBackTheUserCodexModelProvider(t *testing.T) {
	for _, tc := range []struct{ name, asFound string }{
		{"own model_provider", gap2021CodexWithProvider},
		{"no model_provider", gap2021CodexNoProvider},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newGAP2021Home(t)
			h.write(t, h.codexPath, tc.asFound)
			afterSetup := h.setUp(t, connector.NewCodexConnector(), h.codexPath, gap2021Route("codex"))
			defer withConnectorState(t, h.dataDir, "codex")()
			if _, stderr, exitCode := runConnectorCmd(t, "route-restore", "--connector", "codex"); exitCode != 0 || strings.TrimSpace(stderr) != "" {
				t.Fatalf("route-restore: exit=%d stderr=%q", exitCode, stderr)
			}
			assertGAP2021Bytes(t, "config.toml after routing disable", h.read(t, h.codexPath), string(afterSetup))
			if _, stderr, exitCode := runConnectorCmd(t, "teardown", "--connector", "codex"); exitCode != 0 {
				t.Fatalf("teardown: exit=%d stderr=%q", exitCode, stderr)
			}
			assertGAP2021Bytes(t, "config.toml after setup --remove", h.read(t, h.codexPath), tc.asFound)
		})
	}
	// setup --remove straight from a route-only render, with no routing
	// disable first.
	h := newGAP2021Home(t)
	h.write(t, h.codexPath, gap2021CodexWithProvider)
	h.setUp(t, connector.NewCodexConnector(), h.codexPath, gap2021Route("codex"))
	defer withConnectorState(t, h.dataDir, "codex")()
	if _, stderr, exitCode := runConnectorCmd(t, "teardown", "--connector", "codex"); exitCode != 0 {
		t.Fatalf("teardown: exit=%d stderr=%q", exitCode, stderr)
	}
	assertGAP2021Bytes(t, "config.toml after setup --remove of a routed Codex", h.read(t, h.codexPath), gap2021CodexWithProvider)
}

// A user who had Codex set up (and route-only) on the release the rollback
// returns to gets that release's file back byte for byte: its own record
// restores or renders the route, so this release leaves it.
func TestGAP2021RollbackKeepsTheCodexSetUpOnTheReleaseBack(t *testing.T) {
	for _, tc := range []struct {
		name  string
		route *connector.RouteOnlySetup
	}{
		{"hooks only", nil},
		{"hooks and route-only", gap2021Route("codex")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newGAP2021Home(t)
			h.write(t, h.codexPath, gap2021CodexWithProvider)
			h.setUp(t, connector.NewCodexConnector(), h.codexPath, tc.route)
			asFound := string(h.read(t, h.codexPath))
			h.upgrade(t)
			// The newer gateway's start runs setup again.
			if err := connector.NewCodexConnector().Setup(context.Background(), h.opts(tc.route)); err != nil {
				t.Fatalf("codex setup on the newer install: %v", err)
			}
			if prepared := h.rollback(t, "1.0.10", "codex"); strings.Contains(prepared, "put back the model settings") {
				t.Fatalf("prepare-rollback took back a render the release back owns: %q", prepared)
			}
			assertGAP2021Bytes(t, "config.toml after the rollback", h.read(t, h.codexPath), asFound)
		})
	}
}

// The same record decides Claude Code's route-only keys: the user's own
// ANTHROPIC_BASE_URL comes back after a rollback.
func TestGAP2021RollbackPutsBackTheUserClaudeBaseURL(t *testing.T) {
	h := newGAP2021Home(t)
	h.write(t, h.claudePath, gap2021ClaudeWithBaseURL)
	h.upgrade(t)
	h.setUp(t, connector.NewClaudeCodeConnector(), h.claudePath, gap2021Route("claudecode"))
	h.rollback(t, "1.0.10", "codex")
	after := h.read(t, h.claudePath)
	var got, want map[string]any
	if err := json.Unmarshal(after, &got); err != nil {
		t.Fatalf("settings.json after the rollback: %v\n%s", err, after)
	}
	if err := json.Unmarshal([]byte(gap2021ClaudeWithBaseURL), &want); err != nil {
		t.Fatal(err)
	}
	gotJSON, _ := json.Marshal(got)
	wantJSON, _ := json.Marshal(want)
	if !bytes.Equal(gotJSON, wantJSON) {
		t.Fatalf("settings.json after the rollback is not the user's:\n%s\nwant\n%s", after, gap2021ClaudeWithBaseURL)
	}
}
