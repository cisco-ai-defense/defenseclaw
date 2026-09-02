// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package idfabric

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeSamplesEnv regenerates testdata/samples when set. The samples are
// reviewed documentation of the exact projection each connector produces, and
// they are what a Windows run is compared against.
const writeSamplesEnv = "IDFABRIC_WRITE_SAMPLES"

// Fixture values below are deliberately free of credential material. Header
// and env values are empty because only their names and the auth scheme token
// affect the projection; that secrets are dropped is asserted separately in
// TestDiscoverMCPServersProjectsOnlyAllowListedFields with a synthetic secret.

// sampleCase is one connector/event combination to capture.
type sampleCase struct {
	name      string
	connector string
	event     string
	payload   string
	setup     func(t *testing.T, home, workspace string)
}

func sampleCases() []sampleCase {
	return []sampleCase{
		{
			name:      "codex-session_start",
			connector: "codex",
			event:     "session_start",
			payload:   `{"session_id":"codex-sess-01","model":"gpt-5-codex","cwd":"%WORKSPACE%"}`,
			setup:     setupCodexFixture,
		},
		{
			name:      "codex-pre_tool_use",
			connector: "codex",
			event:     "pre_tool_use",
			payload:   `{"session_id":"codex-sess-01","tool_name":"mcp__github__create_issue","tool_input":{"title":"omitted by design"}}`,
			setup:     setupCodexFixture,
		},
		{
			name:      "claudecode-session_start",
			connector: "claudecode",
			event:     "",
			payload:   `{"hook_event_name":"SessionStart","session_id":"cc-sess-01","model":"claude-sonnet-4-6","cwd":"%WORKSPACE%"}`,
			setup:     setupClaudeFixture,
		},
		{
			name:      "claudecode-pre_tool_use",
			connector: "claudecode",
			event:     "",
			payload:   `{"hook_event_name":"PreToolUse","session_id":"cc-sess-01","tool_name":"mcp__sentry__list_issues","tool_input":{"query":"omitted by design"}}`,
			setup:     setupClaudeFixture,
		},
		{
			name:      "cursor-session_start",
			connector: "cursor",
			event:     "sessionStart",
			payload:   `{"hook_event_name":"sessionStart","cursor_version":"3.10.17","session_id":"cur-sess-01","user_email":"cursor.user@example.com","cwd":"%WORKSPACE%"}`,
			setup:     setupCursorFixture,
		},
		{
			name:      "cursor-pre_tool_use",
			connector: "cursor",
			event:     "preToolUse",
			payload:   `{"hook_event_name":"preToolUse","cursor_version":"3.10.17","session_id":"cur-sess-01","user_email":"cursor.user@example.com","tool_name":"Shell","tool_input":{"command":"omitted by design"}}`,
			setup:     setupCursorFixture,
		},
	}
}

// setupCodexFixture writes a Codex ID token carrying an email claim, a local
// npx server, and a remote server whose credential sits in the URL query.
func setupCodexFixture(t *testing.T, home, workspace string) {
	t.Helper()
	codexHome := filepath.Join(home, ".codex")
	t.Setenv("CODEX_HOME", codexHome)
	writeJSON(t, filepath.Join(codexHome, "auth.json"), map[string]any{
		"tokens": map[string]any{
			"id_token": unverifiedTestJWT(t, map[string]any{"email": "codex.user@example.com"}),
		},
	})
	writeFixtureFile(t, filepath.Join(codexHome, "config.toml"), `
[mcp_servers.github]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-github@2.0.1"]
[mcp_servers.github.env]
GITHUB_TOKEN = ""

[mcp_servers.internal_docs]
url = "https://docs.internal.example.com/mcp/sse?apikey="
`)
}

// setupClaudeFixture writes the Claude Code account file with a remote server
// at user scope and a local uvx server at project scope.
func setupClaudeFixture(t *testing.T, home, workspace string) {
	t.Helper()
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	writeJSON(t, filepath.Join(home, ".claude.json"), map[string]any{
		"oauthAccount": map[string]any{"emailAddress": "claude.user@example.com"},
		"mcpServers": map[string]any{
			"sentry": map[string]any{
				"url":     "https://mcp.sentry.dev/sse",
				"headers": map[string]string{"Authorization": "Bearer"},
			},
		},
	})
	writeJSON(t, filepath.Join(workspace, ".mcp.json"), map[string]any{
		"mcpServers": map[string]any{
			"db-tools": map[string]any{
				"command": "uvx",
				"args":    []string{"mcp-server-postgres==0.7.1"},
				"env":     map[string]string{"PGPASSWORD": ""},
			},
		},
	})
}

// setupCursorFixture writes a docker-runner server, an OAuth remote server,
// and a disabled server that must not appear in the projection.
func setupCursorFixture(t *testing.T, home, workspace string) {
	t.Helper()
	writeJSON(t, filepath.Join(home, ".cursor", "mcp.json"), map[string]any{
		"mcpServers": map[string]any{
			"grafana": map[string]any{
				"command": "docker",
				"args":    []string{"run", "-i", "--rm", "-e", "GRAFANA_TOKEN", "grafana/mcp-grafana:1.4.0"},
			},
			"figma": map[string]any{
				"url":              "https://mcp.figma.com/sse",
				"authProviderType": "oauth",
			},
			"retired": map[string]any{
				"command":  "npx",
				"args":     []string{"-y", "old-server"},
				"disabled": true,
			},
		},
	})
}

func writeFixtureFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

// TestCaptureHookEventSamples captures every supported connector and event,
// asserts the projection invariants, and optionally refreshes the committed
// samples.
func TestCaptureHookEventSamples(t *testing.T) {
	sampleDir := filepath.Join("testdata", "samples")
	writeSamples := os.Getenv(writeSamplesEnv) != ""
	if writeSamples {
		if err := os.MkdirAll(sampleDir, 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
	}

	for _, tc := range sampleCases() {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			workspace := filepath.Join(home, "workspace")
			setHome(t, home)
			t.Setenv(EnableEnv, "1")
			t.Setenv(SpoolDirEnv, filepath.Join(home, "spool"))
			if err := os.MkdirAll(workspace, 0o700); err != nil {
				t.Fatalf("MkdirAll: %v", err)
			}
			tc.setup(t, home, workspace)
			writeSampleDeviceKey(t, home)

			payload := strings.ReplaceAll(tc.payload, "%WORKSPACE%", jsonPathValue(workspace))
			written, err := CaptureHookEvent(HookContext{
				Connector:       tc.connector,
				Event:           tc.event,
				Payload:         []byte(payload),
				Home:            home,
				ProducerVersion: "v1.0.0",
				ReceivedAt:      time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC),
			})
			if err != nil {
				t.Fatalf("CaptureHookEvent: %v", err)
			}
			if len(written) == 0 {
				t.Fatal("no records written")
			}

			for _, path := range written {
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("ReadFile: %v", err)
				}
				assertNoWorkspaceLeak(t, raw, workspace)

				normalized := normalizeSample(t, raw)
				if !writeSamples {
					continue
				}
				name := sampleFileName(tc.name, filepath.Base(path))
				if err := os.WriteFile(filepath.Join(sampleDir, name), normalized, 0o644); err != nil {
					t.Fatalf("WriteFile: %v", err)
				}
			}
		})
	}
}

// writeSampleDeviceKey installs a device key so samples show a populated
// device id. The value is a fixed, non-secret seed used only by this test.
func writeSampleDeviceKey(t *testing.T, home string) {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	pem := "-----BEGIN DEFENSECLAW DEVICE KEY-----\n" +
		base64Std(seed) + "\n-----END DEFENSECLAW DEVICE KEY-----\n"
	writeFixtureFile(t, DefaultDeviceKeyFile(home), pem)
}

// jsonPathValue escapes a filesystem path for embedding in a JSON string,
// which matters on Windows where separators are backslashes.
func jsonPathValue(path string) string {
	encoded, err := json.Marshal(path)
	if err != nil {
		return ""
	}
	return strings.Trim(string(encoded), `"`)
}

// assertNoWorkspaceLeak confirms the workspace path, used only to locate MCP
// config, never reached the record.
func assertNoWorkspaceLeak(t *testing.T, raw []byte, workspace string) {
	t.Helper()
	for _, form := range []string{workspace, filepath.ToSlash(workspace)} {
		if strings.Contains(string(raw), form) {
			t.Errorf("record leaked the workspace path %q", form)
		}
	}
}

// sampleFileName derives a stable sample name from the spool filename, whose
// timestamp and nonce vary per run.
func sampleFileName(caseName, spoolName string) string {
	if strings.HasPrefix(spoolName, "agent-") {
		return caseName + ".inventory.json"
	}
	return caseName + ".event.json"
}

// normalizeSample replaces host- and run-specific values with placeholders so
// samples are stable across machines and do not record a developer's
// hostname, account name, or numeric identifiers.
func normalizeSample(t *testing.T, raw []byte) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	for _, key := range []string{"emitted_at", "created_at", "updated_at", "first_seen", "last_seen"} {
		if _, present := doc[key]; present {
			doc[key] = "<timestamp>"
		}
	}
	normalizeSampleBlock(doc)
	for _, key := range []string{"session_start", "pre_tool_use"} {
		if block, ok := doc[key].(map[string]any); ok {
			normalizeSampleBlock(block)
		}
	}
	// Encode without HTML escaping so the <placeholder> markers stay legible
	// instead of becoming \u003c sequences.
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(doc); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	return buf.Bytes()
}

func normalizeSampleBlock(block map[string]any) {
	if _, present := block["mcp_discovered_at"]; present {
		block["mcp_discovered_at"] = "<timestamp>"
	}
	if user, ok := block["user"].(map[string]any); ok {
		// The join key's presence is the point; its value identifies a person.
		if _, present := user["uid"]; present {
			user["uid"] = "<effective-uid>"
		}
		if _, present := user["sid"]; present {
			user["sid"] = "<windows-token-sid>"
		}
	}
	if device, ok := block["device"].(map[string]any); ok {
		if _, present := device["hostname"]; present {
			device["hostname"] = "<hostname>"
		}
		if _, present := device["username"]; present {
			device["username"] = "<os-username>"
		}
	}
}

func base64Std(data []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var b strings.Builder
	for i := 0; i < len(data); i += 3 {
		chunk := data[i:]
		if len(chunk) > 3 {
			chunk = chunk[:3]
		}
		var buf [3]byte
		copy(buf[:], chunk)
		value := uint32(buf[0])<<16 | uint32(buf[1])<<8 | uint32(buf[2])
		b.WriteByte(alphabet[value>>18&0x3f])
		b.WriteByte(alphabet[value>>12&0x3f])
		if len(chunk) > 1 {
			b.WriteByte(alphabet[value>>6&0x3f])
		} else {
			b.WriteByte('=')
		}
		if len(chunk) > 2 {
			b.WriteByte(alphabet[value&0x3f])
		} else {
			b.WriteByte('=')
		}
	}
	return b.String()
}
