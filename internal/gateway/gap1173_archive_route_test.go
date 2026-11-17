// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func gap1173Archives(t *testing.T, project string) (string, string) {
	t.Helper()
	tarf := filepath.Join(project, "state.tar")
	zipf := filepath.Join(project, "state.zip")
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	content := []byte("test: true\n")
	if err := w.WriteHeader(&tar.Header{Name: ".defenseclaw/config.yaml", Mode: 0o600, Size: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tarf, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(zipf)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(file)
	member, err := zw.Create(".defenseclaw/config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := member.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return tarf, zipf
}

func TestGAP1173WindowsHomeReach(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows home spellings")
	}
	for _, home := range []string{t.TempDir(), `\\test-server\share\person`} {
		reaches, ok := stateReachFunc(actionfacts.Facts{ActiveHome: home}, trustedActionRequest{
			ProtectedHomeHook: true, SkipLocalFilesystemResolution: true,
		})
		if !ok || !reaches(filepath.Join(home, ".defenseclaw", "config.yaml")) {
			t.Errorf("absolute home %q was not active", home)
		}
	}
}

func gap1173Hook(t *testing.T, api *APIServer, home, cwd, connector, tool, command string, managedPeer bool) string {
	t.Helper()
	input := map[string]any{"command": command}
	if connector == "codex" {
		input = map[string]any{"cmd": command, "workdir": cwd}
	}
	if connector == "copilot" {
		tool = "run_in_terminal"
	}
	body := mustJSON(t, map[string]any{"session_id": "gap1173", "hook_event_name": "PreToolUse",
		"cwd": cwd, "tool_name": tool, "tool_use_id": "gap1173-call", "tool_input": input})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", bytes.NewReader(body))
	if connector == "codex" {
		setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
	}
	if connector == "copilot" {
		req.Header.Set("X-DefenseClaw-Copilot-Event", "preToolUse")
	}
	if managedPeer {
		header := hookpaths.ResolveConnector(connector, "", "PreToolUse", body)
		req.Header.Set(hookpaths.Header, header)
		req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
	}
	w := httptest.NewRecorder()
	api.handleAgentHook(connector).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("hook status %d: %.200s", w.Code, w.Body.String())
	}
	var answer struct {
		Action string `json:"action"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &answer); err != nil {
		t.Fatal(err)
	}
	return answer.Action
}

// GAP-1173: every row reaches the real hook route. A destination equal to
// the state root blocks even when the archive members are not named in the
// command. Whole-archive calls into the home use the member listing.
func TestGAP1173ArchiveExtractionHookRoutes(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "project")
	if err := os.MkdirAll(filepath.Join(home, ".defenseclaw"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".defenseclaw", "config.yaml"), []byte("test: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	tarfile, zipfile := gap1173Archives(t, project)
	slash := filepath.ToSlash
	state := slash(filepath.Join(home, ".defenseclaw"))
	rows := []struct{ name, connector, tool, command string }{
		{"tar-root", "claudecode", "Bash", `tar -xf ` + slash(tarfile) + ` -C ~/.defenseclaw`},
		{"tar-home-member", "claudecode", "Bash", `tar -xf ` + slash(tarfile) + ` -C ~`},
		{"unzip-root", "codex", "exec_command", `unzip -o ` + slash(zipfile) + ` -d ~/.defenseclaw`},
		{"unzip-home-member", "copilot", "run_in_terminal", `unzip -o ` + slash(zipfile) + ` -d ~`},
		{"sevenzip-root", "copilot", "run_in_terminal", `7z x ` + slash(zipfile) + ` -o` + state},
		{"python-tar", "claudecode", "Bash", `python3 -c 'import tarfile; tarfile.open("` + slash(tarfile) + `").extractall("` + state + `")'`},
		{"python-zip", "codex", "exec_command", `python3 -c 'import zipfile; zipfile.ZipFile("` + slash(zipfile) + `").extractall("` + state + `")'`},
		{"python-shutil", "copilot", "run_in_terminal", `python3 -c 'import shutil; shutil.unpack_archive("` + slash(zipfile) + `", "` + state + `")'`},
	}
	if runtime.GOOS == "windows" {
		rows = append(rows,
			struct{ name, connector, tool, command string }{"expand-archive", "claudecode", "PowerShell", `Expand-Archive -Path '` + slash(zipfile) + `' -DestinationPath '` + state + `'`},
			struct{ name, connector, tool, command string }{"zipfile-dotnet", "claudecode", "PowerShell", `[System.IO.Compression.ZipFile]::ExtractToDirectory('` + slash(zipfile) + `','` + state + `')`},
		)
	}
	for _, tier := range boundedTestTiers {
		for _, row := range rows {
			t.Run(tier.name+"/"+row.name, func(t *testing.T) {
				api := instructionProtectionTestAPIWithPack(t, row.connector, "action", "", tier.posture)
				if tier.managed {
					api.scannerCfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
					api.scannerCfg.Enterprise.Profile = managed.ProfileStandalone
				}
				if action := gap1173Hook(t, api, home, project, row.connector, row.tool, row.command, tier.managed); action != "block" {
					t.Errorf("%s: action %q, want block", row.name, action)
				}
			})
		}
	}
}
