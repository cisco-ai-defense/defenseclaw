// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// GAP-1208: the real Copilot CLI permissionRequest for creating a project
// file (toolInput {file_path, diff}) is read and allowed on its own, in
// observe and action, with no preceding preToolUse to join: never
// HOOK-TOOL-CALL-UNPARSED.
func TestCopilotPermissionRequestProjectFileCreationIsAllowed(t *testing.T) {
	for _, mode := range []string{"observe", "action"} {
		t.Run(mode, func(t *testing.T) {
			input := copilotParallelCorpusInput(t, "windows-native-create-diff")
			cwd, _ := input["cwd"].(string)
			raw, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			project := t.TempDir()
			// file_path and cwd use backslashes, the diff forward slashes:
			// both name the same file under the session cwd.
			text := strings.ReplaceAll(string(raw), `\\`, `/`)
			from, to := strings.ReplaceAll(cwd, `\`, `/`), filepath.ToSlash(project)
			gitTo := to
			if !strings.HasPrefix(gitTo, "/") {
				gitTo = "/" + gitTo
			}
			for _, side := range []string{"a", "b"} {
				text = strings.ReplaceAll(text, side+"/"+from, side+gitTo)
			}
			text = strings.ReplaceAll(text, from, to)
			cfg := &config.Config{}
			cfg.Guardrail.Mode = mode
			cfg.Guardrail.Connector = "copilot"
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/copilot/hook", strings.NewReader(text))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-DefenseClaw-Copilot-Event", "permissionRequest")
			if header := hookpaths.ResolveConnector("copilot", "", "permissionRequest", []byte(text)); header != "" {
				req.Header.Set(hookpaths.Header, header)
			}
			w := httptest.NewRecorder()
			api.handleAgentHook("copilot").ServeHTTP(w, req)
			var verdict struct {
				Action string `json:"action"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &verdict); err != nil {
				t.Fatalf("not a verdict: %v: %s", err, w.Body.String())
			}
			if w.Code != http.StatusOK || verdict.Action != "allow" || strings.Contains(w.Body.String(), hookToolCallUnparsedRuleID) {
				t.Fatalf("project file creation permission: status=%d %s (body %s)", w.Code, w.Body.String(), text)
			}
		})
	}
}
