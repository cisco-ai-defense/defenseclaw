// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

func TestGAP0624AuthorizedKeysTextIsData(t *testing.T) {
	home, project := dynamicWordParityProject(t)
	rows := []struct {
		name, command string
		block         bool
	}{
		{"node report text", `node -e 'require("fs").writeFileSync("/tmp/report.txt", "~/.ssh/authorized_keys")'`, false},
		{"node JSON report", `node -e 'require("fs").writeFileSync(process.env.HOME + "/report.json", JSON.stringify({path:"~/.ssh/authorized_keys"}))'`, false},
		{"echo log text", `echo "checked ~/.ssh/authorized_keys permissions" >> ~/app.log`, false},
		{"node append text", `node -e 'require("fs").appendFileSync("/tmp/log", "/home/alice/.ssh/authorized_keys")'`, false},
		{"node nested JSON data", `node -e 'require("fs").writeFileSync("/tmp/report.txt", JSON.stringify({files:["~/.ssh/authorized_keys", "notes.txt"]}))'`, false},
		{"node long eval data", `node --eval 'require("fs").writeFileSync("/tmp/report.txt", "~/.ssh/authorized_keys")'`, false},
		{"node protected destination", `node -e 'require("fs").writeFileSync(process.env.HOME + "/.ssh/authorized_keys", "marker")'`, true},
		{"node protected append", `node -e 'require("fs").appendFileSync(process.env.HOME + "/.ssh/authorized_keys", "marker")'`, true},
		{"node protected link destination", `node -e 'require("fs").writeFileSync("disklink", "~/.ssh/authorized_keys")'`, true},
		{"shell protected append", `echo marker >> ~/.ssh/authorized_keys`, true},
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, managed := range []bool{false, true} {
			for _, row := range rows {
				t.Run(fmt.Sprintf("%s/managed=%t/%s", connector, managed, row.name), func(t *testing.T) {
					got := postDynamicWordParity(t, home, project, connector, managed, row.command, nil)
					if row.block {
						if !strings.HasPrefix(got, `{"action":"block"`) ||
							!strings.Contains(got, "persistence.ssh_authorized_keys_command") {
							t.Fatalf("protected destination = %.300s", got)
						}
					} else if !strings.HasPrefix(got, `{"action":"allow"`) ||
						strings.Contains(got, "persistence.ssh_authorized_keys_command") {
						t.Fatalf("ordinary data = %.300s", got)
					}
				})
			}
		}
	}
}

func TestGAP0624StrictRetainsInlineDataMention(t *testing.T) {
	home, project := dynamicWordParityProject(t)
	for _, connector := range []string{"claudecode", "codex"} {
		for _, managed := range []bool{false, true} {
			for _, command := range []string{
				`node -e 'require("fs").writeFileSync("/tmp/report.txt", "~/.ssh/authorized_keys")'`,
				`node -e 'require("fs").writeFileSync(process.env.HOME + "/report.json", JSON.stringify({path:"~/.ssh/authorized_keys"}))'`,
			} {
				t.Run(fmt.Sprintf("%s/managed=%t/%s", connector, managed, command), func(t *testing.T) {
					cfg := &config.Config{}
					cfg.Guardrail.Mode = "action"
					cfg.Guardrail.Connector = connector
					cfg.Guardrail.RulePack = "strict"
					api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
					body := mustJSON(t, map[string]any{"session_id": "gap0624-strict", "hook_event_name": "PreToolUse",
						"tool_name": "Bash", "cwd": project, "tool_input": map[string]any{"command": command, "description": "d"}})
					req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(body)))
					if connector == "codex" {
						setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
					}
					if managed {
						req.Header.Set(hookpaths.Header, hookpaths.Resolve(body))
						req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
					}
					recorder := httptest.NewRecorder()
					api.handleAgentHook(connector).ServeHTTP(recorder, req)
					if got := recorder.Body.String(); !strings.HasPrefix(got, `{"action":"block"`) ||
						!strings.Contains(got, "persistence.ssh_authorized_keys_command") {
						t.Fatalf("strict text mention = %.300s", got)
					}
				})
			}
		}
	}
}
