// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

func TestNativeCopilotPatchInPrivateManagedHome(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix private-home permissions")
	}
	private := filepath.Join(t.TempDir(), "private")
	project := filepath.Join(private, "project")
	if err := os.MkdirAll(project, 0700); err != nil {
		t.Fatal(err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(project, "keylink")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "old.txt"), []byte("old\n"), 0600); err != nil {
		t.Fatal(err)
	}
	type testCase struct {
		name, patch, want, rule string
		managed                 bool
		// proof is the patch the client evidence was made for, when it is
		// not the patch of the request.
		proof string
	}
	addAbs := "*** Begin Patch\n*** Add File: " + filepath.Join(project, "abs.txt") + "\n+ordinary project edit\n*** End Patch\n"
	keylinkAbs := "*** Begin Patch\n*** Update File: " + filepath.Join(project, "keylink") + "\n@@\n-old\n+new\n*** End Patch\n"
	cases := []testCase{
		{name: "ordinary project file", patch: "*** Begin Patch\n*** Add File: notes.txt\n+ordinary project edit\n*** End Patch\n", want: "allow", managed: true},
		{name: "protected link", patch: "*** Begin Patch\n*** Update File: keylink\n@@\n-old\n+new\n*** End Patch\n", want: "block", rule: "persistence.ssh_authorized_keys_command", managed: true},
		{name: "untrusted client proof", patch: "*** Begin Patch\n*** Add File: notes.txt\n+ordinary project edit\n*** End Patch\n", want: "block", rule: hookToolCallUnparsedRuleID},
		// Copilot names project files by absolute path as often as by a
		// relative one. ActionFacts refuses absolute patch paths, so the
		// gateway must bind those names to the evidence itself.
		{name: "absolute project file", patch: addAbs, want: "allow", managed: true},
		{name: "absolute update and move", patch: "*** Begin Patch\n*** Update File: " + filepath.Join(project, "old.txt") + "\n*** Move to: " + filepath.Join(project, "moved.txt") + "\n@@\n-old\n+new\n*** End Patch\n", want: "allow", managed: true},
		{name: "absolute and relative files", patch: "*** Begin Patch\n*** Add File: " + filepath.Join(project, "abs2.txt") + "\n+one\n*** Add File: rel2.txt\n+two\n*** Delete File: " + filepath.Join(project, "old.txt") + "\n*** End Patch\n", want: "allow", managed: true},
		{name: "absolute protected link", patch: keylinkAbs, want: "block", rule: "persistence.ssh_authorized_keys_command", managed: true},
		{name: "absolute protected link behind a benign file", patch: "*** Begin Patch\n*** Add File: " + filepath.Join(project, "abs3.txt") + "\n+one\n*** Update File: " + filepath.Join(project, "keylink") + "\n@@\n-old\n+new\n*** End Patch\n", want: "block", rule: "persistence.ssh_authorized_keys_command", managed: true},
		{name: "absolute target outside the evidence", patch: keylinkAbs, proof: addAbs, want: "block", rule: hookToolCallUnparsedRuleID, managed: true},
		{name: "absolute untrusted client proof", patch: addAbs, want: "block", rule: hookToolCallUnparsedRuleID},
	}
	// Every managed private-home payload of the benign corpus is replayed in
	// this private project, so the corpus gates the decision, not only the
	// projection.
	corpus, err := os.Open("testdata/copilot-native-benign.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer corpus.Close()
	lines := bufio.NewScanner(corpus)
	lines.Buffer(make([]byte, 0, 64<<10), 1<<20)
	replayed := 0
	for lines.Scan() {
		var item struct {
			ID      string `json:"id"`
			Fixture string `json:"fixture"`
			Input   struct {
				CWD       string `json:"cwd"`
				ToolCalls []struct {
					Args string `json:"args"`
				} `json:"toolCalls"`
			} `json:"input"`
		}
		if err := json.Unmarshal(lines.Bytes(), &item); err != nil {
			t.Fatal(err)
		}
		if item.Fixture != "managed-private-home" {
			continue
		}
		if len(item.Input.ToolCalls) != 1 || item.Input.CWD == "" {
			t.Fatalf("corpus %s is not one native patch call", item.ID)
		}
		replayed++
		cases = append(cases, testCase{name: "corpus " + item.ID, want: "allow", managed: true,
			patch: strings.ReplaceAll(item.Input.ToolCalls[0].Args, item.Input.CWD, project)})
	}
	if err := lines.Err(); err != nil {
		t.Fatal(err)
	}
	if replayed < 2 {
		t.Fatalf("benign corpus has %d managed private-home payloads, want at least 2", replayed)
	}
	type request struct {
		body   []byte
		header string
	}
	requests := make([]request, 0, len(cases))
	// The native hook runs as the user and can resolve its private project.
	// The managed gateway runs under a service account that cannot stat it.
	native := func(patch string) []byte {
		body, err := json.Marshal(map[string]any{
			"sessionId": "private-home", "cwd": project,
			"toolCalls": []any{map[string]any{"id": "custom_call_private", "name": "apply_patch", "args": patch}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	for _, tc := range cases {
		body := native(tc.patch)
		proof := body
		if tc.proof != "" {
			proof = native(tc.proof)
		}
		header := hookpaths.ResolveConnector("copilot", "", "preToolUse", proof)
		evidence, ok := hookpaths.Decode(header)
		if !ok || evidence[hookpaths.PatchCompleteKey] != "1" {
			t.Fatalf("%s client patch evidence incomplete: %v", tc.name, evidence)
		}
		requests = append(requests, request{body, header})
	}
	if err := os.Chmod(private, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(private, 0700) })
	if _, err := os.Stat(project); err == nil {
		t.Skip("test process can still traverse a private directory")
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "copilot"
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/copilot/hook", strings.NewReader(string(requests[i].body)))
			req.Header.Set("X-DefenseClaw-Copilot-Event", "preToolUse")
			req.Header.Set(hookpaths.Header, requests[i].header)
			if tc.managed {
				req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
			}
			w := httptest.NewRecorder()
			api.handleAgentHook("copilot").ServeHTTP(w, req)
			if !strings.Contains(w.Body.String(), `"action":"`+tc.want+`"`) ||
				(tc.rule == "" && strings.Contains(w.Body.String(), hookToolCallUnparsedRuleID)) {
				t.Fatalf("private-home %s: %s", tc.name, w.Body.String())
			}
			if tc.rule != "" && !strings.Contains(w.Body.String(), tc.rule) {
				t.Fatalf("private-home %s lost its rule: %s", tc.name, w.Body.String())
			}
		})
	}
}
