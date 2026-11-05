// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGAP0518VerifiedOrdinaryNoAnswerFollowsTier(t *testing.T) {
	shortAnswerBudget(t, 300*time.Millisecond)
	addr := hungGateway(t)
	client, err := NewPerUserGatewayHTTPClient(2*time.Second, addr)
	if err != nil {
		t.Fatal(err)
	}
	cwd := t.TempDir()
	file := filepath.Join(cwd, "hello.txt")
	if err := os.WriteFile(file, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, mode, tool, input string
		blocks                  bool
	}{
		{"default read", "open", "Read", `{"file_path":` + mustJSONString(file) + `}`, false},
		{"default shell", "open", "Bash", `{"command":` + mustJSONString("cat "+file) + `}`, false},
		{"strict shell", "closed", "Bash", `{"command":` + mustJSONString("cat "+file) + `}`, true},
		{"protected shell", "open", "Bash", `{"command":"cp source ~/.ssh/authorized_keys"}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"hook_event_name":"PreToolUse","tool_name":` + mustJSONString(tc.tool) +
				`,"cwd":` + mustJSONString(cwd) + `,"tool_input":` + tc.input + `}`
			result, _ := runAgainstGateway(t, "claudecode", addr, func(opts *Options) {
				opts.HTTPClient = client
				opts.FailMode = tc.mode
				opts.OutageFailModeNow = func() string { return tc.mode }
				opts.Stdin = strings.NewReader(body)
			})
			if blocked := claudeBlocked(result); blocked != tc.blocks {
				t.Fatalf("blocked=%t, want %t: code=%d stdout=%q stderr=%q", blocked, tc.blocks, result.code, result.stdout, result.stderr)
			}
			if !tc.blocks && !strings.Contains(result.stdout+result.stderr, "DefenseClaw") {
				t.Fatalf("allowed deadline had no visible warning: %q %q", result.stdout, result.stderr)
			}
		})
	}
}

func TestGAP0518OrdinaryProofRejectsProtectedLinkAndKnownValue(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	key := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.MkdirAll(cwd, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(key), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(cwd, "alias.txt")
	if err := os.Symlink(key, link); err != nil {
		t.Fatal(err)
	}
	call := func(tool, input string) []byte {
		return []byte(`{"hook_event_name":"PreToolUse","tool_name":` + mustJSONString(tool) +
			`,"cwd":` + mustJSONString(cwd) + `,"tool_input":` + input + `}`)
	}
	for _, body := range [][]byte{
		call("Read", `{"file_path":`+mustJSONString(link)+`}`),
		call("Bash", `{"command":"p=~/.ssh/authorized_keys; cp source \"$p\""}`),
		call("Bash", `{"command":"echo marker >> ~/.defenseclaw/config.yaml"}`),
	} {
		if ordinaryNoAnswerPayloadInHome(body, home) {
			t.Fatalf("protected call got an ordinary proof: %s", body)
		}
	}
	if !ordinaryNoAnswerPayloadInHome(call("Bash", `{"command":"echo hello"}`), home) {
		t.Fatal("ordinary command has no local proof")
	}
}

func TestGAP0518LongOrdinaryTouchNoAnswer(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	if err := os.Mkdir(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 2000)
	for i := range names {
		names[i] = fmt.Sprintf("lo%d.txt", i)
	}
	call := func(parts []string) []byte {
		return []byte(`{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":` +
			mustJSONString(cwd) + `,"tool_input":{"command":` + mustJSONString("touch "+strings.Join(parts, " ")) + `}}`)
	}
	if !ordinaryNoAnswerPayloadInHome(call(names), home) {
		t.Fatal("ordinary long touch has no local proof")
	}
	shortAnswerBudget(t, 300*time.Millisecond)
	addr := hungGateway(t)
	result, _ := runAgainstGateway(t, "claudecode", addr, func(opts *Options) {
		opts.FailMode = "open"
		opts.OutageFailModeNow = func() string { return "open" }
		opts.Stdin = strings.NewReader(string(call(names)))
	})
	if claudeBlocked(result) || !strings.Contains(result.stdout+result.stderr, "DefenseClaw") {
		t.Fatalf("ordinary long touch at deadline: code=%d stdout=%q stderr=%q", result.code, result.stdout, result.stderr)
	}
	for _, index := range []int{0, len(names) / 2, len(names) - 1} {
		withKey := append([]string(nil), names...)
		withKey[index] = "../.ssh/authorized_keys"
		if ordinaryNoAnswerPayloadInHome(call(withKey), home) {
			t.Fatalf("protected target at %d received a local proof", index)
		}
	}
}
