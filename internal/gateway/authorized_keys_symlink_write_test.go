// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

func TestAuthorizedKeysSymlinkWriteStatementsAndClientResolution(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX authorized_keys matcher is separate from the Windows enterprise path")
	}
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	input := actionfacts.Input{Tool: "Bash", CWD: cwd, ActiveHome: home, DialectHint: actionfacts.DialectPOSIX}
	for _, row := range []struct {
		name, command string
		want          bool
	}{
		{"semicolon x", "ln -s ~/.ssh/authorized_keys ./x.cfg; echo marker >> ./x.cfg", true},
		{"newline z", "ln -sf $HOME/.ssh/authorized_keys ./z.cfg\necho marker >> ./z.cfg", true},
		{"and ak", "ln -s ~/.ssh/authorized_keys ./ak.lnk && echo marker >> ./ak.lnk", true},
		{"truncate", "ln -s ~/.ssh/authorized_keys ./ak.lnk; echo marker > ./ak.lnk", true},
		{"tee", "ln -s ~/.ssh/authorized_keys ./ak.lnk; echo marker | tee -a ./ak.lnk", true},
		{"copy", "ln -s ~/.ssh/authorized_keys ./ak.lnk; cp marker.pub ./ak.lnk", true},
		{"dd", "ln -s ~/.ssh/authorized_keys ./ak.lnk; dd if=marker.pub of=./ak.lnk", true},
		{"sed", "ln -s ~/.ssh/authorized_keys ./ak.lnk; sed -i s/old/new/ ./ak.lnk", true},
		{"or x", "ln -sf ~/.ssh/authorized_keys ./x.cfg || echo marker >> ./x.cfg", true},
		{"intervening command", "ln -s ~/.ssh/authorized_keys ./z.cfg; true; echo marker >> ./z.cfg", true},
		{"brace group", "{ ln -s ~/.ssh/authorized_keys ./x.cfg; echo marker >> ./x.cfg; }", true},
		{"subshell", "(ln -s ~/.ssh/authorized_keys ./x.cfg; echo marker >> ./x.cfg)", true},
		{"if body", "if true; then ln -s ~/.ssh/authorized_keys ./x.cfg; echo marker >> ./x.cfg; fi", true},
		{"for body", "for i in 1; do ln -s ~/.ssh/authorized_keys ./x.cfg; echo marker >> ./x.cfg; done", true},
		{"different target", "ln -s ~/proj/notes.txt ./x.cfg; echo marker >> ./x.cfg", false},
		{"different name", "ln -s ~/.ssh/authorized_keys ./x.cfg; echo marker >> ./z.cfg", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			input.Command = row.command
			if got := trustedAuthorizedKeysSymlinkWrite(input); got != row.want {
				t.Fatalf("symlink write proof = %v, want %v", got, row.want)
			}
		})
	}
	t.Run("protected home leaves gateway cwd empty", func(t *testing.T) {
		input.Tool = "exec_command"
		input.Command = ""
		input.CWD = ""
		input.Args = json.RawMessage(`{"cmd":"echo marker >> ~/proj/x.cfg"}`)
		facts := actionfacts.Analyze(input)
		request := trustedActionRequest{Input: input, Connector: "codex", ResolvedWriteTargets: map[string]string{
			hookpaths.CWDKey:                     cwd,
			filepath.Join(home, "proj", "x.cfg"): filepath.Join(home, ".ssh", "authorized_keys"),
		}}
		if !trustedExistingAuthorizedKeysSymlinkWrite(request, facts) {
			t.Fatal("client-resolved home write was allowed without a gateway-visible cwd")
		}
		input.CWD = cwd
	})
	t.Run("relative write with protected gateway cwd", func(t *testing.T) {
		input.Tool = "exec_command"
		input.Command, input.CWD = "", ""
		input.Args = json.RawMessage(`{"cmd":"echo marker >> ./x.cfg"}`)
		facts := actionfacts.Analyze(input)
		request := trustedActionRequest{Input: input, Connector: "codex", ResolvedWriteTargets: map[string]string{
			hookpaths.CWDKey:            cwd,
			filepath.Join(cwd, "x.cfg"): filepath.Join(home, ".ssh", "authorized_keys"),
		}}
		if !trustedExistingAuthorizedKeysSymlinkWrite(request, facts) {
			t.Fatal("client-resolved relative write was allowed without a gateway-visible cwd")
		}
		input.CWD = cwd
	})
	for _, row := range []struct {
		name, command, target string
		want                  bool
	}{
		{"existing link", "echo marker >> ./x.cfg", filepath.Join(home, ".ssh", "authorized_keys"), true},
		{"home tilde link", "echo marker >> ~/proj/x.cfg", filepath.Join(home, ".ssh", "authorized_keys"), true},
		{"resolution failed", "echo marker >> ./x.cfg", "", true},
		{"regular file", "echo marker >> ./x.cfg", filepath.Join(cwd, "x.cfg"), false},
	} {
		t.Run(row.name, func(t *testing.T) {
			input.Command = row.command
			facts := actionfacts.Analyze(input)
			request := trustedActionRequest{Input: input, ResolvedWriteTargets: map[string]string{filepath.Join(cwd, "x.cfg"): row.target}}
			if got := trustedExistingAuthorizedKeysSymlinkWrite(request, facts); got != row.want {
				t.Fatalf("existing symlink proof = %v, want %v; paths=%v", got, row.want, facts.Paths)
			}
		})
	}
	t.Run("partial cmd projection uses client target", func(t *testing.T) {
		input.Tool = "exec_command"
		input.Command = ""
		input.Args = json.RawMessage(`{"cmd":"echo marker >> ~/proj/x.cfg"}`)
		facts := actionfacts.Analyze(input)
		request := trustedActionRequest{Input: input, Connector: "codex", ResolvedWriteTargets: map[string]string{
			filepath.Join(cwd, "x.cfg"): filepath.Join(home, ".ssh", "authorized_keys"),
		}}
		if !trustedExistingAuthorizedKeysSymlinkWrite(request, facts) {
			t.Fatal("partial command did not use the client-resolved write target")
		}
	})
	for _, connector := range []string{"codex", "claudecode"} {
		t.Run("older "+connector+" client cannot resolve home path", func(t *testing.T) {
			input.Command = "echo marker >> ./missing.cfg"
			facts := actionfacts.Analyze(input)
			request := trustedActionRequest{Input: input, Connector: connector, ProtectedHomeHook: true}
			if !trustedExistingAuthorizedKeysSymlinkWrite(request, facts) {
				t.Fatal("missing client evidence for an unresolved home write was allowed")
			}
		})
	}
	keys := filepath.Join(home, "authorized_keys")
	link := filepath.Join(home, "existing.cfg")
	if err := os.WriteFile(keys, []byte("marker"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(keys, link); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{
		"tool_name": "Bash", "tool_input": map[string]any{"command": "echo marker >> " + link},
	})
	if err != nil {
		t.Fatal(err)
	}
	targets, ok := hookpaths.Decode(hookpaths.Resolve(payload))
	if !ok || targets[link] != keys {
		t.Fatalf("hook client target = %q, want %q", targets[link], keys)
	}
	if err := os.Mkdir(filepath.Join(home, "proj"), 0o700); err != nil {
		t.Fatal(err)
	}
	homeLink := filepath.Join(home, "proj", "x.cfg")
	if err := os.Symlink(keys, homeLink); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	payload, err = json.Marshal(map[string]any{
		"tool_name": "Bash", "tool_input": map[string]any{"command": "echo marker >> ~/proj/x.cfg"},
	})
	if err != nil {
		t.Fatal(err)
	}
	targets, ok = hookpaths.Decode(hookpaths.Resolve(payload))
	if !ok || targets[homeLink] != keys {
		t.Fatalf("hook client home target = %q, want %q; all=%v", targets[homeLink], keys, targets)
	}
	payload, err = json.Marshal(map[string]any{
		"toolName": "Bash", "toolInput": map[string]any{"cmd": "echo marker >> ~/proj/x.cfg"},
	})
	if err != nil {
		t.Fatal(err)
	}
	targets, ok = hookpaths.Decode(hookpaths.Resolve(payload))
	if !ok || targets[homeLink] != keys {
		t.Fatalf("hook client cmd target = %q, want %q; all=%v", targets[homeLink], keys, targets)
	}
}

func TestAuthorizedKeysWriteTargetCap(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX hook write targets")
	}
	root := t.TempDir()
	home := filepath.Join(root, "home")
	external := filepath.Join(root, "external")
	for _, dir := range []string{filepath.Join(home, ".ssh"), external} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(keys, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(external, "linked.cfg")
	if err := os.Symlink(keys, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	for _, count := range []int{31, 32, 40} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			writes := make([]string, 0, count+1)
			for i := range count {
				writes = append(writes, fmt.Sprintf("echo marker > %s", filepath.Join(external, fmt.Sprintf("benign-%02d", i))))
			}
			writes = append(writes, "echo marker >> "+link)
			command := strings.Join(writes, "; ")
			payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "tool_input": map[string]any{"command": command}})
			if err != nil {
				t.Fatal(err)
			}
			targets, ok := hookpaths.Decode(hookpaths.Resolve(payload))
			if !ok || targets[hookpaths.CWDKey] == "" {
				t.Fatalf("hook evidence lost cwd or failed to decode: ok=%v", ok)
			}
			if count == 31 && targets[link] != keys {
				t.Fatalf("final write resolved to %q, want %q", targets[link], keys)
			}
			if count > 31 && targets["\x00truncated"] != "1" {
				t.Fatal("omitted write target was not marked as truncated")
			}
			input := actionfacts.Input{Tool: "Bash", Command: command, CWD: root, ActiveHome: home, DialectHint: actionfacts.DialectPOSIX}
			request := trustedActionRequest{Input: input, Connector: "codex", ProtectedHomeHook: true, ResolvedWriteTargets: targets}
			if !trustedExistingAuthorizedKeysSymlinkWrite(request, actionfacts.Analyze(input)) {
				t.Fatal("protected linked write was allowed")
			}
		})
	}
}
