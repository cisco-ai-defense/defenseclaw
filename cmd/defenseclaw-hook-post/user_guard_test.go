// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestGAP0322UserGuardDecisionAndBenignTwin(t *testing.T) {
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("Bash is required")
	}
	account := t.TempDir()
	bin := filepath.Join(account, ".local", "bin")
	home := filepath.Join(account, ".defenseclaw")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	native := filepath.Join(bin, "defenseclaw-hook-user")
	self := filepath.Join(bin, "defenseclaw-hook-post")
	body := "#!/bin/bash -p\nread -r value\ncase \"$value\" in\n  protected|down) echo 'review denied' >&2; exit 2;;\n  ordinary) echo '{\"action\":\"allow\"}'; exit 0;;\nesac\nexit 2\n"
	if err := os.WriteFile(native, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	startup := filepath.Join(account, "startup.sh")
	if err := os.WriteFile(startup, []byte("exit 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"guard-user-hook", native, "hook", "--connector", "claudecode", "--hook-home", home}
	for _, tc := range []struct {
		name string
		env  map[string]string
	}{
		{"plain", nil},
		{"noexec", map[string]string{"SHELLOPTS": "noexec"}},
		{"errexit", map[string]string{"SHELLOPTS": "noexec:errexit"}},
		{"posix", map[string]string{"SHELLOPTS": "noexec:posix"}},
		{"startup", map[string]string{"SHELLOPTS": "noexec", "BASH_ENV": startup}},
		{"combined", map[string]string{"SHELLOPTS": "noexec", "BASH_ENV": startup, "FUNCNEST": "1", "BASHOPTS": "failglob:nullglob"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for key, value := range tc.env {
				t.Setenv(key, value)
			}
			for _, call := range []struct {
				input string
				code  int
			}{
				{"protected", 2},
				{"down", 2},
				{"ordinary", 0},
			} {
				var out, errOut bytes.Buffer
				code := runUserHookGuardAt(self, args, strings.NewReader(call.input+"\n"), &out, &errOut)
				if code != call.code || (call.code == 0 && !strings.Contains(out.String(), `"allow"`)) {
					t.Fatalf("%s: exit %d, stdout %q, stderr %q", call.input, code, out.String(), errOut.String())
				}
			}
		})
	}
	if err := os.Remove(native); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := runUserHookGuardAt(self, args, strings.NewReader("ordinary\n"), &out, &errOut); code != 2 {
		t.Fatalf("missing hook exit = %d, stderr %q", code, errOut.String())
	}
}

func TestGAP0322UserGuardSymlinkHomeAndOrdinaryTwin(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix account paths")
	}
	root := t.TempDir()
	realAccount := filepath.Join(root, "real")
	alias := filepath.Join(root, "alias")
	bin := filepath.Join(realAccount, ".local", "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realAccount, alias); err != nil {
		t.Fatal(err)
	}
	self := filepath.Join(bin, "defenseclaw-hook-post")
	if err := os.WriteFile(self, []byte("guard fixture\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	native := filepath.Join(bin, "defenseclaw-hook-user")
	if err := os.WriteFile(native, []byte("#!/bin/sh\nread value\n[ \"$value\" = ordinary ] && exit 0\nexit 2\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	args := []string{"guard-user-hook", filepath.Join(alias, ".local", "bin", "defenseclaw-hook-user"),
		"hook", "--connector", "claudecode", "--hook-home", filepath.Join(alias, ".defenseclaw")}
	for _, call := range []struct {
		input string
		want  int
	}{{"ordinary", 0}, {"protected", 2}} {
		var out, errOut bytes.Buffer
		if got := runUserHookGuardAt(self, args, strings.NewReader(call.input+"\n"), &out, &errOut); got != call.want {
			t.Fatalf("%s exit = %d, want %d; stderr %q", call.input, got, call.want, errOut.String())
		}
	}
}

func TestGAP0322UserGuardCursorTwin(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := runMain(nil, strings.NewReader(`{"cursor_version":"1"}`), &out, &errOut); code != 0 ||
		out.Len() != 0 || errOut.Len() != 0 {
		t.Fatalf("argument-free imported hook: exit %d, stdout %q, stderr %q", code, out.String(), errOut.String())
	}
	out.Reset()
	errOut.Reset()
	if code := runMain(nil, strings.NewReader(`{"hook_event_name":"PreToolUse","tool_input":{"command":"echo ok"}}`), &out, &errOut); code != 2 {
		t.Fatalf("argument-free Claude hook: exit %d, stdout %q, stderr %q", code, out.String(), errOut.String())
	}
}
