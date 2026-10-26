// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// GAP-1877: the hook client omitted every operand over 1024 bytes, so a
// plain redirect from a working directory over 1 KiB left a managed
// gateway behind ProtectHome with incomplete evidence, and the write was
// denied as an SSH authorized keys mutation. Operands up to the Linux
// PATH_MAX are now described.
func TestR105DeepWorkingDirectoryRedirectIsDescribed(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway walk")
	}
	root := t.TempDir()
	homes := filepath.Join(root, "homes")
	home := filepath.Join(homes, "eng1")
	parts := []string{home}
	for i := 0; i < 130; i++ {
		parts = append(parts, fmt.Sprintf("dir%04d", i))
	}
	deep := filepath.Join(parts...)
	if len(deep) <= 1030 {
		t.Fatalf("cwd is %d bytes", len(deep))
	}
	for _, dir := range []string{filepath.Join(home, ".ssh"), deep} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(keys, []byte("# base\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(keys, filepath.Join(deep, "keylink")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Cleanup(func() { _ = os.Chmod(homes, 0o700) })
	for command, want := range map[string]bool{
		"printf one > notes.txt":     false,
		"printf one >> keylink":      true,
		"cp keylink b && echo x > b": false,
	} {
		t.Run(command, func(t *testing.T) {
			if err := os.Chmod(homes, 0o700); err != nil {
				t.Fatal(err)
			}
			body, err := json.Marshal(map[string]any{"session_id": "gap1877", "hook_event_name": "PreToolUse",
				"tool_name": "exec_command", "cwd": deep, "tool_input": map[string]any{"cmd": command}})
			if err != nil {
				t.Fatal(err)
			}
			evidence := hookpaths.Resolve(body)
			if targets, ok := hookpaths.Decode(evidence); !ok || targets[hookpaths.TruncatedKey] != "" {
				t.Fatalf("evidence incomplete: %v", targets)
			}
			if err := os.Chmod(homes, 0); err != nil {
				t.Fatal(err)
			}
			got := overLimitHostHookWithEvidence(t, "codex", home, string(body), evidence)
			if blocked := nativeWriteBlocked(t, got); blocked != want {
				t.Fatalf("blocked = %t, want %t: %.400s", blocked, want, strings.TrimSpace(got))
			}
		})
	}
}
