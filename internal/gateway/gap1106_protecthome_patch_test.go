// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// GAP-1106 / GAP-0781: behind ProtectHome the managed gateway cannot resolve
// the targets of a Codex apply_patch envelope in the user's home, and an
// unknown target set was the SSH rule. The user's hook resolved each target;
// a patch whose targets resolve to ordinary files is allowed, and a patch of
// a key alias or of authorized_keys still blocks.
func TestR105ProtectHomeCodexPatchUsesClientTargets(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway walk")
	}
	root := t.TempDir()
	homes := filepath.Join(root, "homes")
	home := filepath.Join(homes, "eng1")
	project := filepath.Join(home, "project1")
	keyDir := filepath.Join(home, ".ssh")
	for _, dir := range []string{keyDir, project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(keyDir, "authorized_keys")
	for file, data := range map[string]string{keys: "# base\n", filepath.Join(project, "greet.sh"): "#!/bin/bash\necho \"Hello\"\n",
		filepath.Join(project, "race.txt"): "first-line\n"} {
		if err := os.WriteFile(file, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(keys, filepath.Join(project, "keylink")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Cleanup(func() { _ = os.Chmod(homes, 0o700) })
	greet := "*** Begin Patch\n*** Update File: greet.sh\n@@\n #!/bin/bash\n+# greeting script\n echo \"Hello\"\n*** End Patch\n"
	key := "*** Begin Patch\n*** Update File: keylink\n@@\n # base\n+key-marker\n*** End Patch\n"
	addKey := "*** Begin Patch\n*** Add File: ../.ssh/authorized_keys2\n+key-marker\n*** End Patch\n"
	cases := []struct {
		name, tool, text string
		want             bool
	}{
		{"exec heredoc race.txt", "exec_command", "if ! rg -q 'second-line' race.txt; then\n  apply_patch <<'PATCH'\n*** Begin Patch\n*** Update File: race.txt\n@@\n first-line\n+second-line\n*** End Patch\nPATCH\nfi", false},
		{"exec heredoc greet.sh", "exec_command", "apply_patch <<'EOF'\n" + greet + "EOF", false},
		{"apply_patch tool greet.sh", "apply_patch", greet, false},
		{"exec apply_patch help", "exec_command", "apply_patch --help", false},
		{"exec heredoc key alias", "exec_command", "apply_patch <<'EOF'\n" + key + "EOF", true},
		{"apply_patch tool key alias", "apply_patch", key, true},
		{"apply_patch tool adds authorized_keys2", "apply_patch", addKey, true},
		{"exec bash -lc heredoc race.txt (GAP-0781 kvm2 live call)", "exec_command", "bash -lc 'if ! rg -Fxq \"second-line\" race.txt 2>/dev/null; then apply_patch <<'PATCH'\n*** Begin Patch\n*** Update File: race.txt\n@@\n+second-line\n*** End Patch\nPATCH\nfi'", false},
		{"exec bash -lc heredoc key alias", "exec_command", "bash -lc 'apply_patch <<'PATCH'\n" + key + "PATCH'", true},
		{"exec dynamic envelope naming the key directory", "exec_command", "apply_patch \"$(cat ~/.ssh/k.patch)\"", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.Chmod(homes, 0o700); err != nil {
				t.Fatal(err)
			}
			input := map[string]any{"cmd": tc.text}
			if tc.tool == "apply_patch" {
				input = map[string]any{"command": tc.text}
			}
			body, err := json.Marshal(map[string]any{"session_id": "gap1106", "hook_event_name": "PreToolUse",
				"tool_name": tc.tool, "cwd": project, "tool_input": input})
			if err != nil {
				t.Fatal(err)
			}
			evidence := hookpaths.Resolve(body)
			if err := os.Chmod(homes, 0); err != nil {
				t.Fatal(err)
			}
			got := overLimitHostHookWithEvidence(t, "codex", home, string(body), evidence)
			if blocked := nativeWriteBlocked(t, got); blocked != tc.want {
				t.Fatalf("blocked = %t, want %t: %.600s", blocked, tc.want, got)
			}
		})
	}
}
