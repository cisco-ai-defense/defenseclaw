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

// Classifier refix 1 (RV3-1): behind ProtectHome the managed gateway cannot
// read a staged patch file in the user's project. The user's hook read it
// and listed each directive target, resolved; a target that is (or links
// to) a protected key file blocks, an ordinary staged patch is allowed, and
// a file the hook could not read stays TGT-0194.
func TestR105ProtectHomeStagedPatchUsesClientTargets(t *testing.T) {
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
	for file, data := range map[string]string{
		keys:                                 "# base\n",
		filepath.Join(project, "greet.sh"):   "#!/bin/bash\necho \"Hello\"\n",
		filepath.Join(project, "ok.patch"):   "*** Begin Patch\n*** Update File: greet.sh\n@@\n #!/bin/bash\n+# greeting script\n echo \"Hello\"\n*** End Patch\n",
		filepath.Join(project, "key.patch"):  "*** Begin Patch\n*** Update File: keylink\n@@\n # base\n+key-marker\n*** End Patch\n",
		filepath.Join(project, "key2.patch"): "*** Begin Patch\n*** Add File: ../.ssh/authorized_keys2\n+key-marker\n*** End Patch\n",
	} {
		if err := os.WriteFile(file, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(keys, filepath.Join(project, "keylink")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Cleanup(func() { _ = os.Chmod(homes, 0o700) })
	for _, tc := range []struct {
		text string
		want bool
	}{
		{"apply_patch < ok.patch", false},
		{"cat ok.patch | apply_patch", false},
		{"apply_patch < missing.patch", false},
		{"apply_patch < key.patch", true},
		{"env apply_patch < key.patch", true},
		{"cat key2.patch | apply_patch", true},
		{"printf '*** Begin Patch\n*** Update File: greet.sh\n@@\n+x\n*** End Patch' | apply_patch < key.patch", true},
	} {
		t.Run(tc.text, func(t *testing.T) {
			if err := os.Chmod(homes, 0o700); err != nil {
				t.Fatal(err)
			}
			body, err := json.Marshal(map[string]any{"session_id": "rv31", "hook_event_name": "PreToolUse",
				"tool_name": "exec_command", "cwd": project, "tool_input": map[string]any{"cmd": tc.text}})
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
