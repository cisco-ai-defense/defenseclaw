// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// A Delete File of an apply_patch command in a shell call removes the final
// name: deleting a project link to a credential file removes the link and
// stays allowed in every profile, as the typed patch tool does, with the
// evidence the hook client lists for it. A name below a directory link that
// leads into the home removes the credential file and stays blocked.
func TestShellPatchDeleteOfALinkToACredentialFileIsAllowed(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home, project := filepath.Join(root, "home"), filepath.Join(root, "project")
	for _, dir := range []string{home, project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	secret := filepath.Join(home, ".netrc")
	if err := os.WriteFile(secret, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(project, "finalnet")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(home, filepath.Join(project, "homelink")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	verdict := func(connector, name string) string {
		command := "apply_patch <<'EOF'\n*** Begin Patch\n*** Delete File: " + filepath.Join(project, name) + "\n*** End Patch\nEOF\n"
		raw, err := json.Marshal(map[string]string{"command": command})
		if err != nil {
			t.Fatal(err)
		}
		payload, err := json.Marshal(map[string]interface{}{
			"hook_event_name": "PreToolUse", "session_id": "s", "cwd": project, "tool_name": "Bash",
			"tool_input": map[string]string{"command": command},
		})
		if err != nil {
			t.Fatal(err)
		}
		evidence, ok := hookpaths.Decode(hookpaths.ResolveConnector("claude-code", "", "PreToolUse", payload))
		if !ok {
			t.Fatal("no client evidence")
		}
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input:      actionfacts.Input{Tool: "Bash", Args: raw, CWD: project, ActiveHome: home},
			LegacyText: string(raw), Connector: connector, EnforcementCapable: true,
			SkipLocalFilesystemResolution: true, ResolvedWriteTargets: evidence,
		})
		return buildVerdict(findings, "tool_call").Action
	}
	for _, profile := range []string{"default", "permissive", "strict"} {
		connector := "shell-patch-delete-link-" + profile
		installToolCallCorpusProfileConnector(t, connector, profile)
		if got := verdict(connector, "finalnet"); got != "allow" {
			t.Errorf("%s: shell Delete File of a link to a credential file: %s, want allow", profile, got)
		}
		if got := verdict(connector, "homelink/.netrc"); got != "block" {
			t.Errorf("%s: shell Delete File of a credential file below a directory link: %s, want block", profile, got)
		}
	}
}
