// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// GAP-0355: in a sandbox hook, a 403 whose body is OpenShell's refusal of a
// post that carries a credential placeholder from the conversation is named
// as that, not as a host gateway's token drift; another 401 or 403 points at
// sandbox doctor, and other failures read as before.
func TestSandboxHookFailureReasonNamesAPlaceholderRefusal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell hooks are not used on Windows")
	}
	dir := t.TempDir()
	writeSandboxRendering(t, dir, "claudecode", renderSandboxGolden(t, &ClaudeCodeConnector{}, "2.1.156").Files)
	hooks := filepath.Join(dir, "claudecode", "usr", "local", "lib", "defenseclaw", "hooks")
	script := `DEFENSECLAW_BAKED_HOOK_PATH=/usr/bin:/bin; . "$1/_hardening.sh"; . "$1/_sandbox.sh"; RESULT="$3"
defenseclaw_response_failure_reason "$2"`
	for _, c := range []struct{ reason, body, want string }{
		{"gateway returned HTTP 403", "A credential placeholder in the request body cannot be forwarded.",
			"gateway returned HTTP 403 (OpenShell refused it: this conversation holds a sandbox credential placeholder"},
		{"gateway returned HTTP 401", `{"error":"unauthorized"}`, "gateway returned HTTP 401 (DefenseClaw on the user's machine refused the sandbox's request"},
		{"invalid JSON response", "", "invalid JSON response"},
	} {
		out, err := exec.Command("/bin/bash", "-c", script, "bash", hooks, c.reason, c.body).CombinedOutput()
		if err != nil || !strings.HasPrefix(string(out), c.want) || strings.Contains(string(out), "token drift") {
			t.Errorf("%s / %q: %v, %q; want %q...", c.reason, c.body, err, out, c.want)
		}
	}
}
