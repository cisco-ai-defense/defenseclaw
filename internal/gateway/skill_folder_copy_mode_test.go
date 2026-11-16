// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// A copy-mode sandbox names paths inside the sandbox, so the skill folder check
// must not walk the host for them: a link of the same spelling on the host
// working folder is not a read the sandbox makes. The same call from the host,
// and from a mount-mode sandbox whose mount reaches the host, stays blocked.
func TestSkillFolderCheckLeavesTheHostAloneForACopyModeSandbox(t *testing.T) {
	f := newOperandContextFixture(t, "held")
	if err := os.Symlink(f.held, filepath.Join(f.proj, "lnk-held")); err != nil {
		t.Skipf("link unavailable: %v", err)
	}
	call := map[string]interface{}{"command": "cat lnk-held/SKILL.md"}
	benign := map[string]interface{}{"command": "cat notes.txt"}

	inSandbox := func(workdir sandboxauth.Workdir) context.Context {
		return sandboxauth.WithRequest(f.ctx, sandboxauth.Binding{
			SandboxName: "dc-claude", Connector: "claudecode", Workdir: workdir,
		}, nil)
	}
	host := f.ctx
	copyMode := inSandbox(sandboxauth.Workdir{Mode: sandboxauth.WorkdirCopy})
	mounted := inSandbox(sandboxauth.Workdir{
		Mode:   sandboxauth.WorkdirMount,
		Mounts: []sandboxauth.Mount{{SandboxPath: "/work/app", HostPath: f.proj}},
	})

	blocks := func(ctx context.Context, input map[string]interface{}) bool {
		d, matched := f.api.skillFolderAccessDecision(ctx, "claudecode", "PreToolUse", f.proj, "Bash", input)
		return matched && d.Action == "block"
	}
	if !blocks(host, call) {
		t.Fatal("host call that reads a link to a denied skill folder is not blocked")
	}
	if !blocks(mounted, call) {
		t.Error("mount-mode sandbox call that reads a link to a denied skill folder on its mounted host folder is not blocked")
	}
	if blocks(copyMode, call) {
		t.Error("copy-mode sandbox call was judged by a walk of the host working folder")
	}
	for name, ctx := range map[string]context.Context{"host": host, "copy": copyMode, "mount": mounted} {
		if blocks(ctx, benign) {
			t.Errorf("%s: ordinary read blocked", name)
		}
	}
}
