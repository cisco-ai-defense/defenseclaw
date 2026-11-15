// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// srdPOSIXHost makes the hook judge a shell call as a POSIX host does. The
// secret-read chain tests below send POSIX shell commands over POSIX paths.
// On a Windows host the hook reads a Bash call with the Windows dialect
// (windowsHookHost: Git Bash is told apart only when the call reads alone) and
// does not place a relative operand in a directory the gateway cannot see
// (toolChainDriveMounts); both readings join the chain on any call they cannot
// prove, so every row that expects no chain gives one there. Those rows state
// the POSIX reading, so they pin it the same way on every host. The Windows
// reading is judged by the Windows-dialect tests.
func srdPOSIXHost(t *testing.T) {
	t.Helper()
	savedHost, savedMounts := windowsHookHost, toolChainDriveMounts
	windowsHookHost = func() bool { return false }
	toolChainDriveMounts = false
	t.Cleanup(func() { windowsHookHost, toolChainDriveMounts = savedHost, savedMounts })
}

// srdShellPath is a directory of this host spelled for a POSIX shell command
// line (forward slashes; t.TempDir has backslashes on Windows).
func srdShellPath(dir string) string { return filepath.ToSlash(dir) }

// srdConservativeJoin is true for a call whose working directory exists on a
// Windows host: it is a C: path, which the POSIX reading of a shell call does
// not take as absolute, so no operand under it names one exact file and the
// chain joins the read and the upload it cannot tell apart. The row then may
// raise a chain the POSIX table does not expect (more alerts, never fewer): a
// row that expects a chain must still raise it. The same rows run without a
// working directory on the host judge the exact verdicts on Windows too.
func srdConservativeJoin(localCWD bool) bool { return localCWD && runtime.GOOS == "windows" }

// srdTier is one policy tier of a hook-path secret-read chain row. A proven
// credential read followed by an upload blocks in the strict pack (strict and
// managed-strict) and alerts in the default and permissive packs (managed
// default included) (GAP-0595).
type srdTier struct {
	name, pack string
	managed    bool
	strict     bool
}

var srdTiers = []srdTier{
	{name: "default", pack: "default"},
	{name: "permissive", pack: "permissive"},
	{name: "strict", pack: "strict", strict: true},
	{name: "managed", pack: "default", managed: true},
	{name: "managed-strict", pack: "strict", managed: true, strict: true},
}

// srdTiersNamed is the tiers of srdTiers with the given names, in order.
func srdTiersNamed(t *testing.T, names ...string) []srdTier {
	t.Helper()
	var out []srdTier
	for _, name := range names {
		found := false
		for _, tier := range srdTiers {
			if tier.name == name {
				out = append(out, tier)
				found = true
			}
		}
		if !found {
			t.Fatalf("no tier %q", name)
		}
	}
	return out
}

// srdHookHandler is the Claude Code hook route of a gateway in action mode on
// tier (a managed install when tier.managed).
func srdHookHandler(t *testing.T, policiesRoot string, tier srdTier) http.Handler {
	t.Helper()
	installDefaultProfileConnector(t, "claudecode")
	store, logger := testStoreAndV8Logger(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.RulePackDir = filepath.Join(policiesRoot, tier.pack)
	if tier.managed {
		cfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
		cfg.Enterprise.Profile = managed.ProfileStandalone
		prev := liveGeneration.Load()
		liveGeneration.Store(&Generation{Config: cfg})
		t.Cleanup(func() { liveGeneration.Store(prev) })
	}
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, cfg)
	return http.HandlerFunc(api.handleAgentHook("claudecode"))
}

// srdChainAction is the action a raised secret-read chain takes on tier: a
// block in a strict tier when the row is proven to block there (strictBlock),
// an alert otherwise.
func srdChainAction(tier srdTier, strictBlock bool) string {
	if tier.strict && strictBlock {
		return "block"
	}
	return "alert"
}
