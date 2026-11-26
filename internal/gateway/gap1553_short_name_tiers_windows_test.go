// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"golang.org/x/sys/windows"
)

func gap1553GatewaySpelling(t *testing.T, path string, conv func(*uint16, *uint16, uint32) (uint32, error)) string {
	t.Helper()
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := conv(p, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 || n >= uint32(len(buf)) {
		t.Fatalf("convert %s: %v", path, err)
	}
	return windows.UTF16ToString(buf[:n])
}

// rel-1-0-10:GAP-1553 (the effects reading, moved from the Linux R3 rows,
// which have no Windows file system to expand a short name in): on a
// Windows hook host an 8.3 short name of .ssh or authorized_keys is the
// home's keys file, so the hook verdict is at least the long spelling's in
// every tier on both connectors (managed cells carry the home in the hook
// peer, per-user cells read the profile); a short name of a project folder
// stays allowed.
func TestGAP1553ShortNameTiersNative(t *testing.T) {
	useDefaultEffectsLane(t)
	home := gap1553GatewaySpelling(t, t.TempDir(), windows.GetLongPathName)
	ssh, project := filepath.Join(home, ".ssh"), filepath.Join(home, "project")
	for _, dir := range []string{ssh, project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	key := filepath.Join(ssh, "authorized_keys")
	for _, file := range []string{key, filepath.Join(project, "notes.txt")} {
		if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sshShort := filepath.Base(gap1553GatewaySpelling(t, ssh, windows.GetShortPathName))
	keyShort := filepath.Base(gap1553GatewaySpelling(t, key, windows.GetShortPathName))
	projShort := filepath.Base(gap1553GatewaySpelling(t, project, windows.GetShortPathName))
	if sshShort == ".ssh" || keyShort == "authorized_keys" {
		t.Fatalf("the volume of %s has no 8.3 names (%s, %s): run on a volume that makes them", home, sshShort, keyShort)
	}
	t.Setenv("USERPROFILE", home)
	routes := []struct {
		name, connector string
		decide          func(api *APIServer, ctx context.Context, command string) (string, []string)
	}{
		{"claudecode PowerShell", "claudecode", func(api *APIServer, ctx context.Context, command string) (string, []string) {
			resp := api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{HookEventName: "PreToolUse", SessionID: "gap1553", CWD: home,
				ToolName: "PowerShell", ToolInput: map[string]interface{}{"command": command}})
			return resp.Action, resp.Findings
		}},
		{"codex shell", "codex", func(api *APIServer, ctx context.Context, command string) (string, []string) {
			resp := api.evaluateCodexHook(ctx, codexHookRequest{HookEventName: "PreToolUse", ToolName: "shell", CWD: home,
				ToolInput: map[string]interface{}{"command": command}})
			return resp.Action, resp.Findings
		}},
	}
	control := `Add-Content ` + key + ` x`
	rows := []struct {
		name, command string
		allow         bool
	}{
		{"short .ssh", `Add-Content ` + sshShort + `\authorized_keys x`, false},
		{"short authorized_keys in .ssh", `cd .ssh; Add-Content ` + keyShort + ` x`, false},
		{"fp: short project folder", `Add-Content ` + projShort + `\notes.txt x`, true},
	}
	for _, tier := range boundedTestTiers {
		for _, route := range routes {
			api := gap0589TierAPI(t, route.connector, tier.posture, tier.managed, tier.tier)
			ctx := t.Context()
			if tier.managed {
				ctx = withManagedHookPeer(ctx, managedHookPeer{Home: home})
			}
			ca, _ := route.decide(api, ctx, control)
			want := bounded.Stricter(boundedParse(ca), bounded.Unknown(tier.tier))
			for _, row := range rows {
				useEffectsRulesMode(t, "off")
				off, _ := route.decide(api, ctx, row.command)
				useDefaultEffectsLane(t)
				action, findings := route.decide(api, ctx, row.command)
				got := boundedParse(action)
				t.Logf("ROW\t%s\t%s\t%s\toff=%s\t%s\twant>=%s\t%v", tier.name, route.name, row.name, off, action, want, findings)
				if row.allow {
					if got != bounded.Allow {
						t.Errorf("%s %s %s: %s, want allow; findings %v", tier.name, route.name, row.name, action, findings)
					}
					continue
				}
				if bounded.Stricter(got, boundedParse(off)) != got {
					t.Errorf("%s %s %s: %s below its lane-off verdict %s", tier.name, route.name, row.name, action, off)
				}
				if bounded.Stricter(got, want) != got {
					t.Errorf("%s %s %s: %s, want at least %s (the long spelling %s); findings %v", tier.name, route.name, row.name, action, want, ca, findings)
				}
			}
		}
	}
}
