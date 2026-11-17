// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

func kiroSetUpForOrphanTest(t *testing.T, dataDir string) (*KiroConnector, SetupOpts, string) {
	t.Helper()
	home := t.TempDir()
	KiroHomeOverride = home
	t.Cleanup(func() { KiroHomeOverride = "" })
	opts := SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: "tok-test", HookFailMode: "closed"}
	conn := NewKiroConnector()
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	return conn, opts, home
}

// rel-1-0-10 GAP-1092/GAP-1174: `setup remove kiro` on a connector that is not
// configured asks OrphanedHookConfigPaths for the files that still hold
// DefenseClaw hooks. It matched the command as raw bytes, which a Windows
// -EncodedCommand wrapper (and a data folder name JSON escapes, as here)
// does not survive, so Kiro's hook files were reported "already absent" and stayed.
// The Kiro connector reads its files as decoded entries.
func TestOrphanedKiroHooksAreFoundAsDecodedEntries(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "dc&home")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	conn, opts, home := kiroSetUpForOrphanTest(t, dataDir)
	found, err := OrphanedHookConfigPaths(conn, opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		filepath.Join(home, "hooks", kiroManagedHooksName),
		filepath.Join(home, "agents", kiroManagedAgentName+".json"),
	} {
		if !slices.Contains(found, want) {
			t.Errorf("orphaned hook files = %v, missing %s", found, want)
		}
	}
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if left, err := OrphanedHookConfigPaths(conn, opts); err != nil || len(left) != 0 {
		t.Fatalf("after teardown orphaned files = %v, err %v", left, err)
	}
}

// The hook files under ~/.kiro are shared by every DefenseClaw data folder of
// the account. A file whose entries carry the name defenseclaw-* but run
// another install's command is that install's: this install's `setup remove
// kiro` must not find it, and so must not tear it down. Ownership is the
// decoded action.command, not the name prefix.
func TestOrphanedKiroHooksOfAnotherInstallAreNotFound(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows commands name the account's launcher, not a data folder")
	}
	dataA := filepath.Join(t.TempDir(), "install-a")
	dataB := filepath.Join(t.TempDir(), "install-b")
	for _, dir := range []string{dataA, dataB} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	connB, optsB, home := kiroSetUpForOrphanTest(t, dataB)
	hooksFile := filepath.Join(home, "hooks", kiroManagedHooksName)
	agentFile := filepath.Join(home, "agents", kiroManagedAgentName+".json")
	hooksBefore, err := os.ReadFile(hooksFile)
	if err != nil {
		t.Fatal(err)
	}
	agentBefore, err := os.ReadFile(agentFile)
	if err != nil {
		t.Fatal(err)
	}
	connA := NewKiroConnector()
	optsA := SetupOpts{DataDir: dataA, APIAddr: "127.0.0.1:18970", APIToken: "tok-test", HookFailMode: "closed"}
	found, err := OrphanedHookConfigPaths(connA, optsA)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Fatalf("install A found install B's Kiro files: %v", found)
	}
	// Install B still finds its own.
	if found, err := OrphanedHookConfigPaths(connB, optsB); err != nil || len(found) != 2 {
		t.Fatalf("install B's own files = %v, err %v", found, err)
	}
	for path, want := range map[string][]byte{hooksFile: hooksBefore, agentFile: agentBefore} {
		if got, err := os.ReadFile(path); err != nil || string(got) != string(want) {
			t.Fatalf("%s changed: %v", path, err)
		}
	}
}

// The ownership rule on decoded commands, on every OS: an entry counts only
// when its action.command is exactly one of this install's commands; a
// defenseclaw-* name, a kiro-hook.sh path under another data folder or a
// command that merely contains this install's does not.
func TestKiroV3FileHoldsCommandComparesTheDecodedCommand(t *testing.T) {
	const own = "/home/u/.defenseclaw/hooks/kiro-hook.sh --hook-surface v3"
	commands := []string{own}
	entry := func(name, command string) string {
		return `{"name":"` + name + `","trigger":"preToolUse","action":{"type":"command","command":"` + command + `"}}`
	}
	for name, tc := range map[string]struct {
		file string
		want bool
	}{
		"own command":                      {`{"hooks":[` + entry("defenseclaw-pre-tool", own) + `]}`, true},
		"own command under another name":   {`{"hooks":[` + entry("my-hook", own) + `]}`, true},
		"own command with padding":         {`{"hooks":[` + entry("my-hook", "  "+own+" ") + `]}`, true},
		"defenseclaw name, other install":  {`{"hooks":[` + entry("defenseclaw-pre-tool", "/other/.defenseclaw/hooks/kiro-hook.sh --hook-surface v3") + `]}`, false},
		"kiro-hook.sh of another install":  {`{"hooks":[` + entry("x", "/other/hooks/kiro-hook.sh") + `]}`, false},
		"command that contains ours":       {`{"hooks":[` + entry("x", "sudo "+own) + `]}`, false},
		"operator hook":                    {`{"hooks":[` + entry("x", "/usr/local/bin/audit") + `]}`, false},
		"entry without an action":          {`{"hooks":[{"name":"defenseclaw-pre-tool"}]}`, false},
		"no hooks":                         {`{"version":"v1"}`, false},
		"another entry beside our own one": {`{"hooks":[` + entry("a", "/usr/bin/true") + `,` + entry("b", own) + `]}`, true},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "defenseclaw.json")
			if err := os.WriteFile(path, []byte(tc.file), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := kiroV3FileHoldsCommand(path, commands)
			if err != nil || got != tc.want {
				t.Fatalf("kiroV3FileHoldsCommand = %v, %v, want %v", got, err, tc.want)
			}
		})
	}
	if got, err := kiroV3FileHoldsCommand(filepath.Join(t.TempDir(), "absent.json"), commands); err != nil || got {
		t.Fatalf("an absent file holds %v, %v", got, err)
	}
}

// A managed (guardian) install owns no command: its footprint is the hook
// guardian's, never a boot or remove cleanup's.
func TestKiroInstallHookCommandsAreEmptyForAManagedInstall(t *testing.T) {
	conn := NewKiroConnector()
	if got := conn.installHookCommands(SetupOpts{DataDir: t.TempDir(), ManagedEnterprise: true}); len(got) != 0 {
		t.Fatalf("a managed install owns commands %v", got)
	}
	if got := conn.installHookCommands(SetupOpts{DataDir: t.TempDir()}); len(got) == 0 {
		t.Fatal("a per-user install owns no command")
	}
}

// rel-1-0-10 GAP-1174: the defenseclaw agent Setup writes goes with its last
// DefenseClaw hook when it holds only keys Setup writes, the $schema pointer
// and known keys with an empty value. Any other key, or a value in one of the
// known ones, is the operator's, and the file stays.
func TestKiroTeardownRemovesTheManagedAgentOnlyWhenItHoldsKnownKeys(t *testing.T) {
	for name, tc := range map[string]struct {
		extra      map[string]interface{}
		wantRemain bool
	}{
		"schema pointer":            {map[string]interface{}{"$schema": "https://kiro.dev/schemas/agent.json"}, false},
		"empty known keys":          {map[string]interface{}{"resources": []interface{}{}, "mcpServers": map[string]interface{}{}, "allowedTools": []interface{}{}, "prompt": ""}, false},
		"unknown key":               {map[string]interface{}{"kiroUpgrade": map[string]interface{}{"revision": 3}}, true},
		"operator mcp servers":      {map[string]interface{}{"mcpServers": map[string]interface{}{"x": map[string]interface{}{"command": "y"}}}, true},
		"operator prompt":           {map[string]interface{}{"prompt": "be brief"}, true},
		"operator allowed tools":    {map[string]interface{}{"allowedTools": []interface{}{"fs_read"}}, true},
		"operator resources":        {map[string]interface{}{"resources": []interface{}{"file://README.md"}}, true},
		"operator tool settings":    {map[string]interface{}{"toolsSettings": map[string]interface{}{"shell": map[string]interface{}{"x": 1}}}, true},
		"unknown key with empty ok": {map[string]interface{}{"resources": []interface{}{}, "model": "x"}, true},
	} {
		t.Run(name, func(t *testing.T) {
			conn, opts, home := kiroSetUpForOrphanTest(t, t.TempDir())
			agent := filepath.Join(home, "agents", kiroManagedAgentName+".json")
			cfg, err := readJSONObject(agent)
			if err != nil {
				t.Fatal(err)
			}
			for key, value := range tc.extra {
				cfg[key] = value
			}
			if err := writeJSONObject(agent, cfg); err != nil {
				t.Fatal(err)
			}
			if err := conn.Teardown(context.Background(), opts); err != nil {
				t.Fatalf("Teardown: %v", err)
			}
			_, statErr := os.Stat(agent)
			if tc.wantRemain && statErr != nil {
				t.Fatalf("an agent with operator content was removed: %v", statErr)
			}
			if !tc.wantRemain && !os.IsNotExist(statErr) {
				t.Fatalf("the managed agent stayed after teardown: %v", statErr)
			}
			if err := conn.VerifyClean(opts); err != nil {
				t.Fatalf("VerifyClean: %v", err)
			}
		})
	}
}

// What sits beside a removed Kiro file goes with it when DefenseClaw made it:
// the empty .lock its atomic write leaves (cert L24 dcw-std2 kiro-rm110: only
// defenseclaw.json.lock, 0 bytes, remained after `setup remove kiro` on
// 1.0.10) and the .bak copies Kiro's /upgrade-agent keeps of the DefenseClaw
// agent. A .bak that carries operator content stays.
func TestKiroTeardownRemovesTheResidueBesideTheManagedFiles(t *testing.T) {
	conn, opts, home := kiroSetUpForOrphanTest(t, t.TempDir())
	agent := filepath.Join(home, "agents", kiroManagedAgentName+".json")
	hooks := filepath.Join(home, "hooks", kiroManagedHooksName)
	body, err := os.ReadFile(agent)
	if err != nil {
		t.Fatal(err)
	}
	write := func(path string, data []byte) {
		t.Helper()
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(agent+".bak", body)
	write(agent+".bak.1", body)
	write(agent+".lock", nil)
	write(hooks+".lock", nil)
	operator := []byte(`{"name":"defenseclaw","prompt":"operator text","hooks":[]}` + "\n")
	write(agent+".bak.2", operator)
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	for _, gone := range []string{agent, agent + ".bak", agent + ".bak.1", agent + ".lock", hooks, hooks + ".lock"} {
		if _, err := os.Lstat(gone); !os.IsNotExist(err) {
			t.Errorf("%s remains after teardown: %v", filepath.Base(gone), err)
		}
	}
	if got, err := os.ReadFile(agent + ".bak.2"); err != nil || string(got) != string(operator) {
		t.Errorf("the operator's backup copy was removed or changed: %v", err)
	}
}
