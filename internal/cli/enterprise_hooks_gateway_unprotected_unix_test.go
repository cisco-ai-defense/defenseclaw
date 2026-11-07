//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

func gatewayCopyFixture(t *testing.T) (dir, path string) {
	t.Helper()
	dir = t.TempDir()
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, dir)
	oldOwner, oldTrust, oldDirTrust := enterpriseHookAuthorizationOwnershipSetter, enterpriseHookAuthorizationFileTrustCheck, enterpriseHookAuthorizationDirTrustCheck
	t.Cleanup(func() {
		enterpriseHookAuthorizationOwnershipSetter, enterpriseHookAuthorizationFileTrustCheck, enterpriseHookAuthorizationDirTrustCheck = oldOwner, oldTrust, oldDirTrust
	})
	enterpriseHookAuthorizationOwnershipSetter = func(string) error { return nil }
	enterpriseHookAuthorizationFileTrustCheck = func(string) error { return nil }
	enterpriseHookAuthorizationDirTrustCheck = func(string) error { return nil }
	return dir, filepath.Join(dir, managed.HookGuardianUnprotectedAgentsFile)
}

// rootRecordFixture writes the administrator record (the root-only
// unprotected-agents.json) the way the enumerator does, with its scan time.
func rootRecordFixture(t *testing.T, agents []enterprisehooks.UnprotectedAgent, scanned time.Time) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), enterprisehooks.UnprotectedAgentsFileName)
	data, err := enterprisehooks.MarshalUnprotectedAgentsForConfig(agents, 7, "digest-7")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, scanned, scanned); err != nil {
		t.Fatal(err)
	}
	return path
}

func openCodeV1For(uid int) enterprisehooks.UnprotectedAgent {
	return enterprisehooks.UnprotectedAgent{User: "r109ye1", UID: &uid, Connector: "opencode", Version: "1.18.34",
		InstallPath: "/opt/dc-agents/lib/node_modules/opencode-ai", Code: enterprisehooks.UnprotectedCodeOpenCodeV1, Reason: "V1 copy"}
}

// rel-1-0-6 GAP-0789: the gateway copy is the administrator record, byte for
// byte and as old as its scan, not a second computation. A scan that found
// nothing is mirrored too: an absent copy is an unknown scan to the gateway,
// never "nothing found".
func TestGatewayUnprotectedAgentsCopyIsTheAdministratorRecord(t *testing.T) {
	dir, path := gatewayCopyFixture(t)
	scanned := time.Now().Add(-3 * time.Minute).Truncate(time.Second)
	for name, agents := range map[string][]enterprisehooks.UnprotectedAgent{
		"a scan with a V1":       {openCodeV1For(1006)},
		"a completed empty scan": nil,
	} {
		root := rootRecordFixture(t, agents, scanned)
		if err := mirrorEnterpriseHookGatewayUnprotectedAgents(dir, root); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		want, err := os.ReadFile(root)
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s: copy = %q, %v; want the record bytes %q", name, got, err, want)
		}
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o640 || !info.ModTime().Equal(scanned) {
			t.Fatalf("%s: copy mode/time = %v, %v; want 0640 and the scan time %v", name, info, err, scanned)
		}
	}
}

// The copy follows the record when the cycle could not replace it: the
// administrator still sees the old V1, so the gateway copy must list it too,
// not a clean scan of this cycle (review 2 M1).
func TestGatewayUnprotectedAgentsCopyFollowsARecordThatWasNotReplaced(t *testing.T) {
	f := newStandaloneFixture(t, standaloneTestResolver{})
	configPath := filepath.Join(f.root, "config.yaml")
	raw := []byte("deployment_mode: managed_enterprise\n")
	if err := os.WriteFile(configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := configwrite.SHA256Hex(raw)
	state, err := json.Marshal(configwrite.GenerationState{Generation: 7, ConfigSHA256: digest})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.root, "config.generation.json"), state, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(managed.ConfigPathEnv, configPath)
	current := standaloneTestConfig(f.dataDir)
	current.ConfigFilePath = configPath
	enabled := true
	current.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"opencode": {Enabled: &enabled}}
	prevLoader, prevResolver, prevSessions := enterpriseHooksEnumerateConfigLoader, enterpriseHooksEnumerateResolver, enterpriseHookSessionUIDs
	prevManifest, prevEligible, prevRoot, prevGateway := enterpriseHooksEnumerateManifestWriter, enterpriseHooksEnumerateEligibleWriter, enterpriseHooksEnumerateUnprotectedWriter, enterpriseHooksEnumerateGatewayAgents
	t.Cleanup(func() {
		enterpriseHooksEnumerateConfigLoader, enterpriseHooksEnumerateResolver, enterpriseHookSessionUIDs = prevLoader, prevResolver, prevSessions
		enterpriseHooksEnumerateManifestWriter, enterpriseHooksEnumerateEligibleWriter, enterpriseHooksEnumerateUnprotectedWriter, enterpriseHooksEnumerateGatewayAgents = prevManifest, prevEligible, prevRoot, prevGateway
	})
	enterpriseHooksEnumerateConfigLoader = func() (*config.Config, string, error) { return current, digest, nil }
	enterpriseHooksEnumerateResolver = func(context.Context) unixidentity.Resolver { return standaloneTestResolver{} }
	enterpriseHookSessionUIDs = func() []int { return nil }
	enterpriseHooksEnumerateManifestWriter = func(string, enterprisehooks.Manifest) (bool, error) { return true, nil }
	enterpriseHooksEnumerateEligibleWriter = func(string, []enterprisehooks.UnixEligibleAccount, []enterprisehooks.UnixEligibleAccount) error {
		return nil
	}
	enterpriseHooksEnumerateGatewayAgents = publishEnterpriseHookUnixGatewayUnprotectedAgents

	rootPath := enterprisehooks.UnprotectedAgentsPath(f.manifest)
	oldData, err := enterprisehooks.MarshalUnprotectedAgentsForConfig([]enterprisehooks.UnprotectedAgent{openCodeV1For(1006)}, 7, digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootPath, oldData, 0o600); err != nil {
		t.Fatal(err)
	}
	cycle := func(rootWrite func(string, []enterprisehooks.UnprotectedAgent, uint64, string) error) {
		t.Helper()
		enterpriseHooksEnumerateUnprotectedWriter = rootWrite
		if _, err := runEnterpriseHooksEnumerateCycle(context.Background(), io.Discard, f.manifest,
			enterpriseHooksEnumerateOptions{manifest: f.manifest, descriptor: filepath.Join(f.root, "absent.json")}, &enterprisehooks.UnixEnumeratorState{Version: 1}); err != nil {
			t.Fatal(err)
		}
	}
	copyAgents := func() []enterprisehooks.UnprotectedAgent {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(f.authDir, managed.HookGuardianUnprotectedAgentsFile))
		if err != nil {
			t.Fatalf("no gateway copy: %v", err)
		}
		agents, err := enterprisehooks.ParseUnprotectedAgents(data)
		if err != nil {
			t.Fatal(err)
		}
		if enterprisehooks.UnprotectedAgentsRecordConfigGeneration(data) != 7 || enterprisehooks.UnprotectedAgentsRecordConfigSHA256(data) != digest {
			t.Fatalf("gateway copy lacks the installed config stamp: %s", data)
		}
		return agents
	}

	// The root record write fails: the administrator still sees the V1, and
	// so does the gateway copy.
	cycle(func(string, []enterprisehooks.UnprotectedAgent, uint64, string) error {
		return errors.New("simulated record write failure")
	})
	if got := copyAgents(); len(got) != 1 || got[0].Connector != "opencode" || got[0].Code != enterprisehooks.UnprotectedCodeOpenCodeV1 {
		t.Fatalf("copy after a failed record write = %+v, want the V1 the administrator still sees", got)
	}
	// Benign twin: the write succeeds with a clean scan and the copy is clean.
	cycle(func(path string, agents []enterprisehooks.UnprotectedAgent, generation uint64, stamp string) error {
		data, err := enterprisehooks.MarshalUnprotectedAgentsForConfig(agents, generation, stamp)
		if err != nil {
			return err
		}
		return os.WriteFile(path, data, 0o600)
	})
	if got := copyAgents(); len(got) != 0 {
		t.Fatalf("copy after a clean scan = %+v, want none", got)
	}
}

// A record that is missing, unreadable or malformed, or a copy that cannot be
// written, withdraws the previous copy: it must not speak for a scan this
// cycle replaced.
func TestGatewayUnprotectedAgentsCopyIsWithdrawnWhenItCannotBeMade(t *testing.T) {
	dir, path := gatewayCopyFixture(t)
	seed := func() string {
		t.Helper()
		root := rootRecordFixture(t, nil, time.Now())
		if err := mirrorEnterpriseHookGatewayUnprotectedAgents(dir, root); err != nil {
			t.Fatal(err)
		}
		return root
	}
	gone := func(what string) {
		t.Helper()
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s: the previous copy still stands: %v", what, err)
		}
	}

	root := seed()
	if err := os.Remove(root); err != nil {
		t.Fatal(err)
	}
	if err := mirrorEnterpriseHookGatewayUnprotectedAgents(dir, root); err == nil {
		t.Fatal("a missing record reported success")
	}
	gone("missing record")

	root = seed()
	if err := os.WriteFile(root, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := mirrorEnterpriseHookGatewayUnprotectedAgents(dir, root); err == nil {
		t.Fatal("a malformed record reported success")
	}
	gone("malformed record")

	root = seed()
	enterpriseHookAuthorizationOwnershipSetter = func(string) error { return errors.New("cannot set the owner") }
	if err := mirrorEnterpriseHookGatewayUnprotectedAgents(dir, root); err == nil {
		t.Fatal("publishing with a failing ownership step reported success")
	}
	gone("copy write failure")
}

// When the guardian directory refuses the removal as well, the copy is
// emptied in place: the gateway reads an empty copy as an unknown scan, so an
// old clean copy never speaks for a record that lists a V1 (review 2 M1).
func TestGatewayUnprotectedAgentsCopyIsEmptiedWhenTheDirectoryRefusesRemoval(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir, path := gatewayCopyFixture(t)
	if err := mirrorEnterpriseHookGatewayUnprotectedAgents(dir, rootRecordFixture(t, nil, time.Now())); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o550); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o750) })
	err := mirrorEnterpriseHookGatewayUnprotectedAgents(dir, rootRecordFixture(t, []enterprisehooks.UnprotectedAgent{openCodeV1For(5001)}, time.Now()))
	if err == nil {
		t.Fatal("a read-only guardian directory allowed the copy to be replaced")
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if _, parseErr := enterprisehooks.ParseUnprotectedAgents(data); parseErr == nil {
		t.Fatalf("the old copy still reads as a completed scan: %q", data)
	}
}
