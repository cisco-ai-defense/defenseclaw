// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"golang.org/x/sys/windows"
)

func TestCanonicalWindowsCopilotManagedTargetsSortsAndRejectsAmbiguity(t *testing.T) {
	first := WindowsCopilotManagedRuntimeTarget{
		SID: "S-1-5-21-111-222-333-1001", DataDir: `C:\Users\alice\.defenseclaw`,
	}
	second := WindowsCopilotManagedRuntimeTarget{
		SID: "S-1-5-21-111-222-333-1002", DataDir: `C:\Users\bob\.defenseclaw`,
	}
	targets, err := canonicalWindowsCopilotTargets(
		[]WindowsCopilotManagedRuntimeTarget{second, first, first},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 || targets[0] != first || targets[1] != second {
		t.Fatalf("canonical Copilot targets = %+v", targets)
	}

	for name, candidate := range map[string][]WindowsCopilotManagedRuntimeTarget{
		"system SID": {{
			SID: "S-1-5-18", DataDir: `C:\Windows\System32\config\systemprofile\.defenseclaw`,
		}},
		"noncanonical data directory": {{
			SID: first.SID, DataDir: `C:\Users\alice\other`,
		}},
		"same SID different directory": {
			first,
			{SID: first.SID, DataDir: `C:\Users\alice2\.defenseclaw`},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := canonicalWindowsCopilotTargets(candidate); err == nil {
				t.Fatal("ambiguous Copilot target set was accepted")
			}
		})
	}
}

func TestWindowsCopilotSnapshotFilesUseSafeActivationOrder(t *testing.T) {
	root := filepath.Join(t.TempDir(), "GitHub", "Copilot", "policy.d")
	original := windowsCopilotManagedRootResolver
	windowsCopilotManagedRootResolver = func() (string, error) { return root, nil }
	t.Cleanup(func() { windowsCopilotManagedRootResolver = original })

	active, err := windowsCopilotSnapshotFiles(WindowsCopilotManagedPolicyTeardownSnapshot{
		PolicyExisted: true,
		Policy:        []byte("policy"),
		StateExisted:  true,
		State:         []byte("state"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(active[0].path) != windowsCopilotManagedStateFile ||
		filepath.Base(active[1].path) != connector.CopilotEnterprisePolicyFileName {
		t.Fatalf("active restore order = %s, %s", active[0].path, active[1].path)
	}

	absent, err := windowsCopilotSnapshotFiles(WindowsCopilotManagedPolicyTeardownSnapshot{})
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(absent[0].path) != connector.CopilotEnterprisePolicyFileName ||
		filepath.Base(absent[1].path) != windowsCopilotManagedStateFile {
		t.Fatalf("deactivation order = %s, %s", absent[0].path, absent[1].path)
	}
	if _, err := windowsCopilotSnapshotFiles(WindowsCopilotManagedPolicyTeardownSnapshot{
		PolicyExisted: true,
	}); err == nil {
		t.Fatal("asymmetric Copilot snapshot was accepted")
	}
}

func TestValidateWindowsCopilotManagedArtifactDataBindsExactIdentity(t *testing.T) {
	hook := `C:\Program Files\Cisco\DefenseClaw\defenseclaw-hook.exe`
	setup := connector.SetupOpts{
		ManagedEnterprise: true,
		AgentVersion:      connector.CopilotEnterpriseMinVersion,
		HookContractID:    connector.CopilotEnterpriseHookContractID,
		HookExecutable:    hook,
	}
	policy, err := connector.NewCopilotEnterpriseConnector().ManagedHookPolicy(setup)
	if err != nil {
		t.Fatal(err)
	}
	targets := []WindowsCopilotManagedRuntimeTarget{{
		SID: "S-1-5-21-111-222-333-1001", DataDir: `C:\Users\alice\.defenseclaw`,
	}}
	state, err := renderWindowsCopilotManagedState(windowsCopilotManagedPolicyState{
		SchemaVersion:      1,
		PolicySHA256:       windowsManagedPolicyDigest(policy),
		HookExecutable:     hook,
		GatewayAddr:        "127.0.0.1:18970",
		GatewayServiceName: "DefenseClawGateway",
		Targets:            targets,
	})
	if err != nil {
		t.Fatal(err)
	}
	artifacts := windowsCopilotManagedArtifacts{
		policy: windowsManagedFileSnapshot{path: `C:\policy.json`, existed: true, data: policy},
		state:  windowsManagedFileSnapshot{path: `C:\state.json`, existed: true, data: state},
	}
	validated, err := validateWindowsCopilotManagedArtifactData(artifacts, false)
	if err != nil {
		t.Fatal(err)
	}
	if !validated.active || !equalWindowsCopilotTargets(validated.parsed.Targets, targets) {
		t.Fatalf("validated Copilot artifacts = %+v", validated)
	}

	tampered := artifacts
	tampered.policy.data = append([]byte(nil), policy...)
	tampered.policy.data = bytes.Replace(
		tampered.policy.data,
		[]byte("copilot-hooks-v2"),
		[]byte("copilot-hooks-v3"),
		1,
	)
	if _, err := validateWindowsCopilotManagedArtifactData(tampered, false); err == nil {
		t.Fatal("Copilot policy drift was accepted")
	}
}

func TestRetireWindowsCopilotManagedLockKeepsPathExclusiveUntilClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), windowsCopilotManagedLockFile)
	lock, err := openWindowsCopilotManagedPolicyLockFile(path)
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = windows.CloseHandle(lock)
		}
	}()

	if err := retireWindowsCopilotManagedLock(lock); err != nil {
		t.Fatal(err)
	}
	if competing, err := openWindowsCopilotManagedPolicyLockFile(path); err == nil {
		_ = windows.CloseHandle(competing)
		t.Fatal("competing Copilot transaction acquired a replacement lock before the retired handle closed")
	}
	if err := windows.CloseHandle(lock); err != nil {
		t.Fatal(err)
	}
	closed = true
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retired Copilot lock still exists: %v", err)
	}

	// A later transaction may create a new lock only after the retiring
	// handle has closed and the old name has disappeared.
	replacement, err := openWindowsCopilotManagedPolicyLockFile(path)
	if err != nil {
		t.Fatalf("create next Copilot transaction lock: %v", err)
	}
	if err := retireWindowsCopilotManagedLock(replacement); err != nil {
		_ = windows.CloseHandle(replacement)
		t.Fatal(err)
	}
	if err := windows.CloseHandle(replacement); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement Copilot lock still exists after retirement: %v", err)
	}
}
