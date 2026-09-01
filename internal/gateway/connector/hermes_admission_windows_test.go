// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
	"golang.org/x/sys/windows"
)

func TestHermesAdmissionAcceptsMergedProtectedReceiptWithoutMutation(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	opts := prepareHermesSetupAdmissionFixture(t, SetupOpts{DataDir: filepath.Join(root, "defenseclaw-data")})
	path := filepath.Join(opts.DataDir, agentSelectionFile)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateHermesWindowsSetupAdmission(context.Background(), opts); err != nil {
		t.Fatalf("merged receipt admission: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("Hermes admission rewrote or consumed the merged protected receipt")
	}
	var receipt agentSelectionReceipt
	if err := json.Unmarshal(after, &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Selections["codex"].Connector != "codex" || receipt.Selections["hermes"].Connector != "hermes" {
		t.Fatalf("merged protected receipt lost a connector: %+v", receipt.Selections)
	}
}

func TestHermesConnectorLifecycleWithProtectedAdmission(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	configPath := filepath.Join(root, "hermes-home", "config.yaml")
	previousConfigPath := HermesConfigPathOverride
	HermesConfigPathOverride = configPath
	t.Cleanup(func() { HermesConfigPathOverride = previousConfigPath })

	opts := prepareHermesSetupAdmissionFixture(t, SetupOpts{
		DataDir:  filepath.Join(root, "defenseclaw-data"),
		APIAddr:  "127.0.0.1:18970",
		APIToken: "lifecycle-matrix-token",
	})
	conn := NewHermesConnector()
	if err := conn.VerifyClean(opts); err != nil {
		t.Fatalf("VerifyClean before Setup: %v", err)
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if err := conn.VerifyClean(opts); err != nil {
		t.Fatalf("VerifyClean after Teardown: %v", err)
	}
}

func TestHermesSetupAdmissionRejectsChangedPathBytesVersionAndCustodyBeforeMutation(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*testing.T, *SetupOpts)
		wantError string
	}{
		{
			name: "replaced executable bytes",
			mutate: func(t *testing.T, opts *SetupOpts) {
				t.Helper()
				if err := atomicWriteFile(opts.AgentExecutable, []byte("MZ replaced Hermes bytes"), 0o700); err != nil {
					t.Fatal(err)
				}
			},
			wantError: "digest does not match protected evidence",
		},
		{
			name: "fresh probe mismatched version",
			mutate: func(t *testing.T, _ *SetupOpts) {
				t.Helper()
				hermesAgentVersionProbe = func(context.Context, string) (string, error) {
					return "Hermes Agent v0.19.0", nil
				}
			},
			wantError: "fresh version probe does not match protected raw, normalized, and contract evidence",
		},
		{
			name: "wrong executable path",
			mutate: func(t *testing.T, opts *SetupOpts) {
				t.Helper()
				wrong := filepath.Join(opts.DataDir, "wrong", "hermes.exe")
				if err := atomicWriteFile(wrong, []byte("MZ Hermes v0.20 admission fixture"), 0o700); err != nil {
					t.Fatal(err)
				}
				opts.AgentExecutable = wrong
			},
			wantError: "not the protected current-token updater-managed executable",
		},
		{
			name: "unsafe executable DACL",
			mutate: func(t *testing.T, opts *SetupOpts) {
				t.Helper()
				if err := setOTLPWindowsBroadDACL(opts.AgentExecutable, windows.GENERIC_WRITE); err != nil {
					t.Fatal(err)
				}
			},
			wantError: "untrusted Windows principal",
		},
		{
			name: "reparse directory chain",
			mutate: func(t *testing.T, opts *SetupOpts) {
				t.Helper()
				managedRoot := filepath.Join(opts.DataDir, "managed-hermes")
				realRoot := filepath.Join(opts.DataDir, "managed-hermes-real")
				if err := os.Rename(managedRoot, realRoot); err != nil {
					t.Fatal(err)
				}
				createTestDirectoryRedirect(t, managedRoot, realRoot)
			},
			wantError: "reparse points are not allowed",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := testenv.PrivateTempDir(t)
			configPath := filepath.Join(root, "hermes-home", "config.yaml")
			if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(configPath, []byte("operator_literal: KEEP-CONFIG-BYTES\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			allowlistPath := filepath.Join(filepath.Dir(configPath), hermesAllowlistFileName)
			if err := os.WriteFile(allowlistPath, []byte("{\"approvals\":[],\"operator\":\"KEEP-ALLOWLIST-BYTES\"}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			previousConfig := HermesConfigPathOverride
			HermesConfigPathOverride = configPath
			t.Cleanup(func() { HermesConfigPathOverride = previousConfig })

			opts := prepareHermesSetupAdmissionFixture(t, SetupOpts{
				DataDir: filepath.Join(root, "defenseclaw-data"),
				APIAddr: "127.0.0.1:18970",
			})
			activePath := filepath.Join(opts.DataDir, activeConnectorFile)
			if err := atomicWriteFile(activePath, []byte("{\"version\":3,\"names\":[\"claudecode\"],\"name\":\"claudecode\"}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			targets := hermesAdmissionMutationTargets(opts, configPath)
			before := snapshotHermesAdmissionTargets(t, targets)
			test.mutate(t, &opts)

			err := NewHermesConnector().Setup(context.Background(), opts)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("Setup error = %v, want %q", err, test.wantError)
			}
			assertHermesAdmissionTargetsUnchanged(t, before)
		})
	}
}

func TestHermesContractPublicationRevalidatesReceiptAfterEntryHashing(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	opts := prepareHermesSetupAdmissionFixture(t, SetupOpts{DataDir: filepath.Join(root, "defenseclaw-data")})
	if err := atomicWriteFile(opts.AgentExecutable, []byte("MZ bytes replaced after setup admission"), 0o700); err != nil {
		t.Fatal(err)
	}
	entry := NewHookContractLockEntry(opts, NewHermesConnector(), "test-build")
	if strings.EqualFold(entry.AgentExecutableSHA256, loadHermesReceiptDigestForTest(t, opts.DataDir)) {
		t.Fatal("test fixture did not create post-admission digest drift")
	}
	lockPath := filepath.Join(opts.DataDir, hookContractLockFile)
	if err := SaveFreshHookContractLockEntry(opts.DataDir, entry); err == nil ||
		!strings.Contains(err.Error(), "does not match protected executable evidence") {
		t.Fatalf("SaveFreshHookContractLockEntry error = %v, want protected-evidence mismatch", err)
	}
	if _, err := os.Lstat(lockPath); !os.IsNotExist(err) {
		t.Fatalf("failed publication created a contract lock: %v", err)
	}
}

func TestHermesProtectedLockReuseReceivesFreshEquivalentRevalidation(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	opts := prepareHermesSetupAdmissionFixture(t, SetupOpts{DataDir: filepath.Join(root, "defenseclaw-data")})
	entry := NewHookContractLockEntry(opts, NewHermesConnector(), "test-build")
	if err := SaveFreshHookContractLockEntry(opts.DataDir, entry); err != nil {
		t.Fatalf("seal fresh receipt evidence: %v", err)
	}
	if err := os.Remove(filepath.Join(opts.DataDir, agentSelectionFile)); err != nil {
		t.Fatal(err)
	}
	if err := validateHermesWindowsSetupAdmission(context.Background(), opts); err != nil {
		t.Fatalf("valid protected lock reuse failed revalidation: %v", err)
	}
	if err := atomicWriteFile(opts.AgentExecutable, []byte("MZ changed after protected lock"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := validateHermesWindowsSetupAdmission(context.Background(), opts); err == nil ||
		!strings.Contains(err.Error(), "digest does not match protected evidence") {
		t.Fatalf("changed bytes reused protected lock: %v", err)
	}
}

func loadHermesReceiptDigestForTest(t *testing.T, dataDir string) string {
	t.Helper()
	selection, ok := loadSetupAgentSelection(dataDir, "hermes")
	if !ok {
		t.Fatal("protected Hermes receipt unavailable")
	}
	return selection.SHA256
}
