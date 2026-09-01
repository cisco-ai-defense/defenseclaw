// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func TestAmpSealedExecutableAuthoritySurvivesReceiptExpiry(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	opts := prepareAmpSetupOptsForTest(t, SetupOpts{
		DataDir:    filepath.Join(root, "data"),
		ConfigHome: filepath.Join(root, "amp-config"),
		APIAddr:    "127.0.0.1:18970",
		APIToken:   "amp-scoped-token",
	})
	conn := NewAMPConnector()
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("initial Amp setup: %v", err)
	}
	entry := NewHookContractLockEntry(opts, conn, "test-build")
	if err := SaveFreshHookContractLockEntry(opts.DataDir, entry); err != nil {
		t.Fatalf("seal Amp executable authority: %v", err)
	}
	if err := os.Remove(filepath.Join(opts.DataDir, agentSelectionFile)); err != nil {
		t.Fatalf("remove expired setup receipt fixture: %v", err)
	}

	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("setup with intact sealed Amp authority: %v", err)
	}
	if err := validateAmpWindowsLockPublication(
		opts.DataDir,
		NewHookContractLockEntry(opts, conn, "test-build"),
	); err != nil {
		t.Fatalf("revalidate intact sealed Amp authority: %v", err)
	}
}

func TestAmpSealedExecutableAuthorityRejectsBinaryReplacement(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	opts := prepareAmpSetupOptsForTest(t, SetupOpts{
		DataDir:    filepath.Join(root, "data"),
		ConfigHome: filepath.Join(root, "amp-config"),
		APIAddr:    "127.0.0.1:18970",
		APIToken:   "amp-scoped-token",
	})
	conn := NewAMPConnector()
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("initial Amp setup: %v", err)
	}
	entry := NewHookContractLockEntry(opts, conn, "test-build")
	if err := SaveFreshHookContractLockEntry(opts.DataDir, entry); err != nil {
		t.Fatalf("seal Amp executable authority: %v", err)
	}
	if err := os.Remove(filepath.Join(opts.DataDir, agentSelectionFile)); err != nil {
		t.Fatalf("remove expired setup receipt fixture: %v", err)
	}

	pluginPath := ampPluginPath(opts)
	const sentinel = "operator-edited Amp plugin sentinel\n"
	if err := atomicWriteFile(pluginPath, []byte(sentinel), 0o600); err != nil {
		t.Fatalf("write plugin mutation sentinel: %v", err)
	}
	if err := atomicWriteFile(opts.AgentExecutable, []byte("replacement Amp executable bytes"), 0o700); err != nil {
		t.Fatalf("replace sealed Amp executable: %v", err)
	}

	err := conn.Setup(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "digest does not match protected evidence") {
		t.Fatalf("setup after Amp binary replacement error=%v, want protected digest rejection", err)
	}
	body, readErr := os.ReadFile(pluginPath)
	if readErr != nil {
		t.Fatalf("read plugin after rejected setup: %v", readErr)
	}
	if string(body) != sentinel {
		t.Fatalf("rejected setup mutated Amp plugin: %q", body)
	}

	replacementEntry := NewHookContractLockEntry(opts, conn, "test-build")
	if err := SaveFreshHookContractLockEntry(opts.DataDir, replacementEntry); err == nil ||
		!strings.Contains(err.Error(), "does not match protected executable evidence") {
		t.Fatalf("contract publication after Amp binary replacement error=%v, want protected evidence rejection", err)
	}
}

func prepareAmpSetupOptsForTest(t *testing.T, opts SetupOpts) SetupOpts {
	t.Helper()
	if opts.DataDir == "" {
		opts.DataDir = filepath.Join(testenv.PrivateTempDir(t), "data")
	}
	if err := ensureManagedBackupDirRestricted(opts.DataDir); err != nil {
		t.Fatalf("prepare protected Amp state: %v", err)
	}
	executableRoot := testenv.PrivateTempDir(t)
	executable := filepath.Join(executableRoot, "amp.exe")
	if err := atomicWriteFile(executable, []byte("fixture native Amp executable"), 0o700); err != nil {
		t.Fatalf("write Amp executable fixture: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	const rawVersion = "0.0.1785875347-gbc402f"
	selection := writeAmpSetupSelectionForTest(
		t,
		opts.DataDir,
		executable,
		rawVersion,
		"0.0.1785875347",
		now,
		now.Add(agentSelectionMaxLifetime),
	)
	resolution := ResolveHookContract("amp", selection.RawVersion)
	opts.AgentVersion = selection.RawVersion
	opts.AgentExecutable = selection.Executable
	opts.HookContractID = resolution.Contract.ContractID
	return opts
}
