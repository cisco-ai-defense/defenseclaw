// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func TestWindowsCodexRegistrationEvidenceMatchesRenderedPerUserOutageMode(t *testing.T) {
	for _, mode := range []string{"open", "closed"} {
		t.Run(mode, func(t *testing.T) {
			dataDir := testenv.PrivateTempDir(t)
			hookDir := filepath.Join(dataDir, "hooks")
			if err := os.MkdirAll(hookDir, 0o700); err != nil {
				t.Fatal(err)
			}
			conn := NewCodexConnector()
			opts := SetupOpts{
				DataDir: dataDir, APIAddr: "127.0.0.1:18970", HookFailMode: mode,
			}
			if got := resolveHookFailMode(opts, conn); got != "closed" {
				t.Fatalf("non-outage failure mode = %q, want closed", got)
			}
			renderedMode := renderedHookFailMode(opts, conn)
			if renderedMode != mode {
				t.Fatalf("rendered outage mode = %q, want %q", renderedMode, mode)
			}
			if err := writeHookConfigSidecar(hookDir, opts.APIAddr, conn.Name(), renderedMode, false); err != nil {
				t.Fatal(err)
			}
			if err := SaveFreshHookContractLockEntry(dataDir, NewHookContractLockEntry(opts, conn, "test-version")); err != nil {
				t.Fatal(err)
			}
			current, err := HookRuntimeRegistrationCurrent(opts, conn, "test-version")
			if err != nil || !current {
				t.Fatalf("fresh Codex registration evidence: current=%v err=%v", current, err)
			}
		})
	}
}
