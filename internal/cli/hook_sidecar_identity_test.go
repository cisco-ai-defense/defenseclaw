// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

func TestReadHookSidecarRetriesReplacementBetweenLookupAndOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".hookcfg")
	stage := path + ".new"
	body := []byte(`{"version":2,"gateway_addr":"127.0.0.1:18970"}`)
	for _, name := range []string{path, stage} {
		if err := os.WriteFile(name, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var swapped bool
	var swapErr error
	t.Cleanup(pathidentity.SetPinnedStatHookForTest(func(candidate string) {
		if candidate == path && !swapped {
			swapped = true
			swapErr = safefile.ReplaceFileAtomically(stage, path)
		}
	}))
	address := readHookSidecar(path)["DEFENSECLAW_GATEWAY_ADDR"]
	if swapErr != nil {
		t.Fatal(swapErr)
	}
	if !swapped {
		t.Fatal("replacement fixture did not run")
	}
	if address != "127.0.0.1:18970" {
		t.Fatalf("gateway address after replacement = %q", address)
	}
}

func TestReadHookSidecarReadsStableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".hookcfg")
	if err := os.WriteFile(path, []byte(`{"version":2,"gateway_addr":"127.0.0.1:18970"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readHookSidecar(path)["DEFENSECLAW_GATEWAY_ADDR"]; got != "127.0.0.1:18970" {
		t.Fatalf("gateway address = %q", got)
	}
}
