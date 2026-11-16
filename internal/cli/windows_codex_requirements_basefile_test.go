// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// GAP-1001: a failure that matches the busy-writer sentinel reaches the JSON
// report as error_code writer_lock_busy; no other failure does.
func TestAnnotateWindowsCodexRequirementsFailureSetsTheWriterLockBusyCode(t *testing.T) {
	var busy connector.WindowsCodexMachineRequirementsReport
	annotateWindowsCodexRequirementsFailure(&busy, fmt.Errorf("Codex requirements reconcile failed: %w", connector.ErrWindowsCodexWriterLockBusy))
	if busy.ErrorCode != "writer_lock_busy" {
		t.Fatalf("error code = %q", busy.ErrorCode)
	}
	raw, err := json.Marshal(busy)
	if err != nil || !strings.Contains(string(raw), `"error_code":"writer_lock_busy"`) {
		t.Fatalf("the report does not carry the code: %s %v", raw, err)
	}
	for name, cause := range map[string]error{"nil": nil, "other": errors.New("open Codex machine policy lock: access denied")} {
		var other connector.WindowsCodexMachineRequirementsReport
		annotateWindowsCodexRequirementsFailure(&other, cause)
		raw, _ := json.Marshal(other)
		if other.ErrorCode != "" || strings.Contains(string(raw), "error_code") {
			t.Fatalf("%s: a code was set: %s", name, raw)
		}
	}
}

// GAP-1001: the document a reconcile renders into is read only from the
// recovered-policy folder beside the ownership record, as text.
func TestReadWindowsCodexRequirementsBaseFile(t *testing.T) {
	install := t.TempDir()
	ownership := filepath.Join(install, "codex-requirements-ownership.json")
	folder := filepath.Join(install, "recovered-policy")
	if err := os.MkdirAll(folder, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name string, data []byte) string {
		path := filepath.Join(folder, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if got, err := readWindowsCodexRequirementsBaseFile(write("ok.toml", []byte("[features]\nfoo = true\n")), ownership); err != nil || !strings.Contains(string(got), "foo") {
		t.Fatalf("a text base was refused: %q %v", got, err)
	}
	if got, err := readWindowsCodexRequirementsBaseFile(write("empty.toml", nil), ownership); err != nil || len(got) != 0 {
		t.Fatalf("an empty base renders the managed policy alone: %q %v", got, err)
	}
	for name, data := range map[string][]byte{"nul.toml": {0x61, 0, 0x62}, "latin.toml": {0xc3, 0x28}} {
		if _, err := readWindowsCodexRequirementsBaseFile(write(name, data), ownership); err == nil || !strings.Contains(err.Error(), "UTF-8") {
			t.Fatalf("%s must be refused as not text: %v", name, err)
		}
	}
	outside := filepath.Join(install, "elsewhere.toml")
	if err := os.WriteFile(outside, []byte("[features]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{outside, filepath.Join(folder, "..", "elsewhere.toml"), folder, filepath.Join(folder, "missing.toml")} {
		if _, err := readWindowsCodexRequirementsBaseFile(path, ownership); err == nil {
			t.Fatalf("%s must be refused", path)
		}
	}
	if _, err := readWindowsCodexRequirementsBaseFile(write("big.toml", make([]byte, windowsCodexRequirementsBaseFileLimit+1)), ownership); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("an oversized base must be refused: %v", err)
	}
}
