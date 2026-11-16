// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0114: the managed scanner runtime kept the service TEMP, which the
// gateway's write-restricted token cannot write, so every local MCP server
// scan failed before the server started. The runtime gets a folder in the
// gateway's data folder instead.
func TestScannerRuntimeGetsATemporaryFolderTheGatewayCanWrite(t *testing.T) {
	home := t.TempDir()
	previous := scannerRuntimeDataDir
	t.Cleanup(func() { scannerRuntimeDataDir = previous })
	scannerRuntimeDataDir = func() string { return home }

	base := []string{`TEMP=C:\Windows\TEMP`, `tmp=C:\Windows\TEMP`, `PATH=C:\Windows\System32`}
	vars := map[string][]string{}
	for _, kv := range scannerRuntimeEnv(base, map[string]string{}, nil) {
		name, value, _ := strings.Cut(kv, "=")
		vars[strings.ToUpper(name)] = append(vars[strings.ToUpper(name)], value)
	}
	want := filepath.Join(home, "scanner-tmp")
	if got := vars["TEMP"]; len(got) != 1 || got[0] != want {
		t.Fatalf("TEMP = %v, want only %s", got, want)
	}
	if got := vars["TMP"]; len(got) != 1 || got[0] != want {
		t.Fatalf("TMP = %v, want only %s", got, want)
	}
	if info, err := os.Stat(want); err != nil || !info.IsDir() {
		t.Fatalf("temporary folder %s: %v", want, err)
	}

	// Without a data folder (off Windows) the inherited values stay.
	scannerRuntimeDataDir = func() string { return "" }
	env := strings.Join(scannerRuntimeEnv(base, map[string]string{}, nil), "\n")
	if !strings.Contains(env, `TEMP=C:\Windows\TEMP`) {
		t.Fatalf("env %q lost the inherited TEMP", env)
	}
}
