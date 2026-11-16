// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// scanners.mcp_scanner.binary may be relative: ./bin/project-scanner runs in the
// project folder, and ./bin/defenseclaw (the scanner runtime, which never
// runs in the project) in the gateway's folder. Both ran before the Linux
// MCP scan got its contained runner and must still run with it.
func TestMCPScannerRunsARelativeScannerBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fixture is a Unix executable path")
	}
	fixture := buildScannerFixture(t, `{"scanner":"mcp-scanner","target":"my-server","findings":[{"id":"f1","severity":"HIGH","title":"t"}]}`+"\n", 0)
	raw, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, binary string }{
		{name: "project scanner", binary: "./bin/project-scanner"},
		{name: "scanner runtime", binary: "./bin/defenseclaw"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			project := t.TempDir()
			if err := os.MkdirAll(filepath.Join(project, "bin"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(project, tc.binary), raw, 0o755); err != nil {
				t.Fatal(err)
			}
			if usesScannerRuntime(tc.binary) {
				t.Chdir(project) // the runtime runs in the gateway's folder
			} else {
				t.Chdir(t.TempDir()) // only cmd.Dir can find it
			}
			ms := NewMCPScannerFromLLM(config.MCPScannerConfig{Binary: tc.binary}, config.LLMConfig{}, config.CiscoAIDefenseConfig{})
			ms.Project = project
			result, err := ms.Scan(context.Background(), "my-server")
			if err != nil {
				t.Fatalf("scan with %s: %v", tc.binary, err)
			}
			if result == nil || result.ExitCode != 0 || len(result.Findings) != 1 {
				t.Fatalf("scan with %s = %+v, want one finding", tc.binary, result)
			}
		})
	}
}
