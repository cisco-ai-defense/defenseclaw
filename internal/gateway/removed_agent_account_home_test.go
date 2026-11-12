// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// The skip of a connector whose agent was removed rests on proof that no agent
// is left in the account, and a Claude Desktop engine folder counts as one.
// The engine-folder test once honoured the XDG_CONFIG_HOME of the process (a
// CI runner sets it) and left an engine folder in that real configuration
// folder, so the removed-agent tests that ran after it in the same process
// found an installed agent and failed the start instead of skipping the
// connector (GAP-0932). This runs those tests in order, in a process whose
// XDG_CONFIG_HOME names a folder of its own, and requires the folder to stay
// empty.
func TestEngineFolderTestsLeaveTheProcessConfigFolderEmpty(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("XDG_CONFIG_HOME is the Linux configuration folder")
	}
	config := filepath.Join(testenv.PrivateTempDir(t), "xdg-config")
	if err := os.Mkdir(config, 0o700); err != nil {
		t.Fatal(err)
	}
	tests := []string{
		"TestClaudeDesktopEngineKeepsClaudeCodeInstalled",
		"TestClaudeDesktopEngineInEveryDataRootKeepsClaudeCodeInstalled",
		"TestRunGuardrailMultiRemovedAgentKeepsOtherConnectors",
		"TestSetupConnectorsIsolatedSkipsAnActiveConnectorWhoseAgentExecutableIsGone",
		"TestPendingAbsentConnectorRetainedHookIsDenied",
	}
	cmd := exec.Command(os.Args[0], "-test.v", "-test.count=1", "-test.run", "^("+strings.Join(tests, "|")+")$")
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "XDG_CONFIG_HOME=") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, "XDG_CONFIG_HOME="+config)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the engine-folder and removed-agent tests failed in order: %v\n%s", err, out)
	}
	for _, name := range tests {
		if !strings.Contains(string(out), "--- PASS: "+name+" ") {
			t.Errorf("%s did not run and pass:\n%s", name, out)
		}
	}
	if left, err := os.ReadDir(config); err != nil || len(left) != 0 {
		t.Errorf("the tests left %d entries in the process configuration folder (error %v)", len(left), err)
	}
}
