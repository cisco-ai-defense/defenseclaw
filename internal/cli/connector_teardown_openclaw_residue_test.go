// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// A failed `defenseclaw setup openclaw` leaves openclaw.json as it is and tells
// the operator to run `defenseclaw-gateway connector teardown --connector
// openclaw`. That one command has to take out the DefenseClaw entries whatever
// the rollback left configured: a prior install that never had OpenClaw (the
// setup remove command reports it already absent) and a prior install that had
// OpenClaw as its only connector (the setup remove command refuses without
// --force). GAP-0973.

const openClawResidueSettings = "// my OpenClaw settings\n" +
	"{\n" +
	"  gateway: { port: 0x4965, },\n" +
	"  plugins: { allow: [\"somebody-else\"], entries: { \"somebody-else\": { enabled: true, }, }, },\n" +
	"}\n"

// openClawResidueRegistered is what the registration of a gateway start makes
// of an openclaw.json that held another plugin: DefenseClaw allowed, enabled
// and loaded from its directory, saved as JSON. The plugin bundle is optional
// in a test build, so this test writes the file itself and runs the real
// command; the next test runs the real registration when the bundle is built.
func openClawResidueRegistered(extDir string) string {
	return "{\n" +
		"  \"gateway\": {\"port\": 18789},\n" +
		"  \"plugins\": {\n" +
		"    \"allow\": [\"somebody-else\", \"defenseclaw\"],\n" +
		"    \"entries\": {\n" +
		"      \"defenseclaw\": {\"enabled\": true},\n" +
		"      \"somebody-else\": {\"enabled\": true}\n" +
		"    },\n" +
		"    \"load\": {\"paths\": [" + strconv.Quote(extDir) + "]}\n" +
		"  }\n" +
		"}\n"
}

// runResidueTeardown leaves the OpenClaw home as the failed setup did (register
// writes openclaw.json), restores the connector state of the rolled-back
// install, runs the teardown command and checks that no DefenseClaw entry is
// left while the operator keeps what was theirs.
func runResidueTeardown(t *testing.T, prior []string, savedAfter bool, register func(t *testing.T, dir, home, configPath string)) {
	t.Helper()
	dir := t.TempDir()
	home := filepath.Join(dir, "openclaw-home")
	extDir := filepath.Join(home, "extensions", "defenseclaw")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	previous := connector.OpenClawHomeOverride
	connector.OpenClawHomeOverride = home
	t.Cleanup(func() { connector.OpenClawHomeOverride = previous })
	configPath := filepath.Join(home, "openclaw.json")
	register(t, dir, home, configPath)
	registered, err := os.ReadFile(configPath)
	if err != nil || !strings.Contains(string(registered), "defenseclaw") {
		t.Fatalf("no DefenseClaw entries to remove (err=%v):\n%s", err, registered)
	}
	if savedAfter {
		saved := strings.Replace(string(registered), "{", "{\"meta\": {\"saved\": true},", 1)
		if err := os.WriteFile(configPath, []byte(saved), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// The state the rollback restored.
	defer withConnectorState(t, dir, strings.Join(prior, ","))()
	if err := connector.SaveActiveConnectors(dir, prior); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, exitCode := runConnectorCmd(t, "teardown", "--connector", "openclaw")
	if exitCode != 0 || stderr != "" {
		t.Fatalf("teardown: exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	got, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "defenseclaw") {
		t.Fatalf("the teardown left DefenseClaw entries:\n%s", got)
	}
	// Benign twin: what the operator had stays (the port is 18789, or 0x4965 when
	// the pre-setup bytes come back).
	if !strings.Contains(string(got), "somebody-else") ||
		(!strings.Contains(string(got), "18789") && !strings.Contains(string(got), "0x4965")) {
		t.Fatalf("the teardown dropped what the operator had:\n%s", got)
	}
	if savedAfter && !strings.Contains(string(got), "saved") {
		t.Fatalf("the teardown dropped the saved key:\n%s", got)
	}
	if _, err := os.Stat(extDir); !os.IsNotExist(err) {
		t.Fatalf("the plugin directory is still there: %v", err)
	}
}

var openClawResidueCases = map[string]struct {
	prior      []string // the connectors the rolled-back install names
	savedAfter bool     // OpenClaw or the operator saved the file after the registration
}{
	"prior install had no OpenClaw":                                   {prior: nil},
	"prior install had OpenClaw as its only one":                      {prior: []string{"openclaw"}},
	"prior install had no OpenClaw and the file was saved afterwards": {prior: nil, savedAfter: true},
	"prior install had OpenClaw and the file was saved afterwards":    {prior: []string{"openclaw"}, savedAfter: true},
}

func TestConnectorTeardownRemovesTheEntriesAFailedOpenClawSetupLeaves(t *testing.T) {
	for name, tc := range openClawResidueCases {
		t.Run(name, func(t *testing.T) {
			runResidueTeardown(t, tc.prior, tc.savedAfter, func(t *testing.T, dir, home, configPath string) {
				extDir := filepath.Join(home, "extensions", "defenseclaw")
				if err := os.MkdirAll(extDir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(extDir, "package.json"), []byte("{}\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(configPath, []byte(openClawResidueRegistered(extDir)), 0o644); err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}

// The same with the registration DefenseClaw makes, which also records the
// conversation grant it adds (needs the plugin bundle, as the connector tests do).
func TestConnectorTeardownRemovesTheEntriesOfARealOpenClawRegistration(t *testing.T) {
	if !connector.OpenClawExtensionAvailable() {
		t.Skip("OpenClaw extension bundle is optional; run `make extensions` before this test")
	}
	for name, tc := range openClawResidueCases {
		t.Run(name, func(t *testing.T) {
			runResidueTeardown(t, tc.prior, tc.savedAfter, func(t *testing.T, dir, home, configPath string) {
				if err := os.WriteFile(configPath, []byte(openClawResidueSettings), 0o644); err != nil {
					t.Fatal(err)
				}
				opts := connector.SetupOpts{DataDir: dir, ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970"}
				if err := connector.NewOpenClawConnector().Setup(context.Background(), opts); err != nil {
					t.Fatalf("registration: %v", err)
				}
			})
		})
	}
}
