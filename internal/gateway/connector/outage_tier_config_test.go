// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"testing"
)

// outageDefaultTierConfig and outageStrictTierConfig are config.yaml files
// whose rule pack is the default and the strict one.
const (
	outageDefaultTierConfig = "config_version: 9\nobservability: {}\nguardrail:\n  mode: observe\n"
	outageStrictTierConfig  = outageDefaultTierConfig + "  rule_pack: strict\n"
)

// writeOutageTierConfig writes config.yaml into the data directory dir; an
// empty body writes none.
func writeOutageTierConfig(t *testing.T, dir, body string) {
	t.Helper()
	if body == "" {
		return
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	// As the account of dir, never the account running the tests: the
	// record write also records the config that account runs under
	// (.config-record), and a real ~/.defenseclaw of the build account
	// must not decide a case (rel-1-0-10:GAP-1176).
	if err := WithUserHomeDir(dir, func() error {
		return writePerUserGatewayHelperRecord(filepath.Join(dir, "hooks"))
	}); err != nil {
		t.Fatal(err)
	}
}

// installOutageOpenRuntimeForHookTest gives a per-user hook test what an
// installed outage-open hook asks before it lets a call run while the gateway
// is down (defenseclaw_config_outage_open, `hook-outage-mode`): this
// account's gateway binary in home/.local/bin and a default-tier config.yaml
// in dataDir. The hook's environment must keep cold starts off
// (DEFENSECLAW_GATEWAY_AUTOSTART=0), or the hook starts a gateway from it.
func installOutageOpenRuntimeForHookTest(t *testing.T, home, dataDir string) {
	t.Helper()
	installNativeGatewayForHookTest(t, home)
	writeOutageTierConfig(t, dataDir, outageDefaultTierConfig)
}
