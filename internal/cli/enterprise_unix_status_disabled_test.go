// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// TestUnixStatusTextNamesADisabledConnector is rel-1-0-6:GAP-0325: the
// Linux and macOS status text had no line for Codex once
// guardrail.connectors.codex.enabled was false; it now says codex disabled.
// Other actions print no connectors line.
func TestUnixStatusTextNamesADisabledConnector(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		for _, action := range []string{"status", "verify", "ensure"} {
			r := enterprisestatus.New(action, "standalone", goos, "1.0.7")
			r.Installed, r.InstalledVersion = true, "1.0.7"
			if action != "ensure" {
				r.Connectors, _ = enterprisestatus.BuildConnectors(enterprisestatus.ConnectorInputs{
					ConfigLoaded: true, Enabled: []string{"claudecode"}, Disabled: []string{"codex"},
				}, func(string) string { return "closed" })
			}
			r.Finish(goos, 0)
			var out bytes.Buffer
			if err := printLifecycleResult(&out, r, false); err != nil {
				t.Fatal(err)
			}
			has := strings.Contains(out.String(), "  connectors: claudecode enabled, codex disabled (DefenseClaw does not inspect a disabled connector on this computer)\n")
			if has != (action != "ensure") {
				t.Fatalf("%s %s: connectors line present=%v:\n%s", goos, action, has, out.String())
			}
		}
	}
}
