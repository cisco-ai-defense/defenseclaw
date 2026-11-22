// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-1140: config set connectors.openclaw.plugin_account was refused with
// only "configuration could not be compiled safely" at "$". The candidate
// check names the key and the rule.
func TestConfigValidateNamesTheOpenClawConnectorRefusal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	source := "config_version: 9\ndata_dir: " + dir + "\nconnectors:\n  openclaw:\n    plugin_account: dcw-oc\n"
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	failure := configV8ValidationFailure(mustFailLoad(t, path, dir))
	if failure.Path != "$.connectors.openclaw.plugin_account" || !strings.Contains(failure.Reason, "config_semantic_invalid") ||
		!strings.Contains(failure.Reason, "plugin_account") || strings.Contains(failure.Reason, "could not be compiled safely") {
		t.Fatalf("failure = %+v, want the plugin_account rule at its key", failure)
	}
}
