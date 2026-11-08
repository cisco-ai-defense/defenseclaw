// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"strings"
	"testing"
)

// rel-1-0-6 GAP-0188: config validate on a standalone managed Linux or macOS
// host refuses a top-level audit_db or judge_bodies_db in the words ensure
// uses, naming the key that replaced it, in the error and the JSON message.
func TestConfigValidateOnManagedHostNamesTheKeyAMovedStorePathKeyBecame(t *testing.T) {
	onStandaloneManagedHost(t)
	for key, home := range map[string]string{
		"audit_db":        "observability.local.path",
		"judge_bodies_db": "observability.local.judge_bodies_path",
	} {
		path, out, err := runConfigValidate(t, managedValidateHead+key+": /var/tmp/store.db\n", true)
		if err == nil {
			t.Fatalf("%s: config validate accepted the candidate", key)
		}
		if !strings.HasPrefix(err.Error(), path) || !strings.Contains(err.Error(), key+" was retired in config_version 8; use "+home+".") {
			t.Fatalf("%s: refusal = %q, want it to name %s", key, err, home)
		}
		if !strings.Contains(out, home) {
			t.Fatalf("%s: JSON = %q, want it to name %s", key, out, home)
		}
	}
}
