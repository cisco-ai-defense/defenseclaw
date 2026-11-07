// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

const movedStorePathKeyConfig = "config_version: 9\ndeployment_mode: managed_enterprise\nenterprise:\n  profile: standalone\n" +
	"guardrail:\n  enabled: true\n  mode: observe\n"

// rel-1-0-6 GAP-0188: the Windows managed ensure preflight (the gateway
// service's own compile of the supplied config) refuses a top-level
// audit_db or judge_bodies_db in the words the Linux and macOS refusal uses,
// naming the key that replaced it; config validate's diagnostic, which the
// Python CLI words as "did you mean", names it too.
func TestStandaloneGatewayConfigCheckNamesTheKeyAMovedStorePathKeyBecame(t *testing.T) {
	dataDir := t.TempDir()
	// Without the key the schema passes (the test host has no rule packs,
	// so a later check may still refuse it, for another reason).
	if err := validateStandaloneGatewayConfig(writeStandaloneGatewayCheckConfig(t, movedStorePathKeyConfig), dataDir, ""); err != nil &&
		strings.Contains(err.Error(), "unknown setting") {
		t.Fatalf("clean config refused by the schema: %v", err)
	}
	for key, home := range map[string]string{
		"audit_db":        "observability.local.path",
		"judge_bodies_db": "observability.local.judge_bodies_path",
	} {
		path := writeStandaloneGatewayCheckConfig(t, movedStorePathKeyConfig+key+": /var/tmp/store.db\n")
		err := validateStandaloneGatewayConfig(path, dataDir, "")
		if err == nil || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), key+" was retired in config_version 8; use "+home) {
			t.Fatalf("%s: ensure preflight = %v, want it to name %s", key, err, home)
		}
		_, loadErr := loadManagedCandidateV8File(path, dataDir, "")
		var schemaErr *config.V8SchemaError
		if !errors.As(loadErr, &schemaErr) {
			t.Fatalf("%s: load = %v, want a schema error", key, loadErr)
		}
		if failure := configV8ValidationFailure(loadErr); failure.Path != "$."+key || !strings.Contains(failure.Reason, key+" was retired in config_version 8; use "+home) {
			t.Fatalf("%s: validate diagnostic = %+v, want it to name %s", key, failure, home)
		}
	}
}
