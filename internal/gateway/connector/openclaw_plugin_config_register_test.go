// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"reflect"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/openclawschema"
)

// GAP-1862: a second registration of the OpenClaw plugin config check (or a
// nil one) panics and keeps the registered check, as RegisterV8SchemaCheck
// does; it used to replace the check silently.
func TestOpenClawPluginConfigCheckRegistersOnce(t *testing.T) {
	registered := openClawPluginConfigMigrator
	if registered == nil {
		t.Fatal("the connector test program registers the check (openclaw_schema_link_test.go)")
	}
	for name, check := range map[string]func(map[string]interface{}, interface{}) (interface{}, bool, []string, error){
		"nil":    nil,
		"second": openclawschema.Migrate,
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s registration did not panic", name)
				}
				if reflect.ValueOf(openClawPluginConfigMigrator).Pointer() != reflect.ValueOf(registered).Pointer() {
					t.Errorf("%s registration replaced the check", name)
				}
			}()
			SetOpenClawPluginConfigMigrator(check)
		}()
	}
}
