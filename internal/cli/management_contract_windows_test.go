// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/contracttest"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// TestManagementContractWindowsSecret validates what Windows
// `enterprise secret set`, `status` and `remove` print with --json.
func TestManagementContractWindowsSecret(t *testing.T) {
	schemas := contracttest.Compile(t)
	windowsSecretTestHarness(t)
	const value = "contract-test-credential-value"

	out, err := runWindowsSecretCommand(t, "set", enterpriseSecretOptions{name: "ai-defense-api-key", fromStdin: true, json: true}, value+"\r\n")
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	if strings.Contains(out, value) {
		t.Fatal("the credential value was printed")
	}
	if doc := schemas.Validate(t, "secret-result.schema.json", []byte(out)); doc["ok"] != true || doc["action"] != "set" {
		t.Fatalf("set result %s", out)
	}

	out, err = runWindowsSecretCommand(t, "status", enterpriseSecretOptions{json: true}, "")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if strings.Contains(out, value) {
		t.Fatal("the credential value was printed")
	}
	schemas.Validate(t, "secret-result.schema.json", []byte(out))

	out, err = runWindowsSecretCommand(t, "remove", enterpriseSecretOptions{name: "ai-defense-api-key", json: true}, "")
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	schemas.Validate(t, "secret-result.schema.json", []byte(out))

	t.Run("failures print one document", func(t *testing.T) {
		opts := enterpriseSecretOptions{name: "ai-defense-api-key", fromStdin: true, json: true}
		notElevated := func(managedHost bool) func() {
			return func() {
				windowsSecretIsElevated = func() bool { return false }
				managedHostWindowsStandalone = func() (string, bool) {
					if managedHost {
						return `HKLM\` + WindowsEnterpriseMarkerKey, true
					}
					return "", false
				}
			}
		}
		cases := map[string]struct {
			setup func()
			opts  enterpriseSecretOptions
			exit  int
		}{
			"not elevated, managed":   {notElevated(true), opts, enterprisestatus.WindowsExitAccessDenied},
			"not elevated, unmanaged": {notElevated(false), opts, windowsSecretExitFailure},
			"bad name":                {func() {}, enterpriseSecretOptions{name: "BAD", fromStdin: true, json: true}, windowsSecretExitInvalid},
			"not installed":           {func() { windowsSecretDeploymentInstalled = func() (bool, error) { return false, nil } }, opts, windowsSecretExitFailure},
		}
		for name, tc := range cases {
			t.Run(name, func(t *testing.T) {
				savedElevated, savedInstalled, savedManaged := windowsSecretIsElevated, windowsSecretDeploymentInstalled, managedHostWindowsStandalone
				t.Cleanup(func() {
					windowsSecretIsElevated, windowsSecretDeploymentInstalled, managedHostWindowsStandalone = savedElevated, savedInstalled, savedManaged
				})
				tc.setup()
				out, err := runWindowsSecretCommand(t, "set", tc.opts, value+"\r\n")
				doc := schemas.Validate(t, "secret-result.schema.json", []byte(out))
				requireExit(t, doc, commandExitCode(err), tc.exit)
				if strings.Contains(out, value) {
					t.Fatal("the credential value was printed")
				}
			})
		}
	})
}
