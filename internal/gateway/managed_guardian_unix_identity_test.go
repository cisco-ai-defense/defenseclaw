//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The standalone Unix guardian records each protected target's uid and
// home inode; the gateway's strict ledger decode must accept them.
func TestManagedGuardianCoverageAcceptsStandaloneUnixIdentity(t *testing.T) {
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, t.TempDir())
	oldValidate := validateManagedGuardianAuthorization
	validateManagedGuardianAuthorization = func(_, _ string) error { return nil }
	t.Cleanup(func() { validateManagedGuardianAuthorization = oldValidate })
	path := managed.HookGuardianAuthorizationPath(t.TempDir())
	data := []byte(fmt.Sprintf(`{
		"version":1,
		"updated_at":%q,
		"ok":true,
		"target_count":1,
		"success_count":1,
		"failure_count":0,
		"protected_targets":[{"user":"ldapuser","user_home":"/home/ldapuser","connector":"codex","ok":true,"uid":1234567,"home_inode":42}]
	}`, time.Now().UTC().Format(time.RFC3339)))
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if ok, reason := managedGuardianCoversConnectors("unused", []string{"codex"}); !ok {
		t.Fatalf("a standalone ledger row with uid and home_inode was rejected: %s", reason)
	}
}
