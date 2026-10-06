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

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestIdentitySpoolKeepsRecordsOfAccountsAPassDidNotList pins GAP-0145: a
// pass that did not list an account (it could not decide it while the
// directory was unreachable) must not delete its record while the gateway
// still trusts it; a record older than that goes.
func TestIdentitySpoolKeepsRecordsOfAccountsAPassDidNotList(t *testing.T) {
	dir := t.TempDir()
	for name, age := range map[string]time.Duration{"94401103.json": 5 * time.Minute, "94401104.json": 2 * IdentitySpoolMaxAge} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("{}"), 0o640); err != nil {
			t.Fatal(err)
		}
		when := time.Now().Add(-age)
		if err := os.Chtimes(path, when, when); err != nil {
			t.Fatal(err)
		}
	}
	if err := WriteIdentitySpool(context.Background(), dir, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "94401103.json")); err != nil {
		t.Errorf("the record of an unlisted account that is still trusted was removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "94401104.json")); !os.IsNotExist(err) {
		t.Errorf("a record older than IdentitySpoolMaxAge was kept (stat error %v)", err)
	}
}
