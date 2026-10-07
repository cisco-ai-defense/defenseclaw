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

package kernelpolicy

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// The kernel scope must agree with hook enrollment about which install
// belongs to a user. This package keeps its own small copy of the
// enumerator's probes (the sensor helper stays small); this test fails when
// the two drift.
func TestCLIConnectorsAreKnownToTheEnumerator(t *testing.T) {
	for connector := range cliConnectors {
		if !enterprisehooks.UnixAgentProbeKnown(connector) {
			t.Errorf("%s is not a connector the enumerator probes", connector)
		}
	}
}

// The helper reads the enumerator's eligible-accounts record next to the
// manifest: the same file name, and the record the enumerator writes parses.
func TestEligibleAccountsRecordIsTheEnumerators(t *testing.T) {
	if EligibleAccountsFileName != enterprisehooks.UnixEligibleAccountsFileName {
		t.Fatalf("file name %s, the enumerator writes %s", EligibleAccountsFileName, enterprisehooks.UnixEligibleAccountsFileName)
	}
	const manifest = "/etc/defenseclaw/hook-guardian/targets.yaml"
	if got, want := EligibleAccountsPath(manifest), enterprisehooks.UnixEligibleAccountsPath(manifest); got != want {
		t.Fatalf("path %s, the enumerator writes %s", got, want)
	}
	data, err := json.Marshal(struct {
		Version  int                                   `json:"version"`
		Accounts []enterprisehooks.UnixEligibleAccount `json:"accounts"`
	}{1, []enterprisehooks.UnixEligibleAccount{{User: "alice", UID: 1001, GID: 1001, Home: "/home/alice", HomeInode: 7}}})
	if err != nil {
		t.Fatal(err)
	}
	accounts, err := ParseEligibleAccounts(data)
	if err != nil || !reflect.DeepEqual(accounts, []EligibleAccount{{User: "alice", UID: 1001, Home: "/home/alice"}}) {
		t.Fatalf("%+v %v", accounts, err)
	}
}

func TestUserSearchDirsCoverTheEnumeratorsUserDirs(t *testing.T) {
	const home = "/home/drift"
	mine := map[string]bool{}
	for _, dir := range searchDirs(newMemFS(), home, ResolveOptions{}) {
		mine[dir] = true
	}
	for _, dir := range enterprisehooks.UnixAgentSearchDirs(home) {
		if strings.HasPrefix(dir, home+"/") && !mine[dir] {
			t.Errorf("the enumerator looks for agents in %s and the kernel scope does not", dir)
		}
	}
}
