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
