// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package openshell

import (
	"path/filepath"
	"testing"
)

// rel-1-0-10:GAP-1781: every release setup mode can install knows the
// migration level its gateway leaves, so a lower pin is caught before its
// gateway fails to open the database.
func TestGatewayDBMigrationsCoverEveryPin(t *testing.T) {
	for release := range TarballPins {
		if GatewayDBMigrations[release] == 0 {
			t.Errorf("TarballPins release %s has no GatewayDBMigrations entry", release)
		}
	}
	if GatewayDBMigrations[InstallerVersion] < GatewayDBMigrations[SupportedMin] {
		t.Errorf("InstallerVersion %s migrates below SupportedMin %s", InstallerVersion, SupportedMin)
	}
}

func TestReleaseOfMigration(t *testing.T) {
	for level, want := range map[int]string{1: "0.1.6", 8: "0.1.6", 9: "0.1.7", 10: "0.1.9", 11: "a release newer than 0.1.9"} {
		if got := ReleaseOfMigration(level); got != want {
			t.Errorf("ReleaseOfMigration(%d) = %q, want %q", level, got, want)
		}
	}
	if got, want := GatewayDBPath("/home/a"), filepath.Join("/home/a", ".local", "state", "openshell", "gateway", "openshell.db"); got != want {
		t.Errorf("GatewayDBPath = %q, want %q", got, want)
	}
}
