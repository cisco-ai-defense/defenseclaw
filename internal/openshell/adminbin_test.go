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
	"errors"
	"slices"
	"strings"
	"testing"
)

// The administrator's binary comes from the system folders only, in order,
// and only when the managed trust check passes (GAP-0186, GAP-0221).
func TestAdminBinaryDirsAndTrust(t *testing.T) {
	if got := AdminBinaryDirs("linux"); !slices.Equal(got, []string{"/usr/bin", "/usr/local/bin"}) {
		t.Fatalf("linux dirs = %v", got)
	}
	if got := AdminBinaryDirs("darwin"); !slices.Equal(got, []string{"/usr/local/bin", "/opt/homebrew/bin"}) {
		t.Fatalf("darwin dirs = %v", got)
	}
	// A binary that does not exist is not found, and the error names where
	// it was looked for.
	_, err := AdminBinary("linux", "openshell-no-such-binary", func(string) error { return nil })
	if !errors.Is(err, ErrNoAdminBinary) || !strings.Contains(err.Error(), "/usr/bin, /usr/local/bin") {
		t.Fatalf("missing binary: %v", err)
	}
	// One that exists but fails the trust check is named with the reason.
	_, err = AdminBinary("linux", "sh", func(string) error { return errors.New("owned by a user") })
	if err == nil {
		t.Skip("no sh in /usr/bin or /usr/local/bin")
	}
	if !errors.Is(err, ErrNoAdminBinary) || !strings.Contains(err.Error(), "owned by a user") {
		t.Fatalf("untrusted binary: %v", err)
	}
	path, err := AdminBinary("linux", "sh", func(string) error { return nil })
	if err != nil || (path != "/usr/bin/sh" && path != "/usr/local/bin/sh") {
		t.Fatalf("trusted binary = %q, %v", path, err)
	}
}
