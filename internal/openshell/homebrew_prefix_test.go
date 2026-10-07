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
	"os"
	"path/filepath"
	"testing"
)

// TestHomebrewPrefixProblem (GAP-0048): as a standard user on a Mac whose
// Homebrew another account owns, NVIDIA's installer failed with
// "Permission denied @ dir_s_mkdir - /opt/homebrew/Library/Taps/nvidia" and
// setup blamed Xcode. The folders Homebrew writes are checked first.
func TestHomebrewPrefixProblem(t *testing.T) {
	prefix := t.TempDir()
	taps := filepath.Join(prefix, "Library", "Taps")
	if err := os.MkdirAll(taps, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := homebrewPrefixProblem(prefix, func(string) bool { return true }); err != nil {
		t.Fatalf("a writable prefix: %v", err)
	}
	err := homebrewPrefixProblem(prefix, func(dir string) bool { return dir != taps })
	var pe *HomebrewPrefixError
	if !errors.Is(err, ErrHomebrewPrefix) || !errors.As(err, &pe) || pe.Path != taps || pe.Owner == "" {
		t.Fatalf("err = %v (%+v)", err, pe)
	}
	if err := homebrewPrefixProblem(filepath.Join(prefix, "none"), func(string) bool { return false }); err != nil {
		t.Fatalf("no Homebrew there: %v", err)
	}
}
