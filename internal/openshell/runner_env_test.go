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
	"slices"
	"testing"
)

// TestCommandsGetTheUserRuntimeDir (GAP-0058): in a login shell from
// `sudo -iu` or `su -l`, XDG_RUNTIME_DIR is unset although the user
// manager runs, and the doctor's `systemctl --user show` failed with
// "Failed to connect to bus: No medium found". Commands get the caller's
// runtime directory when the environment has none; one that is set stays.
func TestCommandsGetTheUserRuntimeDir(t *testing.T) {
	dir := func() string { return "/run/user/1000" }
	if got := withRuntimeDir([]string{"HOME=/home/dev"}, dir); !slices.Equal(got, []string{"HOME=/home/dev", "XDG_RUNTIME_DIR=/run/user/1000"}) {
		t.Fatalf("unset: %v", got)
	}
	if got := withRuntimeDir([]string{"XDG_RUNTIME_DIR="}, dir); !slices.Contains(got, "XDG_RUNTIME_DIR=/run/user/1000") {
		t.Fatalf("empty: %v", got)
	}
	if got := withRuntimeDir([]string{"XDG_RUNTIME_DIR=/run/user/1001"}, dir); !slices.Equal(got, []string{"XDG_RUNTIME_DIR=/run/user/1001"}) {
		t.Fatalf("set: %v", got)
	}
	if got := withRuntimeDir([]string{"HOME=/home/dev"}, func() string { return "" }); !slices.Equal(got, []string{"HOME=/home/dev"}) {
		t.Fatalf("no runtime dir: %v", got)
	}
}
