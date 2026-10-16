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

//go:build !windows

package packs

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0510: a managed standalone configuration whose locked openshell.pack
// inherits workspace.mode: mount (extends balanced) is refused at load with
// the pack's field and the fix, as every user's policy refused it at each
// explain and run; the same pack in copy mode loads.
func TestLockedManagedPackMountIsRefusedAtLoad(t *testing.T) {
	trustAllPacks(t)
	dir := t.TempDir()
	writePack(t, dir, "wk-locked", "version: 1\nname: wk-locked\nextends: balanced\negress: {block: [github.com]}\n")
	writePack(t, dir, "wk-copy", "version: 1\nname: wk-copy\nextends: balanced\negress: {block: [github.com]}\nworkspace: {mode: copy}\n")
	for _, tc := range []struct {
		pack string
		want string
	}{
		{pack: "wk-locked", want: "workspace.mode (managed computers run sandboxes on a copy of the project: set workspace.mode: copy in the pack)"},
		{pack: "wk-copy"},
	} {
		t.Run(tc.pack, func(t *testing.T) {
			cfg := managedTestConfig(func(o *config.OpenShellConfig) {
				o.PackDir, o.Pack = dir, tc.pack
				o.Admin.Locked = []string{"pack"}
			})
			cfg.Enterprise.Profile = "standalone"
			err := cfg.ValidateGuardrailProfiles()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("ValidateGuardrailProfiles() = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), `openshell.pack "wk-locked"`) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ValidateGuardrailProfiles() = %v, want %q", err, tc.want)
			}
		})
	}
}
