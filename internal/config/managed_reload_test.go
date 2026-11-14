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

package config

import (
	"strings"
	"testing"
)

func TestManagedReloadRefusal(t *testing.T) {
	m := func(mode string) *Config { return &Config{DeploymentMode: mode} }
	for _, tc := range []struct {
		name       string
		old, next  *Config
		managedWhy string
		liveWhy    string
	}{
		{"oss to oss", m(""), m(""), "", ""},
		{"managed to managed", m("managed_enterprise"), m("managed_enterprise"), "", ""},
		{"managed spelling", m("managed_enterprise"), m("managed-enterprise"), "", ""},
		{"downgrade", m("managed_enterprise"), m(""), "managed_downgrade", "managed_downgrade"},
		{"upgrade", m(""), m("managed_enterprise"), "", "deployment_mode_change"},
		{"nil old", nil, m(""), "", ""},
		{"nil next", m("managed_enterprise"), nil, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			why, err := ManagedReloadRefusal(tc.old, tc.next)
			if why != tc.managedWhy || (err != nil) != (tc.managedWhy != "") {
				t.Fatalf("ManagedReloadRefusal = %q, %v; want %q", why, err, tc.managedWhy)
			}
			why, err = LiveReloadRefusal(tc.old, tc.next)
			if why != tc.liveWhy || (err != nil) != (tc.liveWhy != "") {
				t.Fatalf("LiveReloadRefusal = %q, %v; want %q", why, err, tc.liveWhy)
			}
			if tc.managedWhy == "managed_downgrade" && !strings.Contains(err.Error(), "cannot downgrade deployment_mode from managed_enterprise") {
				t.Fatalf("message = %v", err)
			}
		})
	}
}
