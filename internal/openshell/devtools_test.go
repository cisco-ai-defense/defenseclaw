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

package openshell_test

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// TestOutdatedXcodeAppUsesHomebrewsMinimums: the check counted the
// Command Line Tools as current when their major release was at least
// macOS's, and Xcode.app as outdated below it. Homebrew's minimums are the
// macOS release's own only from macOS 26 on; before, they are a year
// ahead (Xcode 16.0 and the Command Line Tools 16.0.0 on macOS 15). On
// macOS 15.6 with the tools 15.3 and Xcode 14.3.1, Homebrew refuses both,
// and setup said the tools were current and that updating them did not
// help; with the tools 16.4 and Xcode 15.4, Homebrew refuses Xcode alone,
// and setup gave the generic hint. The check compares against Homebrew's
// minimum for the release.
func TestOutdatedXcodeAppUsesHomebrewsMinimums(t *testing.T) {
	for _, tc := range []struct {
		name, macOS, clt, xcode string
		outdated                bool
	}{
		// macOS 15: Xcode 16.0, the Command Line Tools 16.0.0.
		{"macOS 15, tools and Xcode.app both too old", "15.6", "15.3.0.0.1.1708646388", "14.3.1", false},
		{"macOS 15, current tools, Xcode.app 15.4", "15.6", "16.4.0.0.1.1747106510", "15.4", true},
		{"macOS 15, tools 16.0.0, Xcode.app 16.0", "15.6", "16.0.0.0.1.1724870825", "16.0", false},
		{"macOS 15, current tools, Xcode.app 16.2", "15.6.1", "16.4.0.0.1.1747106510", "16.2", false},
		// macOS 14: Xcode 15.0, the Command Line Tools 15.0.0.
		{"macOS 14, current tools, Xcode.app 14.3.1", "14.7.6", "15.0.0.0.1.1694021235", "14.3.1", true},
		{"macOS 14, tools 14.3.1 too old", "14.7.6", "14.3.1.0.1.1683849156", "14.3.1", false},
		{"macOS 14, current tools, Xcode.app 15.0", "14.7.6", "15.3.0.0.1.1708646388", "15.0", false},
		// macOS 13: Xcode 14.1, the Command Line Tools 14.0.0.
		{"macOS 13, current tools, Xcode.app 14.0.1", "13.7.8", "14.0.0.0.1.1661618636", "14.0.1", true},
		{"macOS 13, current tools, Xcode.app 14.1", "13.7.8", "14.3.1.0.1.1683849156", "14.1", false},
		{"macOS 13, tools 13.4 too old", "13.7.8", "13.4.0.0.1.1651278267", "13.4.1", false},
		// From macOS 26 on the release's own: Xcode 27.0 and the Command
		// Line Tools 27.0.0 on macOS 27.
		{"macOS 27, current tools, Xcode.app 26.2", "27.0", "27.0.0.0.1.1788430756", "26.2", true},
		{"macOS 27, current tools, Xcode.app 27.0", "27.0", "27.0.0.0.1.1788430756", "27.0", false},
		{"macOS 27, tools 26.2 too old", "27.0", "26.2.0.0.1.1764812424", "26.2", false},
		// What Homebrew's minimums are not known for, or a version that
		// could not be read, does not count.
		{"macOS 10.15", "10.15.7", "12.4.0.0.1.1648179577", "11.7", false},
		{"no macOS version", "", "27.0.0.0.1.1788430756", "26.2", false},
		{"no tools version", "27.0", "", "26.2", false},
		{"Xcode.app version not a number", "27.0", "27.0.0.0.1.1788430756", "26.2 beta", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := &openshell.DeveloperTools{MacOS: tc.macOS, Selected: openshell.CommandLineTools, CLT: tc.clt,
				XcodeApp: openshell.XcodeApp, Xcode: tc.xcode}
			if got := d.OutdatedXcodeApp(); got != tc.outdated {
				t.Fatalf("OutdatedXcodeApp = %t for %+v, want %t", got, d, tc.outdated)
			}
			// With Xcode.app selected, the Xcode Homebrew refuses is the
			// selected one, which the generic hint covers.
			d.Selected = openshell.XcodeApp + "/Contents/Developer"
			if d.OutdatedXcodeApp() {
				t.Fatalf("OutdatedXcodeApp with Xcode.app selected for %+v", d)
			}
		})
	}
}
