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
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// Where a Mac's developer tools are, as Homebrew looks for them.
const (
	// XcodeApp is the Xcode Homebrew checks before it builds a formula from
	// source, whichever developer directory xcode-select selects.
	XcodeApp = "/Applications/Xcode.app"
	// CommandLineTools is the developer directory of Apple's Command Line
	// Tools.
	CommandLineTools = "/Library/Developer/CommandLineTools"
)

// cltPackage is the package pkgutil knows the Command Line Tools by (the
// one Homebrew reads their version from).
const cltPackage = "com.apple.pkg.CLTools_Executables"

// DeveloperTools are a Mac's developer tools as Homebrew checks them
// before it builds a formula from source, which it does for NVIDIA's
// nvidia/openshell formula: the tap has no bottle.
type DeveloperTools struct {
	// MacOS is the macOS release (sw_vers -productVersion).
	MacOS string `json:"macos,omitempty"`
	// Selected is the developer directory xcode-select selects.
	Selected string `json:"selected,omitempty"`
	// CLT is the Command Line Tools' version ("" when not installed).
	CLT string `json:"command_line_tools,omitempty"`
	// XcodeApp is the Xcode.app found at XcodeApp ("" when there is none)
	// and Xcode its version ("" when it could not be read).
	XcodeApp string `json:"xcode_app,omitempty"`
	Xcode    string `json:"xcode,omitempty"`
}

// OutdatedXcodeApp reports current Command Line Tools, which xcode-select
// selects (at least the ones Homebrew wants on this macOS release:
// homebrewMinimums), next to an Xcode.app older than the Xcode Homebrew
// wants. Homebrew refuses that Xcode.app even so ("Your Xcode (26.2) at
// /Applications/Xcode.app is too outdated. Please update to Xcode 27.0 (or
// delete it)."): updating or removing it is the fix, not the Command Line
// Tools. A version that could not be read does not count.
func (d *DeveloperTools) OutdatedXcodeApp() bool {
	if d == nil || d.XcodeApp == "" || d.Xcode == "" || filepath.Clean(d.Selected) != CommandLineTools {
		return false
	}
	xcode, clt, ok := homebrewMinimums(d.MacOS)
	if !ok {
		return false
	}
	cltCurrent, cltKnown := atLeast(d.CLT, clt)
	xcodeCurrent, xcodeKnown := atLeast(d.Xcode, xcode)
	return cltKnown && xcodeKnown && cltCurrent && !xcodeCurrent
}

// homebrewMinimum are the oldest Xcode and Command Line Tools Homebrew
// builds a formula from source with on the macOS releases before 26
// (MacOS::Xcode.minimum_version and MacOS::CLT.minimum_version in its
// os/mac/xcode.rb): the tools of the next year's release, so macOS 15
// needs Xcode 16.0 and the Command Line Tools 16.0.0.
var homebrewMinimum = map[int]struct{ xcode, clt string }{
	15: {"16.0", "16.0.0"},
	14: {"15.0", "15.0.0"},
	13: {"14.1", "14.0.0"},
	12: {"13.1", "13.0.0"},
	11: {"12.2", "12.5.0"},
}

// homebrewMinimums are the oldest Xcode and Command Line Tools Homebrew
// builds a formula from source with on macOS (sw_vers -productVersion):
// homebrewMinimum's before macOS 26, from 26 on (the release after 15) the
// release's own ("27.0" and "27.0.0" on macOS 27). Below either Homebrew
// stops before the build ("Your Xcode (26.2) at /Applications/Xcode.app is
// too outdated.", "Your Command Line Tools are too outdated."). ok is
// false where they are not known: before macOS 11, or no version.
func homebrewMinimums(macOS string) (xcode, clt string, ok bool) {
	major := majorVersion(macOS)
	if m, found := homebrewMinimum[major]; found {
		return m.xcode, m.clt, true
	}
	if major <= 15 {
		return "", "", false
	}
	return fmt.Sprintf("%d.0", major), fmt.Sprintf("%d.0.0", major), true
}

// atLeast reports whether the dotted version v is want or later, compared
// as numbers part by part, a missing part counting as 0 ("16.0" is
// "16.0.0", and "15.3.0.0.1.1708646388" comes before "16.0.0"); known is
// false when either is not a dotted version.
func atLeast(v, want string) (current, known bool) {
	a, b := versionParts(v), versionParts(want)
	if a == nil || b == nil {
		return false, false
	}
	for i := 0; i < len(a) || i < len(b); i++ {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			return x > y, true
		}
	}
	return true, true
}

// versionParts are the numbers of a dotted version (nil when a part is
// not a number).
func versionParts(v string) []int {
	var parts []int
	for _, s := range strings.Split(strings.TrimSpace(v), ".") {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			return nil
		}
		parts = append(parts, n)
	}
	return parts
}

// ShortVersion is v's major and minor release ("27.0.0.0.1.1788430756" is
// 27.0).
func ShortVersion(v string) string {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) > 2 {
		parts = parts[:2]
	}
	return strings.Join(parts, ".")
}

// majorVersion is the major release of a dotted version (0: none).
func majorVersion(v string) int {
	n, err := strconv.Atoi(strings.SplitN(strings.TrimSpace(v), ".", 2)[0])
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// xcodeVersionKey finds CFBundleShortVersionString in an XML property list.
var xcodeVersionKey = regexp.MustCompile(`<key>CFBundleShortVersionString</key>\s*<string>([^<]*)</string>`)

// probeDeveloperTools asks sw_vers, xcode-select and pkgutil, which change
// nothing, and reads the version of the Xcode.app at app. What cannot be
// learned stays empty.
func probeDeveloperTools(ctx context.Context, run Runner, app string) *DeveloperTools {
	output := func(name string, args ...string) string {
		out, err := run.Output(ctx, Command{Name: name, Args: args, Timeout: 30 * time.Second})
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(out))
	}
	d := &DeveloperTools{MacOS: output("sw_vers", "-productVersion"), Selected: output("xcode-select", "-p")}
	for _, line := range strings.Split(output("pkgutil", "--pkg-info="+cltPackage), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "version:"); ok {
			d.CLT = strings.TrimSpace(v)
		}
	}
	if info, err := os.Stat(app); err == nil && info.IsDir() {
		d.XcodeApp = app
		if data, err := safefile.ReadRegularFileBounded(filepath.Join(app, "Contents", "version.plist"), 64<<10); err == nil {
			if m := xcodeVersionKey.FindSubmatch(data); m != nil {
				d.Xcode = strings.TrimSpace(string(m[1]))
			}
		}
	}
	return d
}

// HomebrewInstallError is ErrHomebrewInstall with the developer tools
// Homebrew checked before it built the formula, which say what to update.
type HomebrewInstallError struct {
	Err   error
	Tools *DeveloperTools
}

func (e *HomebrewInstallError) Error() string {
	return fmt.Sprintf("%v (%v)", ErrHomebrewInstall, e.Err)
}

// Unwrap lets errors.Is match ErrHomebrewInstall and the installer's error.
func (e *HomebrewInstallError) Unwrap() []error { return []error{ErrHomebrewInstall, e.Err} }
