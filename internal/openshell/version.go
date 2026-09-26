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
	"fmt"
	"strconv"
	"strings"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
)

// Supported OpenShell releases. 0.1.0 broke every 0.0.x peer, and the
// project promises Stable-interface compatibility only within a minor line,
// so the window is one minor release wide and bumped deliberately.
const (
	// SupportedMin is the oldest OpenShell release DefenseClaw drives.
	SupportedMin = "0.1.1"
	// SupportedBelow is the first release outside the window.
	SupportedBelow = "0.2.0"

	// InstallerTag is the upstream release the setup flow installs.
	InstallerTag = "v0.1.1"
	// InstallerURL is the tag-pinned upstream installer. Fetching it from a
	// tag rather than main keeps the bytes stable enough to pin a digest.
	InstallerURL = "https://raw.githubusercontent.com/NVIDIA/OpenShell/" + InstallerTag + "/install.sh"
	// InstallerSHA256 is the digest of InstallerURL. Setup refuses to run a
	// script that does not match it.
	InstallerSHA256 = "5c98a86a4b811c471b212219cb2a62d458244220ffa71ac8e3baf3700b17b871"

	// DefaultBaseImage is the digest-pinned NVIDIA community sandbox image
	// the DefenseClaw overlay is built on (multi-arch; ships node, uv, git
	// and gh, among others).
	DefaultBaseImage = "ghcr.io/nvidia/openshell-community/sandboxes/base@sha256:aeef1c63f00e2913ea002ccb3aaf925f338b5c5d70e63576f0d95c16a138044e"

	// DefaultWorkspace is the OpenShell workspace (tenant) sandboxes are
	// created in when the operator does not choose one. Since 0.1.0 the
	// gateway no longer selects it implicitly.
	DefaultWorkspace = "default"
	// DefaultGatewayName is the registration the package-managed local
	// gateway installs.
	DefaultGatewayName = "openshell"
)

// SandboxPolicy is the typed OpenShell sandbox policy the renderer produces
// and the client submits.
type SandboxPolicy = v1.SandboxPolicy

// Version is a parsed OpenShell release number. Pre-release and build
// suffixes are kept for display but do not take part in comparisons, so a
// 0.1.2-pre.3 build is treated as 0.1.2.
type Version struct {
	Major, Minor, Patch int
	Raw                 string
}

// ParseVersion accepts "0.1.1", "v0.1.1", "openshell 0.1.1" and
// "0.1.1-1" (the Debian revision the package reports).
func ParseVersion(s string) (Version, error) {
	raw := strings.TrimSpace(s)
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return Version{}, fmt.Errorf("openshell: empty version")
	}
	token := strings.TrimPrefix(fields[len(fields)-1], "v")
	if i := strings.IndexAny(token, "-+"); i >= 0 {
		token = token[:i]
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Version{}, fmt.Errorf("openshell: unrecognized version %q", raw)
	}
	var nums [3]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return Version{}, fmt.Errorf("openshell: unrecognized version %q", raw)
		}
		nums[i] = n
	}
	return Version{Major: nums[0], Minor: nums[1], Patch: nums[2], Raw: raw}, nil
}

// Compare returns -1, 0 or 1.
func (v Version) Compare(o Version) int {
	for _, d := range [3]int{v.Major - o.Major, v.Minor - o.Minor, v.Patch - o.Patch} {
		if d < 0 {
			return -1
		}
		if d > 0 {
			return 1
		}
	}
	return 0
}

func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// ErrUnsupportedVersion reports an OpenShell release outside the window.
type ErrUnsupportedVersion struct {
	Found Version
}

func (e *ErrUnsupportedVersion) Error() string {
	if e.Found.Compare(mustParse(SupportedMin)) < 0 && e.Found.Major == 0 && e.Found.Minor == 0 {
		return fmt.Sprintf("OpenShell %s is a 0.0.x release; 0.1 cannot upgrade it in place — remove it and install %s", e.Found, SupportedMin)
	}
	return fmt.Sprintf("OpenShell %s is not supported; DefenseClaw drives >=%s <%s", e.Found, SupportedMin, SupportedBelow)
}

// CheckSupported returns an *ErrUnsupportedVersion when v is outside the
// supported window.
func CheckSupported(v Version) error {
	if v.Compare(mustParse(SupportedMin)) < 0 || v.Compare(mustParse(SupportedBelow)) >= 0 {
		return &ErrUnsupportedVersion{Found: v}
	}
	return nil
}

func mustParse(s string) Version {
	v, err := ParseVersion(s)
	if err != nil {
		panic(err)
	}
	return v
}
