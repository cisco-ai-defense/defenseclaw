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
	// SupportedMin is the oldest OpenShell release DefenseClaw supports. It
	// creates and starts sandboxes only on it and later, and its install
	// step upgrades an older OpenShell in place (Installer.Install), as
	// ensure moves a managed account off one (ManagedVersionPin). OpenShell
	// 0.1.6 initializes a missing or empty MicroVM hosts file. It preserves
	// nonempty image-authored files, so retain the current MicroVM image
	// verdict and admission gate. Its prereleases come before it
	// (Version.Compare). Review it with InstallerVersion, never above it.
	SupportedMin = "0.1.6"
	// LegacyMin is the oldest release DefenseClaw still connects to, only to
	// move its host to SupportedMin (CheckConnects, Legacy): on a gateway
	// from it to below SupportedMin, its prereleases included, it runs no
	// sandbox work but still lists, stops, deletes and pulls from the
	// sandboxes there, and upgrades OpenShell in place once OpenShell
	// reports each of them stopped, so a host DefenseClaw 1.0.0 to 1.0.3
	// left on 0.1.1 to 0.1.4 keeps its sandboxes and their work through the
	// upgrade. Remove it, and CheckConnects with it, once DefenseClaw 1.0.3
	// is out of support.
	LegacyMin = "0.1.1"
	// SupportedBelow is the first release outside the window.
	SupportedBelow = "0.2.0"

	// InstallerVersion is the release the setup flow installs, and the one
	// it offers an older supported release an in-place upgrade to
	// (Installer.Upgrade, DoctorReport.OpenShellUpgradeAvailable).
	InstallerVersion = "0.1.6"
	// InstallerTag is InstallerVersion's upstream release tag.
	InstallerTag = "v" + InstallerVersion
	// InstallerURL is the tag-pinned upstream installer. Fetching it from a
	// tag rather than main keeps the bytes stable enough to pin a digest.
	InstallerURL = "https://raw.githubusercontent.com/NVIDIA/OpenShell/" + InstallerTag + "/install.sh"
	// InstallerSHA256 is the digest of InstallerURL. Setup refuses to run a
	// script that does not match it.
	InstallerSHA256 = "04c1a437d4a4fc11930d75a336fc4f52bf0c95251e8469c306e407e203769ae7"

	// installerUpgradeReason says why a host on an older supported release
	// is offered InstallerVersion (the doctor's CLI check). Review it with
	// InstallerVersion.
	installerUpgradeReason = "initializes a missing or empty MicroVM hosts file; " +
		"the release also includes the 0.1.5 network and lifecycle fixes"

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

// TarballBaseURL is where NVIDIA publishes the release tarballs and their
// checksum files: TarballBaseURL + "v<version>/<asset>".
const TarballBaseURL = "https://github.com/NVIDIA/OpenShell/releases/download/"

// TarballPins are the SHA-256 digests of NVIDIA's release tarballs, by
// release, that the managed-enterprise "setup" install mode installs
// (TarballInstaller). A tarball is installed only when its digest is
// listed in NVIDIA's own checksum file for the release and equals the
// digest pinned here, so the digests of a release are compiled in only
// after they were checked against the published ones. The macOS
// openshell-driver-vm of every pinned release ships signed with Apple's
// com.apple.security.hypervisor entitlement (since 0.1.3), so it is
// installed as shipped. Add a release with
// InstallerVersion; a release without an entry cannot be installed. The
// managed hosts DefenseClaw 1.0.3 set up with enterprise.openshell.version
// "0.1.3" need no entry for it:
// setup mode raises an older pin to InstallerVersion (ManagedVersionPin), so a
// release older than SupportedMin is never listed.
var TarballPins = map[string]map[string]string{
	"0.1.6": {
		"openshell-x86_64-unknown-linux-musl.tar.gz":           "2951c67366f3e3584ed9cec8d49b9f0b0eefc8cacea8b0582ac164590492f136",
		"openshell-aarch64-unknown-linux-musl.tar.gz":          "259452a6065c4f76e71884b84e8696cc0fec2f8a832891d333f268ca7bb55a21",
		"openshell-aarch64-apple-darwin.tar.gz":                "334e9cf24994a5bfd34691e9835920da15f5ef224cc96be0d4751eadfa279897",
		"openshell-gateway-x86_64-unknown-linux-gnu.tar.gz":    "811265a55993beb333905a5b560764a40aa9177250171f711dce8ba820f7eff8",
		"openshell-gateway-aarch64-unknown-linux-gnu.tar.gz":   "de7342457746829138cecbc21cc90a2d5d4c0ea22a362b976831ac3bbb0109d6",
		"openshell-gateway-aarch64-apple-darwin.tar.gz":        "8313480f7d00264fc6c8eaad6e522736b20be97bed6a8f309c08fcb10e3c617b",
		"openshell-driver-vm-x86_64-unknown-linux-gnu.tar.gz":  "855fdf50b9f1200a6fafd1474b725adff3e7bfe9f787252cdec01c16e90d717c",
		"openshell-driver-vm-aarch64-unknown-linux-gnu.tar.gz": "f12c877d290638f67c3e54b1faed94a50b27f6404200b44c195e6dded6b9a994",
		"openshell-driver-vm-aarch64-apple-darwin.tar.gz":      "4193697d892f1050e282b079259c1581256039a3c276ac798cf4b73b71247e2c",
	},
}

// SandboxPolicy is the typed OpenShell sandbox policy the renderer produces
// and the client submits.
type SandboxPolicy = v1.SandboxPolicy

// Version is a parsed OpenShell release number. Pre is its prerelease, ""
// for a release: the "pre.3" of the tag v0.1.5-pre.3, of the Debian or rpm
// package version 0.1.5~pre.3-1 and of `openshell --version`, or the
// "dev.108" of a dev build (0.1.6-dev.108+g152d05940). A prerelease comes
// before its release, as in semantic versioning (Compare): NVIDIA cuts the
// prereleases of a release before all of its fixes are in, so 0.1.5-pre.3
// is not the supported 0.1.6 release. A package revision (the "-1" of 0.1.1-1) and
// build metadata (the "+g152d05940") take no part in it.
type Version struct {
	Major, Minor, Patch int
	Pre                 string
	Raw                 string
}

// ParseVersion accepts "0.1.1", "v0.1.1", "openshell 0.1.1", "0.1.1-1"
// (the Debian revision the package reports), and the prereleases
// "0.1.5-pre.3", "0.1.5~pre.3" (rpm) and "0.1.5~pre.3-1" (Debian).
func ParseVersion(s string) (Version, error) {
	raw := strings.TrimSpace(s)
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return Version{}, fmt.Errorf("openshell: empty version")
	}
	token := strings.TrimPrefix(fields[len(fields)-1], "v")
	token, _, _ = strings.Cut(token, "+")
	pre := ""
	if i := strings.IndexAny(token, "-~"); i >= 0 {
		rest := token[i+1:]
		switch {
		case token[i] == '~':
			// Debian and rpm spell a prerelease with a tilde, which sorts
			// it before the release; a Debian revision may follow.
			if j := strings.LastIndex(rest, "-"); j >= 0 {
				rest = rest[:j]
			}
			if !validPrerelease(rest) {
				return Version{}, fmt.Errorf("openshell: unrecognized version %q", raw)
			}
			pre = rest
		case rest != "" && (rest[0] < '0' || rest[0] > '9'):
			// "pre.3", "dev.108": a revision is a number ("0.1.1-1").
			if !validPrerelease(rest) {
				return Version{}, fmt.Errorf("openshell: unrecognized version %q", raw)
			}
			pre = rest
		}
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
	return Version{Major: nums[0], Minor: nums[1], Patch: nums[2], Pre: pre, Raw: raw}, nil
}

// validPrerelease reports dot-separated identifiers of letters, digits and
// hyphens, none empty.
func validPrerelease(pre string) bool {
	if pre == "" {
		return false
	}
	for _, id := range strings.Split(pre, ".") {
		if id == "" {
			return false
		}
		for _, r := range id {
			switch {
			case r >= '0' && r <= '9', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '-':
			default:
				return false
			}
		}
	}
	return true
}

// Compare returns -1, 0 or 1, in semantic-versioning precedence: a
// prerelease comes before its release (0.1.5-pre.3 < 0.1.5 < 0.1.6-pre.1),
// so a floor such as SupportedMin is never met by a prerelease of it. The
// ceiling of the supported window compares the release alone
// (Version.Release): 0.2.0-pre.1 is outside it, as 0.2.0 is.
func (v Version) Compare(o Version) int {
	for _, d := range [3]int{v.Major - o.Major, v.Minor - o.Minor, v.Patch - o.Patch} {
		if d < 0 {
			return -1
		}
		if d > 0 {
			return 1
		}
	}
	switch {
	case v.Pre == o.Pre:
		return 0
	case v.Pre == "":
		return 1
	case o.Pre == "":
		return -1
	}
	return comparePrerelease(v.Pre, o.Pre)
}

// comparePrerelease orders two prereleases as semantic versioning does:
// identifier by identifier, numbers by value and below words, and a
// shorter list first when it is a prefix of the other.
func comparePrerelease(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		x, xerr := strconv.Atoi(as[i])
		y, yerr := strconv.Atoi(bs[i])
		switch {
		case xerr == nil && yerr == nil && x != y:
			if x < y {
				return -1
			}
			return 1
		case xerr == nil && yerr != nil:
			return -1
		case xerr != nil && yerr == nil:
			return 1
		case xerr != nil && as[i] != bs[i]:
			return strings.Compare(as[i], bs[i])
		}
	}
	switch {
	case len(as) < len(bs):
		return -1
	case len(as) > len(bs):
		return 1
	}
	return 0
}

// Release is v without its prerelease: the release it is a prerelease of.
func (v Version) Release() Version {
	return Version{Major: v.Major, Minor: v.Minor, Patch: v.Patch}
}

// aboveWindow reports a version at or above SupportedBelow, a prerelease
// of it included.
func aboveWindow(v Version) bool {
	return v.Release().Compare(mustParse(SupportedBelow)) >= 0
}

func (v Version) String() string {
	s := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Pre != "" {
		s += "-" + v.Pre
	}
	return s
}

// breakingReleaseFloor is the upstream installer's BREAKING_RELEASE_VERSION:
// gateway state from earlier releases is incompatible, so the installer
// refuses to upgrade them without OPENSHELL_ACK_BREAKING_UPGRADE=1, while
// 0.0.37 and later upgrade in place.
const breakingReleaseFloor = "0.0.37"

// ErrUnsupportedVersion reports an OpenShell release outside the window.
// Its advice follows the upstream installer, as Installer does: releases
// before 0.0.37 need their runtime cleaned up first, later ones upgrade
// in place.
type ErrUnsupportedVersion struct {
	Found Version
}

func (e *ErrUnsupportedVersion) Error() string {
	switch {
	case e.Found.Compare(mustParse(breakingReleaseFloor)) < 0:
		return fmt.Sprintf("OpenShell %s predates %s, and %s cannot use its gateway state or sandboxes: back up what you need, "+
			"clean up with the old CLI (openshell sandbox delete --all && openshell gateway destroy), then install %s",
			e.Found, breakingReleaseFloor, InstallerVersion, InstallerVersion)
	case e.Found.Compare(mustParse(SupportedMin)) < 0:
		return fmt.Sprintf("OpenShell %s is older than %s, the oldest release DefenseClaw supports; upgrade it in place to %s", e.Found, SupportedMin, InstallerVersion)
	}
	return fmt.Sprintf("OpenShell %s is not supported; DefenseClaw drives >=%s <%s", e.Found, SupportedMin, SupportedBelow)
}

// ErrSandboxRelease reports a release older than SupportedMin, which
// DefenseClaw creates and starts no sandbox on.
type ErrSandboxRelease struct {
	Found Version
}

func (e *ErrSandboxRelease) Error() string {
	if err := CheckConnects(e.Found); err != nil {
		return err.Error()
	}
	return fmt.Sprintf("OpenShell %s runs no DefenseClaw sandbox: OpenShell %s or later is required; upgrade OpenShell to %s in place",
		e.Found, SupportedMin, InstallerVersion)
}

// CheckSandboxRelease returns an *ErrSandboxRelease when a gateway of
// release v must run no sandbox work: one older than SupportedMin, a
// prerelease of SupportedMin included.
func CheckSandboxRelease(v Version) error {
	if v.Compare(mustParse(SupportedMin)) < 0 {
		return &ErrSandboxRelease{Found: v}
	}
	return nil
}

// RunsSandboxes reports whether the gateway release release (as its
// health reports it) is SupportedMin or later; false when it cannot be read.
func RunsSandboxes(release string) bool {
	v, err := ParseVersion(release)
	return err == nil && CheckSandboxRelease(v) == nil
}

// ProvisioningTimedOut reports OpenShell's account of a sandbox whose
// provisioning deadline passed, which it holds in its error phase: the
// condition reason it sets then (ProvisioningTimedOut,
// ImagePreparationTimedOut), or its refusals to stop such a sandbox
// ("sandbox provisioning timed out; retry start after timeout cleanup
// completes") and to start it before that cleanup ends ("provisioning
// timeout cleanup is still pending; ..."). Such a sandbox is started again
// without a stop (NVIDIA/OpenShell#4231).
func ProvisioningTimedOut(said string) bool {
	return strings.Contains(said, "ProvisioningTimedOut") || strings.Contains(said, "ImagePreparationTimedOut") ||
		strings.Contains(said, "provisioning timed out") || strings.Contains(said, "provisioning timeout cleanup")
}

// ManagedVersionPin is the effective managed version requirement. Exact pins
// below SupportedMin move to InstallerVersion; ranges start no lower than the
// floor. An upper bound at or below the floor has no usable release and is
// reported by floorPossible. The lifecycle and daemon use the same result.
func ManagedVersionPin(pin string) (effective string, raised, floorPossible bool) {
	pin = strings.TrimSpace(pin)
	floor := mustParse(SupportedMin)
	if len(strings.Fields(pin)) == 1 {
		if v, err := ParseVersion(pin); err == nil {
			if v.Compare(floor) < 0 {
				return InstallerVersion, true, true
			}
			return pin, false, true
		}
	}
	fields := strings.Fields(pin)
	if len(fields) == 0 || len(fields) > 2 || !strings.HasPrefix(fields[0], ">=") {
		return pin, false, true
	}
	low, err := ParseVersion(strings.TrimPrefix(fields[0], ">="))
	if err != nil {
		return pin, false, true
	}
	if len(fields) == 2 {
		if !strings.HasPrefix(fields[1], "<") {
			return pin, false, true
		}
		high, err := ParseVersion(strings.TrimPrefix(fields[1], "<"))
		if err != nil {
			return pin, false, true
		}
		if high.Compare(floor) <= 0 {
			return pin, false, false
		}
	}
	if low.Compare(floor) < 0 {
		upper := ""
		if len(fields) == 2 {
			upper = " " + fields[1]
		}
		return ">=" + SupportedMin + upper, true, true
	}
	return pin, false, true
}

// CheckSupported returns an *ErrUnsupportedVersion when v is outside the
// supported window, SupportedMin to SupportedBelow: an older release is one
// the install step upgrades in place.
func CheckSupported(v Version) error {
	if v.Compare(mustParse(SupportedMin)) < 0 || aboveWindow(v) {
		return &ErrUnsupportedVersion{Found: v}
	}
	return nil
}

// CheckConnects returns an *ErrUnsupportedVersion when DefenseClaw does not
// talk to a gateway of release v at all: outside LegacyMin to
// SupportedBelow. A legacy release (Legacy) passes, for the move off it
// only. Remove it with LegacyMin.
func CheckConnects(v Version) error {
	if v.Compare(mustParse(LegacyMin)) < 0 || aboveWindow(v) {
		return &ErrUnsupportedVersion{Found: v}
	}
	return nil
}

// Legacy reports a release DefenseClaw connects to only to move its host to
// SupportedMin (LegacyMin): older than SupportedMin, a prerelease of it
// included, and not older than LegacyMin.
func Legacy(v Version) bool {
	return CheckConnects(v) == nil && CheckSupported(v) != nil
}

func mustParse(s string) Version {
	v, err := ParseVersion(s)
	if err != nil {
		panic(err)
	}
	return v
}
