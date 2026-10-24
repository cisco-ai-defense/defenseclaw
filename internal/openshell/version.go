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
	// ensure moves a managed account off one (ManagedSetupPin). Before
	// 0.1.5 the supervisor's network broker fell through to the native
	// connect, bind, listen or send when it could not inspect a socket
	// descriptor, so a sandbox's traffic could bypass its policy
	// (NVIDIA/OpenShell#4494). Its prereleases come before it
	// (Version.Compare): the fix landed in 0.1.5-pre.4, so 0.1.5-pre.1 to
	// pre.3 still have the hole. A sandbox keeps the supervisor of the
	// release its session started on, so one that started earlier must stop
	// and start again (record.SessionRelease). Every release from it also
	// stops a sandbox in OpenShell's error state, so that it can be started
	// again (NVIDIA/OpenShell#4231). Review it with InstallerVersion, never
	// above it.
	SupportedMin = "0.1.5"
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
	InstallerVersion = "0.1.5"
	// InstallerTag is InstallerVersion's upstream release tag.
	InstallerTag = "v" + InstallerVersion
	// InstallerURL is the tag-pinned upstream installer. Fetching it from a
	// tag rather than main keeps the bytes stable enough to pin a digest.
	InstallerURL = "https://raw.githubusercontent.com/NVIDIA/OpenShell/" + InstallerTag + "/install.sh"
	// InstallerSHA256 is the digest of InstallerURL. Setup refuses to run a
	// script that does not match it.
	InstallerSHA256 = "7bf6706741b8b59c1b61e0c47030f0a34fefba6cee3c74cd52638cbf7cdc3655"

	// installerUpgradeReason says why a host on an older supported release
	// is offered InstallerVersion (the doctor's CLI check). Review it with
	// InstallerVersion.
	installerUpgradeReason = "closes a hole in the network broker that let a sandbox's connections bypass its policy (0.1.5), " +
		"fixes a supervisor bug that can stall a sandbox's first connection (0.1.2), cuts the CPU an idle sandbox uses (0.1.2), " +
		"ships the MicroVM driver already signed for Apple's Hypervisor (0.1.3), flushes a MicroVM's disk before it stops (0.1.5) " +
		"and lets a sandbox in OpenShell's error state be stopped and started again (0.1.5)"

	// DefaultBaseImage is the digest-pinned NVIDIA community sandbox image
	// the DefenseClaw overlay is built on (multi-arch; ships node, uv, git
	// and gh, among others).
	DefaultBaseImage = "ghcr.io/nvidia/openshell-community/sandboxes/base@sha256:aeef1c63f00e2913ea002ccb3aaf925f338b5c5d70e63576f0d95c16a138044e"
	// NSSMyhostnameVersion is the libnss-myhostname release in
	// NSSMyhostnameDebs.
	NSSMyhostnameVersion = "255.4-1ubuntu8.17"

	// DefaultWorkspace is the OpenShell workspace (tenant) sandboxes are
	// created in when the operator does not choose one. Since 0.1.0 the
	// gateway no longer selects it implicitly.
	DefaultWorkspace = "default"
	// DefaultGatewayName is the registration the package-managed local
	// gateway installs.
	DefaultGatewayName = "openshell"
)

// PinnedDeb is one architecture's file of a pinned Debian package.
type PinnedDeb struct {
	// URLs serve the same file and are tried in order.
	URLs []string
	// SHA256 is the file's digest, as the Packages index of its release
	// publishes it; a build refuses any other file.
	SHA256 string
}

// NSSMyhostnameDebs are the libnss-myhostname NSSMyhostnameVersion packages
// of Ubuntu 24.04 (universe; the noble-security and noble-updates release
// when pinned), the release of DefaultBaseImage, by `dpkg
// --print-architecture`. The images built for OpenShell's MicroVM driver
// install the one of their architecture so that localhost resolves in a
// MicroVM (image.BuildSpec.MicroVM); the images for the docker driver do
// not. Each is fetched from Ubuntu's snapshot archive, which keeps every
// file it published, else from Launchpad's librarian, which keeps Ubuntu's
// builds: the archive's own pool drops a version once a newer one
// supersedes it. The package depends only on libc6 (>= 2.38) and libcap2
// (>= 1:2.10), which DefaultBaseImage carries on both architectures
// (2.39-0ubuntu8.7 and 1:2.66-5ubuntu2.4), so it installs with `dpkg -i`
// and no package index. Review it with DefaultBaseImage.
var NSSMyhostnameDebs = map[string]PinnedDeb{
	"amd64": {
		URLs: []string{
			"https://snapshot.ubuntu.com/ubuntu/20260929T000000Z/pool/universe/s/systemd/libnss-myhostname_255.4-1ubuntu8.17_amd64.deb",
			"https://launchpadlibrarian.net/871327436/libnss-myhostname_255.4-1ubuntu8.17_amd64.deb",
		},
		SHA256: "5014f50bd8a717629a626e799d2c453316e3985893625ec41d12ac1a82bfcd54",
	},
	"arm64": {
		URLs: []string{
			"https://snapshot.ubuntu.com/ubuntu/20260929T000000Z/pool/universe/s/systemd/libnss-myhostname_255.4-1ubuntu8.17_arm64.deb",
			"https://launchpadlibrarian.net/871327181/libnss-myhostname_255.4-1ubuntu8.17_arm64.deb",
		},
		SHA256: "5f39fb3175f068aad4ab0b39479fb0ad1265343982fdc19983f8dfa659e74465",
	},
}

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
// setup mode raises an older pin to InstallerVersion (ManagedSetupPin), so a
// release older than SupportedMin is never listed.
var TarballPins = map[string]map[string]string{
	"0.1.5": {
		"openshell-x86_64-unknown-linux-musl.tar.gz":           "ca1ad6e6fbb4a6cd407e95763391b8ecff02912e7d9c467e7ca22696fe80af69",
		"openshell-aarch64-unknown-linux-musl.tar.gz":          "30c949b4ac07a9c8245c1248eb82e4eb241615134fcabf3c9bf30dec7d00addf",
		"openshell-aarch64-apple-darwin.tar.gz":                "48d6f4b4a222dc0a120ee4d6a677cb931bcc57f9ac54aefb101588f99c9c7642",
		"openshell-gateway-x86_64-unknown-linux-gnu.tar.gz":    "6ed6a6aff420c65250082cc1db48dc6271a6f5eec0e0068133566ffae4aa788b",
		"openshell-gateway-aarch64-unknown-linux-gnu.tar.gz":   "125f9f43b8d06da8280c78089904a6da2faa7c4cb03f82db3b31fc980cf6c62d",
		"openshell-gateway-aarch64-apple-darwin.tar.gz":        "8e6fd1b05999709a9042ec83fcd902e062507af3e817f28bcda181fb93b42e7a",
		"openshell-driver-vm-x86_64-unknown-linux-gnu.tar.gz":  "6465e39666276215a9fa05d27991e67c9c88267284b59aca95cb7dbb9d69cd41",
		"openshell-driver-vm-aarch64-unknown-linux-gnu.tar.gz": "fc49a0bebfda3075a996123c0fd252200e2987856da63fbd8e7f021f327e1e68",
		"openshell-driver-vm-aarch64-apple-darwin.tar.gz":      "125692d5e9b0183ceeadbc78b71de6007a3318dcc7ec9823e784b072ece2c4ac",
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
// is not 0.1.5 (SupportedMin). A package revision (the "-1" of 0.1.1-1) and
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

// ErrSandboxRelease reports a supported OpenShell release older than
// SupportedMin, which DefenseClaw creates and starts no sandbox on.
type ErrSandboxRelease struct {
	Found Version
}

func (e *ErrSandboxRelease) Error() string {
	if e.Found.Pre != "" && e.Found.Release().Compare(mustParse(SupportedMin)) >= 0 {
		// A prerelease of SupportedMin or a later release: the broker fix
		// may not be in it.
		return fmt.Sprintf("OpenShell %s is a prerelease, which runs no DefenseClaw sandbox: a prerelease of %s may lack its fix for the network broker "+
			"that let a sandbox's connections bypass the sandbox policy when it could not inspect them (NVIDIA/OpenShell#4494); upgrade OpenShell to %s in place",
			e.Found, SupportedMin, InstallerVersion)
	}
	return fmt.Sprintf("OpenShell %s runs no DefenseClaw sandbox: before %s its network broker let a sandbox's connections bypass the sandbox policy "+
		"when it could not inspect them (NVIDIA/OpenShell#4494); upgrade OpenShell to %s in place", e.Found, SupportedMin, InstallerVersion)
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

// ManagedSetupPin is the release the managed "setup" install mode installs
// for the exact pin enterprise.openshell.version: the pin, or
// InstallerVersion for one older than SupportedMin (raised reports it). That
// is the in-place migration of the hosts DefenseClaw 1.0.3 set up on
// "0.1.3", whose sandboxes would otherwise never start again: ensure and
// each user's daemon move them to InstallerVersion. Any other pin (a
// range, a newer or unreadable release, prerequisite mode) is kept, and
// judged as it is. Remove it with the 1.0.3 upgrade path.
func ManagedSetupPin(setup bool, pin string) (release string, raised bool) {
	v, err := ParseVersion(pin)
	if !setup || err != nil || strings.TrimSpace(pin) != v.String() || CheckSandboxRelease(v) == nil {
		return pin, false
	}
	return InstallerVersion, true
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
