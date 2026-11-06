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
	"strings"
	"testing"
)

func TestParseVersionAcceptsReportedShapes(t *testing.T) {
	for in, want := range map[string]string{
		"0.1.1":                 "0.1.1",
		"v0.1.1":                "0.1.1",
		"openshell 0.1.1":       "0.1.1",
		"0.1.1-1":               "0.1.1",
		"openshell 0.1.2-pre.3": "0.1.2-pre.3",
		// The prerelease as rpm (%{VERSION}) and Debian spell it, a dev
		// build, and its docker tag.
		"0.1.5~pre.3":                 "0.1.5-pre.3",
		"0.1.5~pre.3-1":               "0.1.5-pre.3",
		"0.1.6-dev.108+g152d05940":    "0.1.6-dev.108",
		"0.0.38~dev.108+g152d05940-1": "0.0.38-dev.108",
		"0.0.38-dev.108-g152d05940":   "0.0.38-dev.108-g152d05940",
		"openshell 0.1.5+g152d05940":  "0.1.5",
		"0.1.5-1ubuntu1":              "0.1.5",
	} {
		if v, err := ParseVersion(in); err != nil || v.String() != want {
			t.Fatalf("ParseVersion(%q) = %s, %v; want %s", in, v, err, want)
		}
	}
	for _, bad := range []string{"", "openshell", "0.1", "a.b.c", "0.1.-1", "0.1.5~", "0.1.5-pre..1", "0.1.5-pre_1"} {
		if _, err := ParseVersion(bad); err == nil {
			t.Fatalf("ParseVersion(%q) succeeded", bad)
		}
	}
	// `openshell --version` output.
	for in, want := range map[string]string{"openshell 0.1.2 (4ce767fc)": "0.1.2", "openshell v0.0.16": "0.0.16", "openshell dev": "",
		"openshell 0.1.5-pre.3 (01087a45)": "0.1.5-pre.3"} {
		if v, err := VersionFromOutput(in); (want == "") != (err != nil) || (err == nil && v.String() != want) {
			t.Errorf("VersionFromOutput(%q) = %v, %v; want %q", in, v, err, want)
		}
	}
}

// TestSandboxRelease: DefenseClaw runs sandboxes only from SupportedMin and
// keeps older releases connected for an in-place upgrade.
func TestSandboxRelease(t *testing.T) {
	if SupportedMin != "0.1.6" || mustParse(SupportedMin).Compare(mustParse(InstallerVersion)) > 0 || CheckSupported(mustParse(SupportedMin)) != nil {
		t.Fatalf("SupportedMin %s, InstallerVersion %s", SupportedMin, InstallerVersion)
	}
	for _, v := range []string{"0.1.1", "0.1.3", "0.1.4", "0.1.5"} {
		var e *ErrSandboxRelease
		if err := CheckSandboxRelease(mustParse(v)); !errors.As(err, &e) || CheckConnects(mustParse(v)) != nil || !Legacy(mustParse(v)) || RunsSandboxes(v) ||
			err.Error() != "OpenShell "+v+" runs no DefenseClaw sandbox: OpenShell 0.1.6 or later is required; upgrade OpenShell to "+InstallerVersion+" in place" {
			t.Errorf("%s: %v", v, err)
		}
	}
	for _, v := range []string{"0.1.6", "0.1.7", "openshell 0.1.6"} {
		if !RunsSandboxes(v) {
			t.Errorf("%s runs no sandbox", v)
		}
	}
	if RunsSandboxes("") || RunsSandboxes("dev") {
		t.Error("an unreadable release runs sandboxes")
	}
	for release := range TarballPins {
		if CheckSandboxRelease(mustParse(release)) != nil {
			t.Errorf("TarballPins lists %s, which runs no sandbox", release)
		}
	}
}

// TestAPrereleaseComesBeforeItsRelease: no prerelease of 0.1.6 runs a
// sandbox, whichever way the release was read. A prerelease of a later
// release can run one. The ceiling keeps its own prereleases out.
func TestAPrereleaseComesBeforeItsRelease(t *testing.T) {
	for _, tc := range []struct{ a, b string }{
		{"0.1.5-pre.3", "0.1.5"},
		{"0.1.5-pre.3", "0.1.5-pre.4"},
		{"0.1.5-pre.9", "0.1.5-pre.10"},
		{"0.1.5-dev.3", "0.1.5-pre.1"},
		{"0.1.5-pre", "0.1.5-pre.1"},
		{"0.1.4", "0.1.5-pre.1"},
		{"0.1.5", "0.1.6-pre.1"},
	} {
		a, b := mustParse(tc.a), mustParse(tc.b)
		if a.Compare(b) != -1 || b.Compare(a) != 1 || a.Compare(a) != 0 {
			t.Errorf("%s vs %s: %d, %d", tc.a, tc.b, a.Compare(b), b.Compare(a))
		}
	}
	if mustParse("0.1.5-1").Compare(mustParse("0.1.5")) != 0 {
		t.Error("a package revision is not the release")
	}
	for _, v := range []string{"0.1.5-pre.1", "0.1.5-pre.3", "0.1.5-pre.7", "openshell 0.1.5-pre.2", "0.1.5~pre.3", "0.1.5~pre.3-1", "0.1.5-dev.4+gabc", "0.1.6-pre.1", "0.1.6-dev.1+gabc"} {
		var e *ErrSandboxRelease
		err := CheckSandboxRelease(mustParse(v))
		if !errors.As(err, &e) || RunsSandboxes(v) || CheckConnects(mustParse(v)) != nil || !Legacy(mustParse(v)) ||
			!strings.Contains(err.Error(), "OpenShell 0.1.6 or later is required") {
			t.Errorf("%s: %v", v, err)
		}
	}
	for _, v := range []string{"0.1.6", "0.1.6-1", "0.1.7-pre.1", "0.1.7-dev.1+gabc"} {
		if !RunsSandboxes(v) {
			t.Errorf("%s runs no sandbox", v)
		}
	}
	if err := CheckSupported(mustParse("0.2.0-pre.1")); err == nil {
		t.Error("a prerelease of SupportedBelow is supported")
	}
	if err := CheckSupported(mustParse("0.1.9-pre.1")); err != nil {
		t.Errorf("0.1.9-pre.1: %v", err)
	}
	// The doctor's CLI check offers the upgrade to a prerelease of the
	// release it installs.
	r := &DoctorReport{CLIVersion: "0.1.5-pre.3", Checks: []Check{{ID: CheckIDCLI, Status: StatusWarn}}}
	if r.OpenShellInstallNeeded() || !r.OpenShellUpgradeAvailable() {
		t.Errorf("prerelease CLI: install needed %v, upgrade available %v", r.OpenShellInstallNeeded(), r.OpenShellUpgradeAvailable())
	}
}

// TestManagedVersionPinFloor covers exact pins and ranges in both managed
// install modes. A range ending at the floor has no usable release.
func TestManagedVersionPinFloor(t *testing.T) {
	for _, tc := range []struct {
		pin      string
		want     string
		raised   bool
		possible bool
	}{
		{"0.1.3", InstallerVersion, true, true},
		{"0.1.1", InstallerVersion, true, true},
		{"0.1.5", InstallerVersion, true, true},
		{"0.01.5", InstallerVersion, true, true},
		// A prerelease of SupportedMin runs no sandbox either.
		{"0.1.5-pre.3", InstallerVersion, true, true},
		{"0.1.6-pre.1", InstallerVersion, true, true},
		{"0.1.6", "0.1.6", false, true},
		{"0.1.7", "0.1.7", false, true},
		{"", "", false, true},
		{">=0.1.1 <0.2.0", ">=0.1.6 <0.2.0", true, true},
		{">=0.1.6 <0.2.0", ">=0.1.6 <0.2.0", false, true},
		{">=0.1.1 <0.1.6", ">=0.1.1 <0.1.6", false, false},
	} {
		if got, raised, possible := ManagedVersionPin(tc.pin); got != tc.want || raised != tc.raised || possible != tc.possible {
			t.Errorf("ManagedVersionPin(%q) = %q, %v, %v; want %q, %v, %v", tc.pin, got, raised, possible, tc.want, tc.raised, tc.possible)
		}
	}
}

// TestProvisioningTimedOut recognizes what OpenShell 0.1.5 says of a
// sandbox whose provisioning deadline passed (NVIDIA/OpenShell#4231).
func TestProvisioningTimedOut(t *testing.T) {
	for _, said := range []string{
		"ProvisioningTimedOut: Provisioning repair window expired after 300 seconds",
		"ImagePreparationTimedOut: Image preparation or initial supervisor startup exceeded its absolute deadline",
		"FailedPrecondition: sandbox provisioning timed out; retry start after timeout cleanup completes",
		"FailedPrecondition: provisioning timeout cleanup is still pending; retry start after compute is reclaimed",
	} {
		if !ProvisioningTimedOut(said) {
			t.Errorf("%q", said)
		}
	}
	if ProvisioningTimedOut("Conflict: sandbox must be Stopped, Completed, or a failed main-process Error to start (current phase: Error)") {
		t.Error("an error-phase refusal is no timeout")
	}
}

// TestInstallerPin: setup installs InstallerVersion with the script of its
// tag, whose digest is pinned, from inside the supported window; the advice names it.
func TestInstallerPin(t *testing.T) {
	if InstallerVersion != "0.1.6" || InstallerTag != "v"+InstallerVersion ||
		InstallerURL != "https://raw.githubusercontent.com/NVIDIA/OpenShell/v0.1.6/install.sh" ||
		InstallerSHA256 != "04c1a437d4a4fc11930d75a336fc4f52bf0c95251e8469c306e407e203769ae7" {
		t.Fatalf("installer pin = %s %s %s", InstallerTag, InstallerURL, InstallerSHA256)
	}
	if v := mustParse(InstallerVersion); CheckSupported(v) != nil || v.Compare(mustParse(LegacyMin)) < 0 {
		t.Fatalf("InstallerVersion %s is outside >=%s <%s", InstallerVersion, LegacyMin, SupportedBelow)
	}
	for v, want := range map[string]string{"0.0.40": "upgrade it in place to " + InstallerVersion, "0.0.16": "then install " + InstallerVersion} {
		if err := CheckSupported(mustParse(v)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", v, err, want)
		}
	}
}

// #1224: the MicroVM driver archive of each Linux architecture has its
// digest compiled in for InstallerVersion, and the doctor's install command
// checks it against that digest, without fetching a checksum file.
func TestVMDriverDigestsArePinnedForTheInstallerRelease(t *testing.T) {
	want := map[string]string{
		"amd64": "855fdf50b9f1200a6fafd1474b725adff3e7bfe9f787252cdec01c16e90d717c",
		"arm64": "f12c877d290638f67c3e54b1faed94a50b27f6404200b44c195e6dded6b9a994",
	}
	for goarch, digest := range want {
		archive := vmDriverArchive(goarch)
		if got := TarballPins[InstallerVersion][archive]; archive == "" || got != digest {
			t.Errorf("%s: pinned digest of %q for %s = %q, want %q", goarch, archive, InstallerVersion, got, digest)
		}
		fix := InstallVMDriverFix(goarch)
		if fix == nil || !strings.Contains(fix.Command, "echo '"+digest+"  "+archive+"' | sha256sum -c -") ||
			strings.Contains(fix.Command, "checksums") || !strings.Contains(fix.Command, TarballBaseURL+InstallerTag+"/"+archive) {
			t.Errorf("%s: install command %q does not check the pinned digest", goarch, fix.Command)
		}
	}
}

// TestTheFloorIsSupportedMin: the owner's floor (2026-11-02) is 0.1.6.
// Older releases are outside the supported window (CheckSupported), and the
// ones DefenseClaw 1.0.0 to 1.0.3 left hosts on (0.1.1 to 0.1.4, and the
// 0.1.5 release and 0.1.6 prereleases) are legacy: DefenseClaw still connects to them
// (CheckConnects), only to move the host off them, and runs no sandbox
// there. 0.1.0 and older are not even connected to.
func TestTheFloorIsSupportedMin(t *testing.T) {
	if SupportedMin != "0.1.6" || LegacyMin != "0.1.1" {
		t.Fatalf("SupportedMin %s, LegacyMin %s", SupportedMin, LegacyMin)
	}
	for _, s := range []string{"0.1.1", "0.1.2", "0.1.3", "0.1.4", "0.1.1-1", "0.1.5", "0.1.5-1", "0.1.5-pre.1", "0.1.5-pre.3", "0.1.5-pre.4", "0.1.5~pre.4-1", "0.1.5-dev.9+gabc", "0.1.6-pre.1"} {
		v := mustParse(s)
		if CheckSupported(v) == nil || CheckConnects(v) != nil || !Legacy(v) || CheckSandboxRelease(v) == nil || RunsSandboxes(s) {
			t.Errorf("%s: supported %v, connects %v, legacy %v", s, CheckSupported(v), CheckConnects(v), Legacy(v))
		}
	}
	for _, s := range []string{"0.1.6", "0.1.6-1", "0.1.7-pre.1", "0.1.9"} {
		v := mustParse(s)
		if CheckSupported(v) != nil || CheckConnects(v) != nil || Legacy(v) || !RunsSandboxes(s) {
			t.Errorf("%s: supported %v, connects %v, legacy %v", s, CheckSupported(v), CheckConnects(v), Legacy(v))
		}
	}
	for _, s := range []string{"0.1.0", "0.0.40", "0.2.0", "0.2.0-pre.1"} {
		v := mustParse(s)
		if CheckConnects(v) == nil || Legacy(v) {
			t.Errorf("%s: connects %v, legacy %v", s, CheckConnects(v), Legacy(v))
		}
	}
	// A legacy gateway answers DefenseClaw's health check (for the move
	// off it); 0.1.0 does not.
	if err := (&GatewayHealth{Healthy: true, Version: mustParse("0.1.3"), RawVersion: "0.1.3"}).CheckVersion(); err != nil {
		t.Errorf("0.1.3 gateway: %v", err)
	}
	if err := (&GatewayHealth{Healthy: true, Version: mustParse("0.1.0"), RawVersion: "0.1.0"}).CheckVersion(); err == nil {
		t.Error("0.1.0 gateway connects")
	}
	// A legacy CLI is offered the upgrade, which setup takes by default.
	r := &DoctorReport{CLIVersion: "0.1.3", Checks: []Check{{ID: CheckIDCLI, Status: StatusWarn}}}
	if !r.OpenShellUpgradeAvailable() || !r.OpenShellLegacy() || r.OpenShellInstallNeeded() {
		t.Errorf("0.1.3 CLI: upgrade available %v, legacy %v, install needed %v", r.OpenShellUpgradeAvailable(), r.OpenShellLegacy(), r.OpenShellInstallNeeded())
	}
	r = &DoctorReport{CLIVersion: "0.1.6", Checks: []Check{{ID: CheckIDCLI, Status: StatusPass}}}
	if r.OpenShellUpgradeAvailable() || r.OpenShellLegacy() {
		t.Error("0.1.6 CLI is offered the upgrade")
	}
}

// TestR108OSMINMinimumAndBenignTwin keeps older releases upgrade-only and
// admits stable releases from the new floor.
func TestR108OSMINMinimumAndBenignTwin(t *testing.T) {
	for _, tc := range []struct {
		name, release string
		usable        bool
	}{
		{"older stable", "0.1.5", false},
		{"floor prerelease", "0.1.6-pre.1", false},
		{"floor stable", "0.1.6", true},
		{"later stable", "0.1.7", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, err := ParseVersion(tc.release)
			if err != nil {
				t.Fatal(err)
			}
			if err := CheckConnects(v); err != nil {
				t.Fatalf("%s must remain connected for upgrade: %v", tc.release, err)
			}
			if got := CheckSupported(v) == nil; got != tc.usable {
				t.Fatalf("%s supported = %v, want %v", tc.release, got, tc.usable)
			}
			if got := CheckSandboxRelease(v) == nil; got != tc.usable {
				t.Fatalf("%s sandbox release = %v, want %v", tc.release, got, tc.usable)
			}
			if got := RunsSandboxes(tc.release); got != tc.usable {
				t.Fatalf("%s runs sandboxes = %v, want %v", tc.release, got, tc.usable)
			}
		})
	}
}

func TestCheckSupportedWindow(t *testing.T) {
	// The advice matches what Installer does: clean up before 0.0.37,
	// upgrade in place from 0.0.37 on.
	for v, want := range map[string]string{
		"0.1.1":       "older than 0.1.6, the oldest release DefenseClaw supports; upgrade it in place to " + InstallerVersion,
		"0.1.4":       "older than 0.1.6",
		"0.1.5-pre.4": "older than 0.1.6",
		"0.1.5":       "older than 0.1.6",
		"0.1.6-pre.1": "older than 0.1.6",
		"0.1.6":       "",
		"0.1.9":       "",
		"0.0.16":      "predates 0.0.37",
		"0.0.36":      "openshell sandbox delete --all && openshell gateway destroy",
		"0.0.37":      "upgrade it in place",
		"0.0.40":      "upgrade it in place",
		"0.1.0":       "upgrade it in place",
		"0.2.0":       "not supported",
		"1.0.0":       "not supported",
	} {
		err := CheckSupported(mustParse(v))
		var unsupported *ErrUnsupportedVersion
		if want == "" {
			if err != nil {
				t.Errorf("%s rejected: %v", v, err)
			}
			continue
		}
		if !errors.As(err, &unsupported) || !strings.Contains(err.Error(), want) {
			t.Errorf("%s = %v, want an ErrUnsupportedVersion saying %q", v, err, want)
		}
		if strings.HasPrefix(want, "upgrade") && (strings.Contains(err.Error(), "remove") || strings.Contains(err.Error(), "destroy")) {
			t.Errorf("%s message asks for a cleanup the installer does not need: %q", v, err)
		}
	}
}
