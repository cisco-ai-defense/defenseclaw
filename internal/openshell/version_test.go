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
	"regexp"
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

// TestSandboxRelease: DefenseClaw runs sandboxes only from SupportedMin, the
// release of NVIDIA/OpenShell#4494 (and #4231), and installs no older one;
// the older supported releases stay driven for everything else.
func TestSandboxRelease(t *testing.T) {
	if SupportedMin != "0.1.5" || mustParse(SupportedMin).Compare(mustParse(InstallerVersion)) > 0 || CheckSupported(mustParse(SupportedMin)) != nil {
		t.Fatalf("SupportedMin %s, InstallerVersion %s", SupportedMin, InstallerVersion)
	}
	for _, v := range []string{"0.1.1", "0.1.3", "0.1.4"} {
		var e *ErrSandboxRelease
		if err := CheckSandboxRelease(mustParse(v)); !errors.As(err, &e) || CheckConnects(mustParse(v)) != nil || !Legacy(mustParse(v)) || RunsSandboxes(v) ||
			err.Error() != "OpenShell "+v+" runs no DefenseClaw sandbox: before 0.1.5 its network broker let a sandbox's connections bypass the sandbox policy "+
				"when it could not inspect them (NVIDIA/OpenShell#4494); upgrade OpenShell to "+InstallerVersion+" in place" {
			t.Errorf("%s: %v", v, err)
		}
	}
	for _, v := range []string{"0.1.5", "0.1.6", "openshell 0.1.5"} {
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

// TestAPrereleaseComesBeforeItsRelease: NVIDIA's prereleases of a release
// precede it, and the broker fix SupportedMin stands for landed in
// 0.1.5-pre.4 (NVIDIA/OpenShell#4494), so no prerelease of 0.1.5 runs a
// sandbox, whichever way the release was read (gateway health, `openshell
// --version`, rpm, dpkg). A prerelease of a later release (0.1.6-pre.1,
// cut after 0.1.5) runs them. The ceiling of the window holds its own
// prereleases out, and an older prerelease is offered the upgrade.
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
	for _, v := range []string{"0.1.5-pre.1", "0.1.5-pre.3", "0.1.5-pre.7", "openshell 0.1.5-pre.2", "0.1.5~pre.3", "0.1.5~pre.3-1", "0.1.5-dev.4+gabc"} {
		var e *ErrSandboxRelease
		err := CheckSandboxRelease(mustParse(v))
		if !errors.As(err, &e) || RunsSandboxes(v) || CheckConnects(mustParse(v)) != nil || !Legacy(mustParse(v)) ||
			!strings.Contains(err.Error(), "is a prerelease, which runs no DefenseClaw sandbox") || !strings.Contains(err.Error(), "NVIDIA/OpenShell#4494") {
			t.Errorf("%s: %v", v, err)
		}
	}
	for _, v := range []string{"0.1.5", "0.1.5-1", "0.1.6-pre.1", "0.1.6-dev.1+gabc"} {
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

// TestManagedSetupPinMigratesTheOldPin: the hosts DefenseClaw 1.0.3 set up
// with enterprise.openshell.version "0.1.3" in setup mode move to
// InstallerVersion in place; every other pin is judged as it is.
func TestManagedSetupPinMigratesTheOldPin(t *testing.T) {
	for _, tc := range []struct {
		setup  bool
		pin    string
		want   string
		raised bool
	}{
		{true, "0.1.3", InstallerVersion, true},
		{true, "0.1.1", InstallerVersion, true},
		{true, "0.1.5", "0.1.5", false},
		// A prerelease of SupportedMin runs no sandbox either.
		{true, "0.1.5-pre.3", InstallerVersion, true},
		{true, "0.1.6-pre.1", "0.1.6-pre.1", false},
		{true, "0.1.6", "0.1.6", false},
		{true, "", "", false},
		{true, ">=0.1.1 <0.2.0", ">=0.1.1 <0.2.0", false},
		{false, "0.1.3", "0.1.3", false},
	} {
		if got, raised := ManagedSetupPin(tc.setup, tc.pin); got != tc.want || raised != tc.raised {
			t.Errorf("ManagedSetupPin(%v, %q) = %q, %v; want %q, %v", tc.setup, tc.pin, got, raised, tc.want, tc.raised)
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
	if InstallerVersion != "0.1.5" || InstallerTag != "v"+InstallerVersion ||
		InstallerURL != "https://raw.githubusercontent.com/NVIDIA/OpenShell/v0.1.5/install.sh" ||
		InstallerSHA256 != "7bf6706741b8b59c1b61e0c47030f0a34fefba6cee3c74cd52638cbf7cdc3655" {
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
		"amd64": "6465e39666276215a9fa05d27991e67c9c88267284b59aca95cb7dbb9d69cd41",
		"arm64": "fc49a0bebfda3075a996123c0fd252200e2987856da63fbd8e7f021f327e1e68",
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

// TestTheFloorIsSupportedMin: the owner's floor (2026-10-21) is 0.1.5.
// Older releases are outside the supported window (CheckSupported), and the
// ones DefenseClaw 1.0.0 to 1.0.3 left hosts on (0.1.1 to 0.1.4, and the
// 0.1.5 prereleases) are legacy: DefenseClaw still connects to them
// (CheckConnects), only to move the host off them, and runs no sandbox
// there. 0.1.0 and older are not even connected to.
func TestTheFloorIsSupportedMin(t *testing.T) {
	if SupportedMin != "0.1.5" || LegacyMin != "0.1.1" {
		t.Fatalf("SupportedMin %s, LegacyMin %s", SupportedMin, LegacyMin)
	}
	for _, s := range []string{"0.1.1", "0.1.2", "0.1.3", "0.1.4", "0.1.1-1", "0.1.5-pre.1", "0.1.5-pre.3", "0.1.5-pre.4", "0.1.5~pre.4-1", "0.1.5-dev.9+gabc"} {
		v := mustParse(s)
		if CheckSupported(v) == nil || CheckConnects(v) != nil || !Legacy(v) || CheckSandboxRelease(v) == nil || RunsSandboxes(s) {
			t.Errorf("%s: supported %v, connects %v, legacy %v", s, CheckSupported(v), CheckConnects(v), Legacy(v))
		}
	}
	for _, s := range []string{"0.1.5", "0.1.5-1", "0.1.6-pre.1", "0.1.9"} {
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
	r = &DoctorReport{CLIVersion: "0.1.5", Checks: []Check{{ID: CheckIDCLI, Status: StatusPass}}}
	if r.OpenShellUpgradeAvailable() || r.OpenShellLegacy() {
		t.Error("0.1.5 CLI is offered the upgrade")
	}
}

func TestCheckSupportedWindow(t *testing.T) {
	// The advice matches what Installer does: clean up before 0.0.37,
	// upgrade in place from 0.0.37 on.
	for v, want := range map[string]string{
		"0.1.1":       "older than 0.1.5, the oldest release DefenseClaw supports; upgrade it in place to " + InstallerVersion,
		"0.1.4":       "older than 0.1.5",
		"0.1.5-pre.4": "older than 0.1.5",
		"0.1.5":       "",
		"0.1.6-pre.1": "",
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

// The pinned libnss-myhostname files: one per architecture the base image
// ships, each by the exact version and a sha256, from a place that keeps
// the file after a newer version supersedes it in the archive's pool.
func TestNSSMyhostnamePins(t *testing.T) {
	urlRE := regexp.MustCompile(`^https://(snapshot\.ubuntu\.com/ubuntu/[0-9]{8}T[0-9]{6}Z/pool/universe/s/systemd|launchpadlibrarian\.net/[0-9]+)/libnss-myhostname_([^_/]+)_([a-z0-9]+)\.deb$`)
	shaRE := regexp.MustCompile(`^[0-9a-f]{64}$`)
	if len(NSSMyhostnameDebs) != 2 {
		t.Fatalf("pinned architectures: %v", NSSMyhostnameDebs)
	}
	for _, arch := range []string{"amd64", "arm64"} {
		deb, ok := NSSMyhostnameDebs[arch]
		if !ok || !shaRE.MatchString(deb.SHA256) || len(deb.URLs) < 2 {
			t.Fatalf("%s pin = %+v", arch, deb)
		}
		for _, u := range deb.URLs {
			m := urlRE.FindStringSubmatch(u)
			if m == nil || m[2] != NSSMyhostnameVersion || m[3] != arch {
				t.Errorf("%s: %s is not the %s %s file on the snapshot archive or Launchpad", arch, u, NSSMyhostnameVersion, arch)
			}
		}
	}
	if NSSMyhostnameDebs["amd64"].SHA256 == NSSMyhostnameDebs["arm64"].SHA256 {
		t.Fatal("both architectures pin one file")
	}
}
