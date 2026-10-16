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
		"openshell 0.1.2-pre.3": "0.1.2",
	} {
		if v, err := ParseVersion(in); err != nil || v.String() != want {
			t.Fatalf("ParseVersion(%q) = %s, %v; want %s", in, v, err, want)
		}
	}
	for _, bad := range []string{"", "openshell", "0.1", "a.b.c", "0.1.-1"} {
		if _, err := ParseVersion(bad); err == nil {
			t.Fatalf("ParseVersion(%q) succeeded", bad)
		}
	}
	// `openshell --version` output.
	for in, want := range map[string]string{"openshell 0.1.2 (4ce767fc)": "0.1.2", "openshell v0.0.16": "0.0.16", "openshell dev": ""} {
		if v, err := VersionFromOutput(in); (want == "") != (err != nil) || (err == nil && v.String() != want) {
			t.Errorf("VersionFromOutput(%q) = %v, %v; want %q", in, v, err, want)
		}
	}
}

// TestInstallerPin: setup installs InstallerVersion with the script of its
// tag, whose digest is pinned, from inside the supported window; the advice names it.
func TestInstallerPin(t *testing.T) {
	if InstallerVersion != "0.1.3" || InstallerTag != "v"+InstallerVersion ||
		InstallerURL != "https://raw.githubusercontent.com/NVIDIA/OpenShell/v0.1.3/install.sh" ||
		InstallerSHA256 != "b8daa915e766564f0473b76ed4e012fff9723c1ac98007b3f85ba20f59442d28" {
		t.Fatalf("installer pin = %s %s %s", InstallerTag, InstallerURL, InstallerSHA256)
	}
	if v := mustParse(InstallerVersion); CheckSupported(v) != nil || v.Compare(mustParse(SupportedMin)) < 0 {
		t.Fatalf("InstallerVersion %s is outside >=%s <%s", InstallerVersion, SupportedMin, SupportedBelow)
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
		"amd64": "22593640c6179eb87413ab099832fbd133d3a6a4979904d27679e7da6d80a0cb",
		"arm64": "4426ee0992989060eb5987ad7072feb3eb6aecf5a628ad0284c3d7ad5f39974b",
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

func TestCheckSupportedWindow(t *testing.T) {
	// The advice matches what Installer does: clean up before 0.0.37,
	// upgrade in place from 0.0.37 on.
	for v, want := range map[string]string{
		"0.1.1":  "",
		"0.1.9":  "",
		"0.0.16": "predates 0.0.37",
		"0.0.36": "openshell sandbox delete --all && openshell gateway destroy",
		"0.0.37": "upgrade it in place",
		"0.0.40": "upgrade it in place",
		"0.1.0":  "upgrade it in place",
		"0.2.0":  "not supported",
		"1.0.0":  "not supported",
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
