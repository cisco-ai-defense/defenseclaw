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
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// The administrator's OpenShell on a managed host (enterprise.openshell.install:
// prerequisite). The administrator installs NVIDIA's packages machine-wide
// (the rpm or deb on Linux; on macOS the binaries copied to /usr/local/bin,
// since a Homebrew prefix belongs to the person who ran brew), and an
// account's managed gateway unit runs that copy with the rendered
// configuration. The account never supplies the binary in this mode.

// AdminBinaryDirs are the folders the administrator's OpenShell binaries
// are looked up in, in order.
func AdminBinaryDirs(goos string) []string {
	if goos == "darwin" {
		return []string{"/usr/local/bin", "/opt/homebrew/bin"}
	}
	return []string{"/usr/bin", "/usr/local/bin"}
}

// ErrNoAdminBinary means the administrator's copy of a binary is not there,
// or is not one a standard account cannot have changed.
var ErrNoAdminBinary = errors.New("openshell: the administrator's OpenShell binary is not installed or not trusted")

// AdminBinary returns the administrator's copy of the OpenShell binary name
// (GatewayBinary, DefaultBinary): the first of AdminBinaryDirs that holds an
// executable regular file passing trusted (the managed trust check: owned by
// root, closed to other writers, no links on the way). Every candidate that
// exists but fails the check is named in the error, so the administrator
// sees what to fix.
func AdminBinary(goos, name string, trusted func(path string) error) (string, error) {
	var refused []string
	for _, dir := range AdminBinaryDirs(goos) {
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
			continue
		}
		if trusted != nil {
			if err := trusted(path); err != nil {
				refused = append(refused, fmt.Sprintf("%s (%v)", path, err))
				continue
			}
		}
		return path, nil
	}
	if len(refused) > 0 {
		return "", fmt.Errorf("%w: %s", ErrNoAdminBinary, strings.Join(refused, "; "))
	}
	return "", fmt.Errorf("%w: %s is in none of %s", ErrNoAdminBinary, name, strings.Join(AdminBinaryDirs(goos), ", "))
}

// AdminVMDriverDirs are the folders the administrator's openshell-driver-vm
// (the MicroVM driver) is looked up in, in order: the lifecycle renders the
// first that holds a trusted driver as the account gateways' driver_dir.
func AdminVMDriverDirs(goos string) []string {
	if goos == "darwin" {
		return []string{"/usr/local/libexec/openshell", "/opt/homebrew/libexec/openshell"}
	}
	return []string{"/usr/libexec/openshell", "/usr/lib/openshell", "/usr/local/libexec/openshell"}
}

// AdminVMDriver is the administrator's openshell-driver-vm on goos: the
// first of AdminVMDriverDirs whose driver exists and passes trusted (the
// managed trust check); refused names, as "path (why)", every candidate
// before it that exists but fails the check. exists and trusted get the
// canonical path (a caller on a rooted test filesystem maps it). exists
// must require a regular executable file. It is the
// one check of the driver: the enterprise verify (as root) and a managed
// user's `sandbox doctor` both run it, so the doctor cannot say ready where
// verify says the driver is missing (GAP-0481).
func AdminVMDriver(goos string, exists func(path string) bool, trusted func(path string) error) (found string, refused []string) {
	for _, dir := range AdminVMDriverDirs(goos) {
		// goos is linux or darwin, so the canonical path is a slash path
		// whatever OS runs this (filepath.Join gave backslashes on Windows).
		driver := path.Join(dir, vmDriverBinary)
		if !exists(driver) {
			continue
		}
		if err := trusted(driver); err != nil {
			refused = append(refused, fmt.Sprintf("%s (%v)", driver, err))
			continue
		}
		return driver, refused
	}
	return "", refused
}

// ExecutableVMDriver reports whether the gateway can execute a regular
// openshell-driver-vm file. Callers use it as AdminVMDriver's exists check.
func ExecutableVMDriver(path string) bool { return executable(path) }

// RenderedAdminVMDriver checks the exact driver_dir passed to the managed
// gateway. The lifecycle chooses that directory from AdminVMDriverDirs, but
// an older render can outlive a moved driver. An alternate trusted driver
// elsewhere does not help: OpenShell searches only an explicit driver_dir
// and the gateway binary's sibling when driver_dir is set.
func RenderedAdminVMDriver(goos, driverDir string, executable func(path string) bool, trusted func(path string) error) (string, string) {
	allowed := false
	for _, dir := range AdminVMDriverDirs(goos) {
		if dir == driverDir {
			allowed = true
			break
		}
	}
	if !allowed {
		return "", fmt.Sprintf("the rendered MicroVM driver_dir %q is not one of the administrator's driver directories (%s)", driverDir, strings.Join(AdminVMDriverDirs(goos), ", "))
	}
	driver := path.Join(driverDir, vmDriverBinary)
	if !executable(driver) {
		return "", fmt.Sprintf("the rendered MicroVM driver_dir %q has no executable %s", driverDir, vmDriverBinary)
	}
	if err := trusted(driver); err != nil {
		return "", fmt.Sprintf("the rendered MicroVM driver %s is not trusted: %v", driver, err)
	}
	return driver, ""
}

// adminVMDriverArchive is OpenShell's release archive of the MicroVM driver
// for a managed host ("" when it publishes none).
func adminVMDriverArchive(goos, goarch string) string {
	switch goos + "/" + goarch {
	case "linux/amd64", "linux/arm64":
		return vmDriverArchive(goarch)
	case "darwin/arm64":
		return vmDriverBinary + "-aarch64-apple-darwin.tar.gz"
	}
	return ""
}

// AdminVMDriverFix is the administrator's step (worded for the
// administrator: the managed doctor says to ask for it) on a managed host
// without a
// trusted openshell-driver-vm: install the driver of OpenShell InstallerTag
// root-owned into the first of AdminVMDriverDirs, after checking its release
// archive against the SHA-256 this build pins for it (TarballPins), never
// against a checksum file fetched from the same release (#1224). The
// openshell package ships no MicroVM driver.
func AdminVMDriverFix(goos, goarch string) *Fix {
	return adminVMDriverFixIn(goos, goarch, AdminVMDriverDirs(goos)[0])
}

// adminVMDriverFixIn installs into the directory the gateway actually uses.
// A stale driver in a later administrator directory must be replaced there.
func adminVMDriverFixIn(goos, goarch, dir string) *Fix {
	archive := adminVMDriverArchive(goos, goarch)
	if archive == "" {
		return &Fix{Summary: "OpenShell publishes its MicroVM driver for Linux on amd64 and arm64 and for Apple-silicon Macs only"}
	}
	digest := TarballPins[InstallerVersion][archive]
	if digest == "" {
		return &Fix{Summary: "install " + vmDriverBinary + " of OpenShell " + InstallerTag + " root-owned into " + dir +
			" (this DefenseClaw build pins no digest for " + archive + ")", Sudo: true}
	}
	check, group := "sha256sum -c -", "root"
	if goos == "darwin" {
		check, group = "shasum -a 256 -c -", "wheel"
	}
	commandDir := shellQuote(dir)
	commandTarget := shellQuote(filepath.Join(dir, vmDriverBinary))
	return &Fix{
		Summary: "install " + vmDriverBinary + " of OpenShell " + InstallerTag + " root-owned into " + dir +
			", after checking the archive against the SHA-256 this DefenseClaw build pins for it (the openshell package ships no MicroVM driver)",
		Command: "d=$(mktemp -d) && (trap 'rm -rf \"$d\"' EXIT; cd \"$d\" && curl -fsSLO " + TarballBaseURL + InstallerTag + "/" + archive +
			" && echo '" + digest + "  " + archive + "' | " + check + " && tar -xzf " + archive + " " + vmDriverBinary +
			" && sudo install -d -m 0755 -o root -g " + group + " " + commandDir +
			" && sudo install -m 0755 -o root -g " + group + " " + vmDriverBinary + " " + commandTarget + ")",
		Sudo: true,
	}
}
