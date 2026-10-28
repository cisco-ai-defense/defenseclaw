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
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
)

// Compute driver selection for managed sandboxes (owner decision
// 2026-10-10): on Linux, enterprise.openshell.driver vm or auto wants the
// MicroVM driver; where KVM does not work for the user, the sandbox falls back
// to the docker driver (enterprise.openshell.driver_fallback: docker, the
// default) with every profile floor unchanged, or is refused (none). The
// probe runs per user at sandbox start, never at login, and its result and the
// chosen driver go on the sandbox record, the registration, the banner,
// explain, doctor, status, telemetry and audit. A running sandbox never
// switches driver. macOS runs the MicroVM driver only.

// Driver reason codes (defenseclaw.sandbox.driver_reason): why a sandbox
// runs on its driver.
const (
	// DriverReasonConfigured: the organization set this driver.
	DriverReasonConfigured = "configured"
	// DriverReasonKVMAvailable: driver auto, and the KVM probe passed.
	DriverReasonKVMAvailable = "kvm_available"
	// The docker fallback replaced the MicroVM driver because:
	// DriverReasonKVMMissing: there is no /dev/kvm.
	DriverReasonKVMMissing = "kvm_missing"
	// DriverReasonKVMAccess: /dev/kvm is not read-write for the user.
	DriverReasonKVMAccess = "kvm_access"
	// DriverReasonCPUVirtualization: the CPU shows no hardware
	// virtualization (no vmx or svm flag).
	DriverReasonCPUVirtualization = "cpu_virtualization"
	// DriverReasonVMDriverMissing: openshell-driver-vm is not installed
	// where the gateway looks for it.
	DriverReasonVMDriverMissing = "vm_driver_missing"
	// DriverReasonVMPrerequisite: the lifecycle found the MicroVM driver's
	// host prerequisites missing (its binary, e2fsprogs, the gateway
	// unit's umask) while the docker fallback's are met.
	DriverReasonVMPrerequisite = "vm_prerequisite_missing"
)

// DriverReasons are the registered reason codes, in a fixed order.
var DriverReasons = []string{
	DriverReasonConfigured, DriverReasonKVMAvailable, DriverReasonKVMMissing,
	DriverReasonKVMAccess, DriverReasonCPUVirtualization, DriverReasonVMDriverMissing, DriverReasonVMPrerequisite,
}

// ValidDriverReason reports whether code is a registered reason ("" is not).
func ValidDriverReason(code string) bool {
	for _, r := range DriverReasons {
		if r == code {
			return true
		}
	}
	return false
}

// IsFallbackReason reports whether code says the docker fallback replaced
// the MicroVM driver.
func IsFallbackReason(code string) bool {
	switch code {
	case DriverReasonKVMMissing, DriverReasonKVMAccess, DriverReasonCPUVirtualization, DriverReasonVMDriverMissing,
		DriverReasonVMPrerequisite:
		return true
	}
	return false
}

// DriverReasonText is a reason in the words a person reads, "" for an
// unknown code.
func DriverReasonText(code string) string {
	switch code {
	case DriverReasonConfigured:
		return "set by your organization"
	case DriverReasonKVMAvailable:
		return "KVM is available on this computer"
	case DriverReasonKVMMissing:
		return "KVM not available on this computer"
	case DriverReasonKVMAccess:
		// IT needs the cause: the account must be able to open /dev/kvm for
		// reading and writing, whether by its group or by the device's mode
		// (GAP-0499).
		return "KVM not available for your account on this computer: /dev/kvm must be readable and writable for your account"
	case DriverReasonCPUVirtualization:
		return "KVM not available on this computer: its CPU shows no hardware virtualization"
	case DriverReasonVMDriverMissing:
		return "the MicroVM driver is not installed on this computer"
	case DriverReasonVMPrerequisite:
		return "the MicroVM driver's prerequisites are missing on this computer"
	}
	return ""
}

// DriverChoiceText is how the banner, status and doctor name a sandbox's
// driver: "docker (fallback: KVM not available on this computer)", "vm".
func DriverChoiceText(driver, reason string) string {
	driver = strings.TrimSpace(driver)
	if driver == "" {
		return ""
	}
	switch {
	case IsFallbackReason(reason):
		return driver + " (fallback: " + DriverReasonText(reason) + ")"
	case reason == DriverReasonKVMAvailable:
		return driver + " (" + DriverReasonText(reason) + ")"
	}
	return driver
}

// VMProbeResult is what the MicroVM probe found: OK, or the reason code
// (DriverReasonKVMMissing, ...) the MicroVM driver can't run for the user.
type VMProbeResult struct {
	OK     bool
	Reason string
}

// VMProbe checks, for one user on Linux, what the MicroVM driver needs: the
// CPU's virtualization flags, /dev/kvm read-write for the user, and
// openshell-driver-vm where the gateway looks for it.
type VMProbe struct {
	// DevicePath and CPUInfoPath default to /dev/kvm and /proc/cpuinfo.
	DevicePath, CPUInfoPath string
	// GOARCH is the CPU architecture ("" = runtime.GOARCH). The vmx/svm
	// flags are read on amd64 only.
	GOARCH string
	// Access reports whether the device exists and the user may read and
	// write it. nil opens it read-write as the calling process (the user's
	// own sandbox daemon), which is the test the driver itself meets.
	Access func(path string) (exists, ok bool)
	// DriverDirs are where openshell-driver-vm may be. nil skips that check
	// (a caller that can't see the user's home, such as the managed
	// gateway, leaves it to the lifecycle's prerequisite record).
	DriverDirs []string
}

// Run probes. The CPU flags come first (the most precise reason), then the
// device, then the driver binary.
func (p VMProbe) Run() VMProbeResult {
	device := firstNonEmptyString(p.DevicePath, kvmDevice)
	arch := firstNonEmptyString(p.GOARCH, runtime.GOARCH)
	if arch == "amd64" || arch == "386" {
		if data, err := os.ReadFile(firstNonEmptyString(p.CPUInfoPath, "/proc/cpuinfo")); err == nil && !cpuHasVirtualization(data) {
			return VMProbeResult{Reason: DriverReasonCPUVirtualization}
		}
	}
	access := p.Access
	if access == nil {
		access = openDeviceRW
	}
	exists, ok := access(device)
	switch {
	case !exists:
		return VMProbeResult{Reason: DriverReasonKVMMissing}
	case !ok:
		return VMProbeResult{Reason: DriverReasonKVMAccess}
	}
	if p.DriverDirs != nil && FindVMDriverIn(p.DriverDirs) == "" {
		return VMProbeResult{Reason: DriverReasonVMDriverMissing}
	}
	return VMProbeResult{OK: true}
}

// openDeviceRW opens path read-write as the calling process.
func openDeviceRW(path string) (exists, ok bool) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return !errors.Is(err, fs.ErrNotExist), false
	}
	_ = f.Close()
	return true, true
}

// cpuHasVirtualization reports whether /proc/cpuinfo shows Intel VT-x
// (vmx) or AMD-V (svm) on a flags line.
func cpuHasVirtualization(cpuinfo []byte) bool {
	sc := bufio.NewScanner(bytes.NewReader(cpuinfo))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		key, value, ok := strings.Cut(sc.Text(), ":")
		if !ok || strings.TrimSpace(key) != "flags" {
			continue
		}
		for _, flag := range strings.Fields(value) {
			if flag == "vmx" || flag == "svm" {
				return true
			}
		}
	}
	return false
}

// UserVMDriverDirs are where the Linux user probe looks for
// openshell-driver-vm. It checks the rendered driver_dir first when set,
// then the selected gateway executable's sibling. Without driver_dir it
// checks the user's and system directories before that sibling. The caller
// supplies the executable it will launch or the one on its managed port;
// an unrelated gateway on PATH or selected in another registration is not
// a driver source.
func UserVMDriverDirs(home, dir, gatewayExecutable string) []string {
	var dirs []string
	if dir != "" {
		dirs = append(dirs, dir)
	} else {
		if home != "" {
			dirs = append(dirs, filepath.Join(home, ".local", "libexec", "openshell"))
		}
		dirs = append(dirs, AdminVMDriverDirs("linux")...)
	}
	if gatewayExecutable != "" && filepath.IsAbs(gatewayExecutable) {
		if real, err := filepath.EvalSymlinks(gatewayExecutable); err == nil {
			gatewayExecutable = real
		}
		sibling := filepath.Dir(gatewayExecutable)
		if !slices.Contains(dirs, sibling) {
			dirs = append(dirs, sibling)
		}
	}
	return dirs
}

// FindVMDriverIn is the first executable openshell-driver-vm in dirs, "".
func FindVMDriverIn(dirs []string) string {
	for _, dir := range dirs {
		if p := filepath.Join(dir, vmDriverBinary); executable(p) {
			return p
		}
	}
	return ""
}

// DriverChoice is the compute driver a managed sandbox gets and why.
type DriverChoice struct {
	Driver ComputeDriver
	// Reason is a DriverReason* code.
	Reason string
}

// Fallback reports whether the docker fallback replaced the MicroVM driver.
func (c DriverChoice) Fallback() bool { return IsFallbackReason(c.Reason) }

// ErrDriverUnavailable means the organization requires the MicroVM driver
// (driver_fallback: none) and it can't run for the user.
var ErrDriverUnavailable = errors.New("openshell: the MicroVM driver is required and can't run")

// DriverUnavailableError is the refusal of a sandbox that wants the MicroVM
// driver where it can't run and the fallback is none.
type DriverUnavailableError struct {
	// Reason is the probe's DriverReason* code.
	Reason string
}

func (e *DriverUnavailableError) Error() string {
	return "your organization requires MicroVM sandboxes, and " + DriverReasonText(e.Reason)
}

func (e *DriverUnavailableError) Unwrap() error { return ErrDriverUnavailable }

// SelectDriver picks the compute driver of a managed sandbox on goos.
// driver is the organization's (config.EnterpriseOpenShellConfig
// SandboxDriver: docker, vm or auto) and fallback the user's
// (SandboxDriverFallback: docker, none or ""). probe runs only when the
// MicroVM driver is wanted on Linux. A refused sandbox returns a
// *DriverUnavailableError.
func SelectDriver(goos, driver, fallback string, probe func() VMProbeResult) (DriverChoice, error) {
	driver = strings.ToLower(strings.TrimSpace(driver))
	if goos == "darwin" {
		if driver == string(DriverDocker) {
			return DriverChoice{Driver: DriverDocker, Reason: DriverReasonConfigured}, nil
		}
		// macOS runs the MicroVM driver only: no probe, no fallback.
		return DriverChoice{Driver: DriverVM, Reason: DriverReasonConfigured}, nil
	}
	switch driver {
	case "", string(DriverDocker):
		return DriverChoice{Driver: DriverDocker, Reason: DriverReasonConfigured}, nil
	case string(DriverVM), "auto":
	default:
		return DriverChoice{}, fmt.Errorf("openshell: compute driver %q is not docker, vm or auto", driver)
	}
	result := VMProbeResult{Reason: DriverReasonKVMMissing}
	if probe != nil {
		result = probe()
	}
	if result.OK {
		reason := DriverReasonConfigured
		if driver == "auto" {
			reason = DriverReasonKVMAvailable
		}
		return DriverChoice{Driver: DriverVM, Reason: reason}, nil
	}
	if !IsFallbackReason(result.Reason) {
		result.Reason = DriverReasonKVMMissing
	}
	if strings.EqualFold(strings.TrimSpace(fallback), "none") {
		return DriverChoice{}, &DriverUnavailableError{Reason: result.Reason}
	}
	return DriverChoice{Driver: DriverDocker, Reason: result.Reason}, nil
}

func firstNonEmptyString(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
