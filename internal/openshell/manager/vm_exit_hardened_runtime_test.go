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

//go:build !windows

package manager

import (
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// NVIDIA/OpenShell#4772: a Developer ID re-signing of openshell-driver-vm
// with the hardened runtime and only the Hypervisor entitlement keeps the
// entitlement the doctor checks but cannot boot a VM (library validation
// refuses the embedded libkrun, dyld ignores DYLD_*). The MicroVM exit on a
// Mac and the signing advice name the two exceptions the re-signing needs.
func TestMacVMExitAndSigningAdviceNameTheHardenedRuntimeExceptions(t *testing.T) {
	vm, _ := openshell.LookupDriver("vm")
	exited := func() error {
		return upstream("wait for sandbox x", errors.New(`sandbox "x" is in error state; OpenShell says: ProcessExited: VM process exited with status 1`))
	}
	want := []string{"--options runtime", "com.apple.security.cs.disable-library-validation", "com.apple.security.cs.allow-dyld-environment-variables"}
	for name, msg := range map[string]string{
		"vm exit on a Mac": vmExitFailure("darwin", false, vm, exited()).Error(),
		"signing advice":   openshell.VMDriverSigningFix("/x/openshell-driver-vm"),
	} {
		for _, w := range want {
			if !strings.Contains(msg, w) {
				t.Errorf("%s lacks %q: %s", name, w, msg)
			}
		}
	}
	if msg := vmExitFailure("linux", false, vm, exited()).Error(); strings.Contains(msg, "disable-library-validation") {
		t.Errorf("the Linux MicroVM exit names a macOS entitlement: %s", msg)
	}
}
