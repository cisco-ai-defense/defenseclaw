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

//go:build darwin

package gateway

import (
	"debug/macho"
	"encoding/binary"
	"testing"
)

func TestValidateSGWDarwinLoadCommandsAcceptsOnlySystemDependencies(t *testing.T) {
	loads := []macho.Load{
		testSGWMachOLoadCommand(sgwLCLoadDylinker, 12, "/usr/lib/dyld"),
		testSGWMachOLoadCommand(sgwLCLoadDylib, 24, "/usr/lib/libSystem.B.dylib"),
		testSGWMachOLoadCommand(sgwLCLoadWeakDylib, 24, "/System/Library/Frameworks/Security.framework/Versions/A/Security"),
		testSGWMachOLoadCommand(sgwLCReexportDylib, 24, "/usr/lib/libobjc.A.dylib"),
		testSGWMachOLoadCommand(sgwLCLazyLoadDylib, 24, "/usr/lib/libc++.1.dylib"),
		testSGWMachOLoadCommand(sgwLCLoadUpwardDylib, 24, "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation"),
	}
	if err := validateSGWDarwinLoadCommands(binary.LittleEndian, loads); err != nil {
		t.Fatalf("validate load commands: %v", err)
	}
}

func TestValidateSGWDarwinLoadCommandsRejectsLoaderExpansion(t *testing.T) {
	tests := []struct {
		name  string
		loads []macho.Load
	}{
		{
			name: "relative dependency",
			loads: []macho.Load{
				testSGWMachOLoadCommand(sgwLCLoadDylinker, 12, "/usr/lib/dyld"),
				testSGWMachOLoadCommand(sgwLCLoadDylib, 24, "@rpath/escape.dylib"),
			},
		},
		{
			name: "unclean dependency",
			loads: []macho.Load{
				testSGWMachOLoadCommand(sgwLCLoadDylinker, 12, "/usr/lib/dyld"),
				testSGWMachOLoadCommand(sgwLCLoadDylib, 24, "/usr/lib/../tmp/escape.dylib"),
			},
		},
		{
			name: "rpath",
			loads: []macho.Load{
				testSGWMachOLoadCommand(sgwLCLoadDylinker, 12, "/usr/lib/dyld"),
				testSGWMachOLoadCommand(sgwLCRPath, 12, "/tmp"),
			},
		},
		{
			name: "dyld environment",
			loads: []macho.Load{
				testSGWMachOLoadCommand(sgwLCLoadDylinker, 12, "/usr/lib/dyld"),
				testSGWMachOLoadCommand(sgwLCDyldEnvironment, 12, "DYLD_LIBRARY_PATH=/tmp"),
			},
		},
		{
			name: "non-system linker",
			loads: []macho.Load{
				testSGWMachOLoadCommand(sgwLCLoadDylinker, 12, "/tmp/dyld"),
			},
		},
		{
			name: "missing linker",
			loads: []macho.Load{
				testSGWMachOLoadCommand(sgwLCLoadDylib, 24, "/usr/lib/libSystem.B.dylib"),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateSGWDarwinLoadCommands(binary.LittleEndian, test.loads); err == nil {
				t.Fatal("unsafe Mach-O load commands were accepted")
			}
		})
	}
}

func TestSGWDarwinCodeRequirementBindsExactIdentity(t *testing.T) {
	admission := sgwRunnerLaunchAdmission{
		TeamID:    "ABCDEFGHIJ",
		SigningID: "com.cisco.s-gw-core",
		CDHash:    "0123456789abcdef0123456789abcdef01234567",
	}
	want := `anchor apple generic and identifier "com.cisco.s-gw-core" and certificate leaf[subject.OU] = "ABCDEFGHIJ" and cdhash H"0123456789abcdef0123456789abcdef01234567"`
	if got := sgwDarwinCodeRequirement(admission); got != want {
		t.Fatalf("requirement = %q, want %q", got, want)
	}
}

func testSGWMachOLoadCommand(command, minimumOffset uint32, value string) macho.LoadBytes {
	size := minimumOffset + uint32(len(value)) + 1
	if remainder := size % 8; remainder != 0 {
		size += 8 - remainder
	}
	raw := make([]byte, size)
	binary.LittleEndian.PutUint32(raw[0:4], command)
	binary.LittleEndian.PutUint32(raw[4:8], size)
	binary.LittleEndian.PutUint32(raw[8:12], minimumOffset)
	copy(raw[minimumOffset:], value)
	return macho.LoadBytes(raw)
}
