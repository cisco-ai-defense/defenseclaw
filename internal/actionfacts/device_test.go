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

package actionfacts

import "testing"

func TestRawBlockDeviceTargetFamilies(t *testing.T) {
	t.Parallel()

	for _, value := range []string{
		"/dev/sda",
		"/dev/sda12",
		"/dev/vdb",
		"/dev/xvdc3",
		"/dev/hda",
		"/dev/disk0",
		"/dev/disk0s2",
		"/dev/rdisk12s4",
		"/dev/nvme0n1",
		"/dev/nvme0n1p2",
		"/dev/mmcblk0",
		"/dev/mmcblk0p1",
		"/dev/md0",
		"/dev/dm-3",
		"/dev/mapper/vg-root",
		"/dev/disk/by-id/nvme-example",
		`\\.\PhysicalDrive0`,
		"//./physicaldrive12",
	} {
		value := value
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			if !isRawBlockDeviceTarget(value) {
				t.Fatalf("isRawBlockDeviceTarget(%q) = false, want true", value)
			}
		})
	}
}

func TestRawBlockDeviceTargetRejectsBenignAndMalformedDevices(t *testing.T) {
	t.Parallel()

	for _, value := range []string{
		"",
		"/dev/null",
		"/dev/zero",
		"/dev/random",
		"/dev/urandom",
		"/dev/log",
		"/dev/tty",
		"/dev/tty0",
		"/dev/stdin",
		"/dev/stdout",
		"/dev/stderr",
		"/dev/fd/1",
		"/dev/loop0",
		"/dev/ram0",
		"/dev/sdaevil",
		"/dev/sdA",
		"/dev/disk",
		"/dev/disk0s",
		"/dev/rdisk0s1tail",
		"/dev/nvme0",
		"/dev/nvme0n",
		"/dev/nvme0n1p",
		"/dev/mmcblk",
		"/dev/mmcblk0p",
		"/dev/md",
		"/dev/dm-",
		"/dev/mapper/",
		"/dev/mapper/..",
		"/dev/mapper/vg/root",
		"/dev/mapper/vg root",
		"/dev/disk/by-id/",
		"/dev/disk/by-id/../sda",
		" /dev/sda",
		"/dev/sda ",
		`\\.\CONOUT$`,
		`\\.\NUL`,
		`\\.\PhysicalDrive`,
		`\\.\PhysicalDrive0\partition`,
		`\\?\PhysicalDrive0`,
	} {
		value := value
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			if isRawBlockDeviceTarget(value) {
				t.Fatalf("isRawBlockDeviceTarget(%q) = true, want false", value)
			}
		})
	}
}

func TestDiskWriteClassificationRequiresConcreteBlockTarget(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name     string
		input    Input
		wantDisk bool
	}{
		{
			name: "dd block device",
			input: Input{
				Tool: "exec",
				Argv: []string{"dd", "if=/tmp/image", "of=/dev/sda"},
			},
			wantDisk: true,
		},
		{
			name: "tee device mapper",
			input: Input{
				Tool: "exec",
				Argv: []string{"tee", "/dev/mapper/vg-root"},
			},
			wantDisk: true,
		},
		{
			name: "dd null sink",
			input: Input{
				Tool: "exec",
				Argv: []string{"dd", "if=/tmp/image", "of=/dev/null"},
			},
		},
		{
			name: "mkfs loop device",
			input: Input{
				Tool: "exec",
				Argv: []string{"mkfs.ext4", "-F", "/dev/loop0"},
			},
		},
		{
			name: "wipefs character device",
			input: Input{
				Tool: "exec",
				Argv: []string{"wipefs", "--all", "/dev/zero"},
			},
		},
		{
			name: "sgdisk image file",
			input: Input{
				Tool: "exec",
				Argv: []string{"sgdisk", "-Z", "./disk.img"},
			},
		},
		{
			name: "tee log socket",
			input: Input{
				Tool: "exec",
				Argv: []string{"tee", "/dev/log"},
			},
		},
		{
			name: "redirect null sink",
			input: Input{
				Tool:    "exec",
				Command: "printf literal > /dev/null",
			},
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(test.input)
			if !facts.Authoritative() {
				t.Fatalf("test input was not authoritative: %#v", facts)
			}
			if got := factsHaveOperation(
				facts,
				OperationDiskWrite,
			); got != test.wantDisk {
				t.Fatalf(
					"disk-write classification = %t, want %t: %#v",
					got,
					test.wantDisk,
					facts,
				)
			}
		})
	}
}

func TestDeviceFlavoredCharacterSinkDoesNotGainDiskWrite(t *testing.T) {
	t.Parallel()

	facts := Facts{
		Parse: ParseResult{
			Status:  StatusComplete,
			Dialect: DialectPowerShell,
		},
		Commands: []CommandFact{{
			ID:         1,
			Kind:       CommandKindProcess,
			Dialect:    DialectPowerShell,
			Effect:     EffectExecute,
			Executable: "Set-Content",
			Program:    "set-content",
			Argv: []string{
				"Set-Content", "-LiteralPath", `\\.\CONOUT$`,
				"-Value", "literal",
			},
			ArgvComplete: true,
			Operations: []OperationKind{
				OperationExecute,
				OperationWrite,
			},
		}},
		Paths: []PathFact{{
			CommandID: 1,
			Access:    PathAccessWrite,
			Flavor:    PathFlavorDevice,
			Value:     `\\.\CONOUT$`,
		}},
	}

	projected := facts.EnforcementProjection()
	if !projected.EnforcementEligible() ||
		factsHaveOperation(projected, OperationDiskWrite) {
		t.Fatalf("character sink gained disk-write semantics: %#v", projected)
	}
}
