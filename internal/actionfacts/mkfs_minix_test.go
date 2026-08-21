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

func TestMkfsMinixDeviceGrammar(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name string
		argv []string
	}{
		{name: "bare", argv: []string{"mkfs.minix", "/dev/sda"}},
		{name: "trusted absolute path", argv: []string{"/usr/sbin/mkfs.minix", "/dev/sda"}},
		{name: "minimum block count", argv: []string{"mkfs.minix", "/dev/sda", "11"}},
		{name: "maximum block count", argv: []string{"mkfs.minix", "/dev/sda", "65535"}},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			out := classifyTestArgv(test.argv)
			if out.status != StatusComplete || len(out.commands) != 1 ||
				out.commands[0].Program != "mkfs.minix" ||
				!commandHasOperation(out.commands[0], OperationDiskWrite) ||
				!outputHasPath(out, PathAccessWrite, "/dev/sda") {
				t.Fatalf("mkfs.minix device grammar was not owned: %#v", out)
			}
		})
	}
}

func TestMkfsMinixControls(t *testing.T) {
	t.Parallel()

	image := classifyTestArgv([]string{"mkfs.minix", "/tmp/minix.img"})
	if image.status != StatusComplete || len(image.commands) != 1 ||
		commandHasOperation(image.commands[0], OperationDiskWrite) ||
		!commandHasOperation(image.commands[0], OperationWrite) ||
		!outputHasPath(image, PathAccessWrite, "/tmp/minix.img") {
		t.Fatalf("ordinary image target became a device wipe: %#v", image)
	}

	for _, option := range []string{"-h", "--help", "-V", "--version"} {
		preview := classifyTestArgv([]string{"mkfs.minix", option, "/dev/sda"})
		if preview.status != StatusComplete || len(preview.commands) != 1 ||
			preview.commands[0].Effect != EffectPreview ||
			commandHasOperation(preview.commands[0], OperationDiskWrite) ||
			len(preview.paths) != 0 {
			t.Fatalf("preview option %q became executable: %#v", option, preview)
		}
	}

	for _, argv := range [][]string{
		{"mkfs.minix", "/dev/sda", "10"},
		{"mkfs.minix", "/dev/sda", "65536"},
		{"mkfs.minix", "--future-option", "/dev/sda"},
		{"mkfs.minixx", "/dev/sda"},
		{"/tmp/mkfs.minix", "/dev/sda"},
	} {
		out := classifyTestArgv(argv)
		if out.status != StatusPartial {
			t.Fatalf("unowned argv=%v status=%s output=%#v", argv, out.status, out)
		}
	}
}
