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

//go:build windows

package cli

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestManagedWatchdogCreationFlagsHonorJobBreakawayPolicy(t *testing.T) {
	base := uint32(windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS)
	tests := []struct {
		name       string
		queryErr   error
		limitFlags uint32
		want       uint32
	}{
		{name: "outside job", queryErr: windows.ERROR_INVALID_HANDLE, want: base | windows.CREATE_BREAKAWAY_FROM_JOB},
		{name: "restricted job", want: base},
		{name: "explicit breakaway", limitFlags: windows.JOB_OBJECT_LIMIT_BREAKAWAY_OK, want: base | windows.CREATE_BREAKAWAY_FROM_JOB},
		{name: "silent breakaway", limitFlags: windows.JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK, want: base},
		{name: "unknown query failure", queryErr: windows.ERROR_ACCESS_DENIED, want: base},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := watchdogCreationFlagsForJob(tc.queryErr, tc.limitFlags); got != tc.want {
				t.Fatalf("watchdog creation flags = %#x, want %#x", got, tc.want)
			}
		})
	}

	attrs := watchdogSysProcAttr()
	if attrs == nil {
		t.Fatal("watchdogSysProcAttr returned nil")
	}
	if attrs.CreationFlags&base != base {
		t.Fatalf("watchdog creation flags = %#x, missing required detachment %#x", attrs.CreationFlags, base)
	}
}
