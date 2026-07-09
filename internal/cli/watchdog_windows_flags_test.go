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

func TestManagedWatchdogCreationFlagsPermitExplicitJobBreakaway(t *testing.T) {
	attrs := watchdogSysProcAttr()
	want := uint32(windows.CREATE_NEW_PROCESS_GROUP |
		windows.DETACHED_PROCESS |
		windows.CREATE_BREAKAWAY_FROM_JOB)
	if attrs == nil {
		t.Fatal("watchdogSysProcAttr returned nil")
	}
	if got := attrs.CreationFlags; got != want {
		t.Fatalf("watchdog creation flags = %#x, want %#x", got, want)
	}
}
