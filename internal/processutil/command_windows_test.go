// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package processutil

import (
	"context"
	"testing"

	"golang.org/x/sys/windows"
)

func TestCommandContextPreventsConsoleAllocation(t *testing.T) {
	cmd := CommandContext(context.Background(), "cmd.exe", "/d", "/c", "exit", "0")
	if cmd.SysProcAttr == nil {
		t.Fatal("captured command missing Windows process attributes")
	}
	if cmd.SysProcAttr.CreationFlags&windows.CREATE_NO_WINDOW == 0 {
		t.Fatalf("captured command creation flags = %#x, missing CREATE_NO_WINDOW", cmd.SysProcAttr.CreationFlags)
	}
	if !cmd.SysProcAttr.HideWindow {
		t.Fatal("captured command must hide any inherited startup window")
	}
	if err := cmd.Run(); err != nil {
		t.Fatalf("hidden captured command failed: %v", err)
	}
}
