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

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// attachParentProcess is ATTACH_PARENT_PROCESS ((DWORD)-1).
const attachParentProcess = ^uint32(0)

var procAttachConsole = windows.NewLazySystemDLL("kernel32.dll").NewProc("AttachConsole")

// needsParentConsole reports whether stdout is missing or unusable. A
// windowsgui binary typed in a terminal gets no usable standard handles; a
// piped or redirected run (setup's identity probe, `| Out-String`) does and
// must keep its handle.
func needsParentConsole(stdout windows.Handle) bool {
	if stdout == 0 || stdout == windows.InvalidHandle {
		return true
	}
	kind, err := windows.GetFileType(stdout)
	return err != nil || kind == windows.FILE_TYPE_UNKNOWN
}

// useParentConsoleForStdout lets `defenseclaw-hook --version` typed in
// PowerShell or cmd print to that terminal (GAP-1829). The hook itself stays
// windowsgui so agent applications never get a console window.
func useParentConsoleForStdout() {
	handle, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
	if err == nil && !needsParentConsole(handle) {
		return
	}
	if ok, _, _ := procAttachConsole.Call(uintptr(attachParentProcess)); ok == 0 {
		return
	}
	if out, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0); err == nil {
		os.Stdout = out
	}
}
