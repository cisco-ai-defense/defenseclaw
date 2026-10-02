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
	"testing"

	"golang.org/x/sys/windows"
)

// GAP-1829: only a missing stdout attaches the parent console; a pipe keeps
// its handle so setup's identity probe still reads the output.
func TestNeedsParentConsoleOnlyWithoutStdout(t *testing.T) {
	if !needsParentConsole(0) || !needsParentConsole(windows.InvalidHandle) {
		t.Fatal("a missing stdout must attach the parent console")
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if needsParentConsole(windows.Handle(w.Fd())) {
		t.Fatal("a piped stdout must keep its handle")
	}
}
