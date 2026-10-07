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

package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// The feed mode takes no argument but --check or --uninstall: nothing a
// caller passes can widen what it reads.
func TestSandboxFeedModeTakesNoOtherArguments(t *testing.T) {
	for _, args := range [][]string{
		{"--socket", "/tmp/x"}, {"--check", "--uninstall"}, {"--managed-enterprise"}, {"check"}, {"--check=true"},
	} {
		var stdout, stderr bytes.Buffer
		if rc := runSandboxFeed(args, &stdout, &stderr); rc != 2 || !strings.Contains(stderr.String(), "usage:") {
			t.Errorf("%q: rc %d, stderr %q", args, rc, stderr.String())
		}
	}
}

func TestSandboxFeedModeRunsAsRootOnly(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	for _, args := range [][]string{nil, {"--check"}, {"--uninstall"}} {
		var stdout, stderr bytes.Buffer
		if rc := runSandboxFeed(args, &stdout, &stderr); rc != 1 || !strings.Contains(stderr.String(), "runs as root") {
			t.Errorf("%q: rc %d, stderr %q", args, rc, stderr.String())
		}
	}
}
