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

package sandboxcli

import (
	"strings"
	"testing"
)

// A headless harness's output is kept only up to its last 16 KiB, where a
// start failure's message is.
func TestOutputTailKeepsTheEnd(t *testing.T) {
	var tail outputTail
	_, _ = tail.Write([]byte(strings.Repeat("x", harnessOutputBytes)))
	_, _ = tail.Write([]byte("\nFailed to start: listen tcp: lookup localhost on 127.0.0.53:53: server misbehaving\n"))
	got := tail.String()
	if len(got) != harnessOutputBytes || !strings.HasSuffix(got, "server misbehaving\n") {
		t.Fatalf("tail is %d bytes ending %q", len(got), got[len(got)-40:])
	}
}

// The sandbox's localhost check asks the system resolver and /etc/hosts
// by absolute path, and reports one line.
func TestLocalhostCheckScript(t *testing.T) {
	for _, want := range []string{"/usr/bin/getent hosts localhost", "/usr/bin/grep -qsw localhost /etc/hosts", `echo "::localhost=$r $h"`} {
		if !strings.Contains(localhostCheckScript, want) {
			t.Errorf("check lacks %q: %s", want, localhostCheckScript)
		}
	}
}
