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

package gateway

import (
	"encoding/json"
	"strings"
	"testing"
)

// GAP-1914: a letter whose lower case is longer (U+023A) in a pkill -F pid
// file made the DefenseClaw control guard panic outside every evaluation
// recovery, and the hook answered with its fail-mode verdict (an allow in a
// fail-open profile). The call is now judged as the same call spelled in
// ASCII, in every pack.
func TestGAP1914HookControlGuardGrowingLetterIsJudged(t *testing.T) {
	for _, p := range gap0437Packs {
		a := gap0437Server(t, p, "claudecode", "action")
		for _, tail := range []string{"defenseclaw-gateway stop", "echo done"} {
			command := "pkill -F " + strings.Repeat("\u023a", 64) + ".pid; " + tail
			got := gap0437Hook(t, a, t.TempDir(), "g-"+p.name+tail, command)
			want := gap0437Hook(t, a, t.TempDir(), "a-"+p.name+tail, "pkill -F AAAA.pid; "+tail)
			if raw, _ := json.Marshal(got); strings.Contains(string(raw), "internal evaluator error") {
				t.Errorf("%s %q: the hook answered with its panic recovery: %s", p.name, command, raw)
			}
			if got["action"] != want["action"] {
				t.Errorf("%s %q: action %v, want %v as for the ASCII spelling", p.name, command, got["action"], want["action"])
			}
		}
	}
}

// A U+0130 before .exe no longer cuts the service executable one byte early.
func TestGAP1914EndpointHealthServiceExecutableShrinkingLetter(t *testing.T) {
	image := `C:\Svc\` + "\u0130" + `\svc.exe -k netsvcs`
	if got, want := endpointHealthServiceExecutable(image), `C:\Svc\`+"\u0130"+`\svc.exe`; got != want {
		t.Errorf("endpointHealthServiceExecutable(%q) = %q, want %q", image, got, want)
	}
	if got := endpointHealthServiceExecutable(`C:\Svc\SVC.EXE -k x`); got != `C:\Svc\SVC.EXE` {
		t.Errorf("ASCII: got %q, want C:\\Svc\\SVC.EXE", got)
	}
}
