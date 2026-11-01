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

// GAP-2268: the shell opens a static redirect target before it runs the
// program, so the redirect of a program named by a relative or untrusted path
// is a projected write.
func TestR105GAP2268OpaqueProgramRedirectIsProjected(t *testing.T) {
	for _, command := range []string{
		"./build.sh > /etc/cron.d/persist",
		"scripts/gen.sh >> /etc/cron.d/persist",
		"/opt/acme/bin/tool > /etc/cron.d/persist",
	} {
		t.Run(command, func(t *testing.T) {
			projected := Analyze(Input{Tool: "exec", Command: command}).EnforcementProjection()
			found := false
			for _, fact := range projected.Paths {
				if (fact.Access == PathAccessWrite || fact.Access == PathAccessAppend) && fact.Resolved == "/etc/cron.d/persist" {
					found = true
				}
			}
			if !found {
				t.Fatalf("no projected write for %q: %#v", command, projected.Paths)
			}
			assertFactsInvariants(t, projected)
		})
	}
}
