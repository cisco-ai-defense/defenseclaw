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

package sensor

import (
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
	"github.com/defenseclaw/defenseclaw/internal/sensor/tactics"
)

// drainHandled runs the consumer until it has handled every scripted event.
func drainHandled(t *testing.T, host *hostPlane, source *fakeSource) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := host.start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	deadline := time.After(5 * time.Second)
	for host.handled.Load() < int64(len(source.script)) {
		select {
		case <-deadline:
			t.Fatalf("consumer handled %d of %d events", host.handled.Load(), len(source.script))
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// credentialAccessWeight is the agent_credential_access weight of the one
// finding harvested from host, 0 when there is none.
func credentialAccessWeight(t *testing.T, host *hostPlane, at time.Time) int {
	t.Helper()
	findings := host.harvest(at, 1)
	if len(findings) > 1 {
		t.Fatalf("got %d findings, want at most one", len(findings))
	}
	weight := 0
	for _, finding := range findings {
		for _, signal := range finding.Signals {
			if signal.ID == "agent_credential_access" {
				weight += signal.Weight
			}
		}
	}
	return weight
}

// TestGAP1189ClaudeOwnBedrockConfigReadIsNotCredentialAccess: Claude Code on
// Amazon Bedrock reads ~/.aws/config itself at every start, an idle TUI
// session included. That read is the agent starting, not credential access:
// it was agent_credential_access T1552 weight 18 (30 x 0.6) on every idle
// managed Linux session.
func TestGAP1189ClaudeOwnBedrockConfigReadIsNotCredentialAccess(t *testing.T) {
	t.Parallel()
	base := time.Unix(1_760_000_000, 0)
	for _, agent := range []plane.Event{
		{Kind: plane.KindExec, PID: 300, PPID: 1, Name: "claude", Cmdline: "claude", At: base},
		{Kind: plane.KindExec, PID: 300, PPID: 1, Name: "2.1.323", Exe: "/home/dev/.local/share/claude/versions/2.1.323",
			Cmdline: "claude", At: base},
	} {
		source := newFake(fullCoverage(), agent,
			plane.Event{Kind: plane.KindFileRead, PID: 300, Path: "/home/dev/.aws/config", At: base.Add(time.Second)},
		)
		host := newHost(source)
		drainHandled(t, host, source)
		if classified, _, _, _ := host.stats(); classified != 0 {
			t.Fatalf("%s: classified %d observations for the agent reading its own provider config", agent.Name, classified)
		}
		if weight := credentialAccessWeight(t, host, base.Add(time.Minute)); weight != 0 {
			t.Fatalf("%s: own ~/.aws/config read scored agent_credential_access %d, want none", agent.Name, weight)
		}
	}
}

// TestGAP1189CredentialReadsOutsideOwnProviderConfigStay is the negative
// side: every read that is not the identified agent itself reading its own
// provider config is graded as before.
func TestGAP1189CredentialReadsOutsideOwnProviderConfigStay(t *testing.T) {
	t.Parallel()
	base := time.Unix(1_760_000_000, 0)
	claude := plane.Event{Kind: plane.KindExec, PID: 400, PPID: 1, Name: "claude", Cmdline: "claude", At: base}
	cases := []struct {
		name   string
		script []plane.Event
		want   int
	}{
		{"child of the agent reads ~/.aws/config", []plane.Event{claude,
			{Kind: plane.KindExec, PID: 401, PPID: 400, Name: "sh", Cmdline: "sh -c true", At: base.Add(time.Second)},
			{Kind: plane.KindFileRead, PID: 401, Path: "/home/dev/.aws/config", At: base.Add(2 * time.Second)},
		}, 18},
		{"agent reads ~/.aws/credentials", []plane.Event{claude,
			{Kind: plane.KindFileRead, PID: 400, Path: "/home/dev/.aws/credentials", At: base.Add(time.Second)},
		}, 30},
		{"agent reads another credential-adjacent file", []plane.Event{claude,
			{Kind: plane.KindFileRead, PID: 400, Path: "/home/dev/.npmrc", At: base.Add(time.Second)},
		}, 18},
		{"agent reads a file only named like the config", []plane.Event{claude,
			{Kind: plane.KindFileRead, PID: 400, Path: "/home/dev/.aws/config.bak", At: base.Add(time.Second)},
		}, 18},
		{"pattern-recognised agent with no connector reads ~/.aws/config", []plane.Event{
			{Kind: plane.KindExec, PID: 500, PPID: 1, Name: "aider", Cmdline: "aider", At: base},
			{Kind: plane.KindFileRead, PID: 500, Path: "/home/dev/.aws/config", At: base.Add(time.Second)},
		}, 18},
		{"connector agent without a provider config reads ~/.aws/config", []plane.Event{
			{Kind: plane.KindExec, PID: 600, PPID: 1, Name: "codex", Cmdline: "codex", At: base},
			{Kind: plane.KindFileRead, PID: 600, Path: "/home/dev/.aws/config", At: base.Add(time.Second)},
		}, 18},
	}
	for _, tc := range cases {
		source := newFake(fullCoverage(), tc.script...)
		host := newHost(source)
		drainHandled(t, host, source)
		if weight := credentialAccessWeight(t, host, base.Add(time.Minute)); weight != tc.want {
			t.Errorf("%s: agent_credential_access weight %d, want %d", tc.name, weight, tc.want)
		}
	}

	// A process with no agent above it stays behind the lineage gate.
	source := newFake(fullCoverage(),
		plane.Event{Kind: plane.KindExec, PID: 700, PPID: 1, Name: "python3", Cmdline: "python3 app.py", At: base},
		plane.Event{Kind: plane.KindFileRead, PID: 700, Path: "/home/dev/.aws/config", At: base.Add(time.Second)},
	)
	host := newHost(source)
	drainHandled(t, host, source)
	if classified, gated, _, _ := host.stats(); classified != 0 || gated == 0 {
		t.Fatalf("unattributed ~/.aws/config read: classified %d gated %d, want gated", classified, gated)
	}
}

// TestGAP1189OwnProviderConfigReadWindowsFoldsCase checks the suffix match
// folds case only where the indicator set does.
func TestGAP1189OwnProviderConfigReadWindowsFoldsCase(t *testing.T) {
	t.Parallel()
	if !hasPathSuffix(`C:/Users/Dev/.AWS/Config`, "/.aws/config", tactics.IndicatorsFor("windows").CaseInsensitivePaths) {
		t.Fatal("windows suffix match does not fold case")
	}
	if hasPathSuffix("/home/dev/.AWS/config", "/.aws/config", tactics.IndicatorsFor("linux").CaseInsensitivePaths) {
		t.Fatal("linux suffix match folds case")
	}
}
