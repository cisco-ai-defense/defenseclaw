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

package manager

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/ocsf"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// ownPortsEnv pushes OpenShell records to one ready sandbox.
type ownPortsEnv struct {
	*harnessEnv
	name string
}

func newOwnPortsEnv(t *testing.T) *ownPortsEnv {
	t.Helper()
	e := newEnv(t, nil)
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "portsbox"})
	e.watch.waitStarted(t, sb.Name)
	return &ownPortsEnv{harnessEnv: e, name: sb.Name}
}

func (e *ownPortsEnv) push(line string) {
	e.t.Helper()
	rec, err := ocsf.Parse(line)
	if err != nil {
		e.t.Fatal(err)
	}
	e.m.mu.Lock()
	b := e.m.boxes[e.name]
	e.m.mu.Unlock()
	e.m.ocsfEvent(context.Background(), b, rec, time.Now())
}

func (e *ownPortsEnv) blocks() []sandboxapi.ActivityEvent {
	var out []sandboxapi.ActivityEvent
	for _, ev := range e.m.ActivitySince(0, e.name) {
		if ev.Kind == sandboxapi.ActivityEgressBlocked {
			out = append(out, ev)
		}
	}
	return out
}

func (e *ownPortsEnv) blocked() int {
	e.t.Helper()
	sb, err := e.m.Get(context.Background(), e.name)
	if err != nil {
		e.t.Fatal(err)
	}
	return sb.Egress.Blocked
}

// A connection OpenShell closes because the policy changed under it (every
// provider or policy reload does that) is none of the user's business: live
// it showed as "✗ bedrock-mantle.us-east-1.api.aws (L7 tunnel closed before
// inspection because policy changed …)", twice per reload, and doubled the
// session's blocked counts. It stays in the audit record only.
func TestPolicyReloadCutsAreNoBlocks(t *testing.T) {
	e := newOwnPortsEnv(t)
	cut := "NET:OPEN [MED] DENIED " + testClaudeBin + "(0) -> bedrock-mantle.us-east-1.api.aws:443 [reason:L7 tunnel closed before inspection " +
		"because policy changed: policy generation is stale [captured_generation:2 current_generation:3]]"
	e.push(cut)
	e.push(cut)
	if got := e.blocks(); len(got) != 0 || e.blocked() != 0 {
		t.Fatalf("feed = %+v, blocked %d; a policy reload's cut counted as a block", got, e.blocked())
	}
	e.tel.mu.Lock()
	audited := 0
	for _, ev := range e.tel.egress {
		if ev.Host == "bedrock-mantle.us-east-1.api.aws" && ev.Blocked {
			audited++
		}
	}
	e.tel.mu.Unlock()
	if audited != 2 {
		t.Fatalf("audited %d reload cuts, want 2", audited)
	}
	// A real denial still counts.
	e.push("NET:OPEN [MED] DENIED /usr/bin/curl(0) -> webhook.example.net:443 [reason:transparent_tcp_policy_denied]")
	if got := e.blocks(); len(got) != 1 || e.blocked() != 1 {
		t.Fatalf("feed = %+v, blocked %d", got, e.blocked())
	}
}

// Denials of this install's own ingress and egress ports are no blocked
// sites, also when the host alias's synthetic address was never named:
// live, "✗ 198.18.0.2:38601 (transparent_tcp_mapping_denied)" showed on
// the feed and in the session summary. After a daemon restart the watch
// resumes past OpenShell's mapping record, so the address comes from the
// sandbox record, and DefenseClaw's own ports are the host alias's anyway.
func TestOwnPortDenialsAreNoBlocks(t *testing.T) {
	e := newOwnPortsEnv(t)
	ingress, egressPort := strconv.Itoa(testIngressPort), strconv.Itoa(testEgressPort)
	// No mapping record seen: the ports alone name the host alias.
	e.push("NET:OPEN [MED] DENIED " + testClaudeBin + "(0) -> 198.18.0.2:" + ingress + " [reason:transparent_tcp_mapping_denied]")
	e.push("NET:OPEN [MED] DENIED " + testClaudeBin + "(0) -> 198.18.0.2:" + egressPort + " [reason:transparent_tcp_mapping_denied]")
	if got := e.blocks(); len(got) != 0 || e.blocked() != 0 {
		t.Fatalf("feed = %+v, blocked %d; DefenseClaw's own ports counted", got, e.blocked())
	}
	// The mapping record goes on the sandbox record.
	e.push("CONFIG:PUBLISHED [INFO] Policy DNS mapped host.openshell.internal resolved=127.0.0.1 synthetic=198.18.0.3 ports=" +
		egressPort + "," + ingress + ",38821 mapping_id=m1")
	e.stop()
	recs, errs := newRecordStore(e.dataDir).loadAll()
	if len(errs) != 0 || len(recs) != 1 || recs[0].HostAlias == nil || recs[0].HostAlias.Addr != "198.18.0.3" ||
		len(recs[0].HostAlias.Ports) != 3 {
		t.Fatalf("records = %+v, %v; want the host alias mapping kept", recs, errs)
	}

	// A restarted daemon has seen no mapping record.
	e.m = e.newManager()
	e.run()
	eventually(t, "the adopted sandbox is ready", func() bool {
		sb, err := e.m.Get(context.Background(), e.name)
		return err == nil && sb.Phase == "ready"
	})
	// A credential port the mapping covers, denied while it was
	// republished, reaches nothing new; the ingress's is DefenseClaw's own.
	e.push("NET:OPEN [MED] DENIED " + testClaudeBin + "(0) -> 198.18.0.3:38821 [reason:transparent_tcp_mapping_denied]")
	e.push("NET:OPEN [MED] DENIED " + testClaudeBin + "(0) -> 198.18.0.3:" + ingress + " [reason:transparent_tcp_mapping_denied]")
	if got := e.blocks(); len(got) != 0 || e.blocked() != 0 {
		t.Fatalf("after the restart: feed = %+v, blocked %d", got, e.blocked())
	}
	// Another port of the host alias is a closed host port, named so.
	e.push("NET:OPEN [MED] DENIED /usr/bin/curl(0) -> 198.18.0.3:38590 [reason:transparent_tcp_mapping_denied]")
	got := e.blocks()
	if len(got) != 1 || got[0].Host != openshellHostAlias || got[0].Port != 38590 || e.blocked() != 1 {
		t.Fatalf("feed = %+v, blocked %d", got, e.blocked())
	}
}
