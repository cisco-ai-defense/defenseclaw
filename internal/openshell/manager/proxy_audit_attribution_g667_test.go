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

//go:build !windows

package manager

import (
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

func TestGAP0667ProxyAuditUsesReportedProcessWhenUnambiguous(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	box := e.create(sandboxapi.CreateRequest{Name: "audit-process"})
	_, advance := e.fakeClock(time.Now().UTC())
	ctx := context.Background()
	request := func(kind egress.EventKind, host string) {
		e.m.egressEvent(ctx, egress.Event{Kind: kind, SandboxName: box.Name, Time: e.m.now(), Host: host, Port: 443,
			Method: "CONNECT", Category: egress.CategoryWebhookCatcher}, 0)
	}
	open := func(binary string, pid int) {
		e.m.mu.Lock()
		b := e.m.boxes[box.Name]
		b.proxyOpens = append(b.proxyOpens, proxyOpen{binary: binary, pid: pid, at: e.m.now()})
		e.m.mu.Unlock()
	}
	rows := func(host string) []audit.SandboxEgressEvent {
		return where(&e.tel.mu, &e.tel.egress, func(ev audit.SandboxEgressEvent) bool { return ev.Host == host })
	}
	for _, tc := range []struct {
		kind egress.EventKind
		host string
	}{{egress.EventAllowed, "allowed.example.org"}, {egress.EventBlocked, "blocked.example.org"}} {
		request(tc.kind, tc.host)
	}
	advance(time.Second)
	open("/usr/bin/curl", 47)
	advance(proxyOpenWindow)
	e.m.sink.flush(ctx)
	for _, host := range []string{"allowed.example.org", "blocked.example.org"} {
		got := rows(host)
		if len(got) != 1 || got[0].Executable != "/usr/bin/curl" || got[0].PID != 47 {
			t.Fatalf("%s audit process: %+v", host, got)
		}
	}
	if rows("allowed.example.org")[0].Blocked || !rows("blocked.example.org")[0].Blocked {
		t.Fatal("the egress decisions changed")
	}

	e.m.mu.Lock()
	e.m.boxes[box.Name].proxyOpens = nil
	e.m.mu.Unlock()
	request(egress.EventAllowed, "unknown.example.org")
	advance(proxyOpenWindow + time.Second)
	e.m.sink.flush(ctx)
	if got := rows("unknown.example.org"); len(got) != 1 || got[0].Executable != "" || got[0].PID != 0 || got[0].Blocked {
		t.Fatalf("an unattributed allowed request: %+v", got)
	}

	request(egress.EventAllowed, "shared.example.org")
	advance(time.Second)
	open("/usr/bin/curl", 47)
	open("/usr/bin/wget", 48)
	advance(proxyOpenWindow)
	e.m.sink.flush(ctx)
	if got := rows("shared.example.org"); len(got) != 1 || got[0].Executable != "" || got[0].PID != 0 || got[0].Blocked {
		t.Fatalf("an ambiguous allowed request: %+v", got)
	}

	e.m.mu.Lock()
	e.m.boxes[box.Name].proxyOpens = nil
	e.m.mu.Unlock()
	requestAt := e.m.now()
	open("/usr/bin/curl", 47)
	advance(10 * time.Second)
	e.m.egressEvent(ctx, egress.Event{Kind: egress.EventAllowed, SandboxName: box.Name, Time: requestAt,
		Host: "queued.example.org", Port: 443, Method: "CONNECT", Category: egress.CategoryWebhookCatcher}, 0)
	advance(proxyOpenWindow)
	e.m.sink.flush(ctx)
	if got := rows("queued.example.org"); len(got) != 1 || got[0].Executable != "/usr/bin/curl" || got[0].PID != 47 {
		t.Fatalf("a queued request matched at dispatch time: %+v", got)
	}

	e.m.mu.Lock()
	e.m.boxes[box.Name].proxyOpens = nil
	e.m.mu.Unlock()
	request(egress.EventAllowed, "closing.example.org")
	open("/usr/bin/curl", 47)
	e.m.sink.flushProxyAudit(ctx, e.m.now(), true)
	if got := rows("closing.example.org"); len(got) != 1 || got[0].Executable != "" || got[0].PID != 0 || got[0].Blocked {
		t.Fatalf("an unfinished matching window assigned a process: %+v", got)
	}

	e.m.mu.Lock()
	e.m.boxes[box.Name].proxyOpens = nil
	e.m.mu.Unlock()
	e.m.egressEvent(ctx, egress.Event{Kind: egress.EventLargeUpload, SandboxName: box.Name, Time: e.m.now(),
		Host: "upload.example.org", Port: 443, Method: "CONNECT", Category: egress.CategoryWebhookCatcher,
		Terminated: true}, 0)
	advance(time.Second)
	open("/usr/bin/curl", 47)
	advance(proxyOpenWindow)
	e.m.sink.flush(ctx)
	if got := rows("upload.example.org"); len(got) != 1 || got[0].Executable != "/usr/bin/curl" || got[0].PID != 47 || !got[0].Blocked {
		t.Fatalf("a terminated proxy upload: %+v", got)
	}
}
