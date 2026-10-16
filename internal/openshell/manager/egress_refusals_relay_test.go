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
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// #1192: a managed daemon relays its untold refusals with each hook call
// and marks them told only once the managed gateway's answer told the
// agent: PendingEgressRefusals hands them out without marking them, again
// and again, and EgressRefusalsTold marks exactly the ones told, of the
// sandbox's own binding.
func TestPendingEgressRefusalsWaitUntilTheGatewayTellsThem(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "relaybox"})
	b := e.binding("relaybox")
	block := func(host string) {
		t.Helper()
		e.m.EgressSink().EgressEvent(egress.Event{Kind: egress.EventBlocked, Method: http.MethodConnect, BindingID: b.ID,
			SandboxName: "relaybox", Host: host, Port: 443, Category: egress.CategoryWebhookCatcher, Unblockable: true, Time: time.Now()})
	}
	block("webhook.site")
	block("pipedream.net")
	first := e.m.PendingEgressRefusals(b.ID, b.SandboxName)
	if len(first) != 2 || first[0].Host != "webhook.site" || first[1].Host != "pipedream.net" ||
		!strings.Contains(first[0].Remedy, "defenseclaw sandbox unblock webhook.site --sandbox relaybox") {
		t.Fatalf("pending = %+v", first)
	}
	if again := e.m.PendingEgressRefusals(b.ID, b.SandboxName); len(again) != 2 {
		t.Fatalf("pending again = %+v", again)
	}
	// Another binding or name marks nothing.
	e.m.EgressRefusalsTold("sb_other", b.SandboxName, first)
	e.m.EgressRefusalsTold(b.ID, "otherbox", first)
	if got := e.m.PendingEgressRefusals(b.ID, b.SandboxName); len(got) != 2 {
		t.Fatalf("after a foreign mark = %+v", got)
	}
	e.m.EgressRefusalsTold(b.ID, b.SandboxName, first[:1])
	if got := e.m.PendingEgressRefusals(b.ID, b.SandboxName); len(got) != 1 || got[0].Host != "pipedream.net" {
		t.Fatalf("after telling webhook.site = %+v", got)
	}
	// A told refusal is not told again on a repeat within the window.
	block("webhook.site")
	if got := e.m.EgressRefusals(b.ID, b.SandboxName); len(got) != 1 || got[0].Host != "pipedream.net" {
		t.Fatalf("taken = %+v", got)
	}
}
