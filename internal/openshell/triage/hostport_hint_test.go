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

package triage

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
)

// A proposal for this machine's own address (live: the host's LAN IP on a
// dev-server port) is rejected with a reason that says how to reach the
// service instead, so the feed line gives the user the way on.
func TestOwnAddressRejectionNamesHostPort(t *testing.T) {
	open := effective(t, nil, packs.Flags{})
	d := Classify(context.Background(), proposal(testOwnV4, 38590), testPolicy(open))
	if d.Verdict != Reject || !strings.Contains(d.Message, "belongs to this machine") ||
		!strings.Contains(d.Message, "--host-port 38590") || !strings.Contains(d.Message, "host.openshell.internal:38590") {
		t.Fatalf("decision = %+v", d)
	}
	// A name that resolves to this machine gets the same way on.
	pol := testPolicy(open)
	pol.Resolver = newResolver().set("dev.example.org", testOwnV4)
	d = Classify(context.Background(), proposal("dev.example.org", 443), pol)
	if d.Verdict != Reject || d.Reason != ReasonResolvesToHost || !strings.Contains(d.Message, "--host-port 443") {
		t.Fatalf("decision for a name = %+v", d)
	}
}
