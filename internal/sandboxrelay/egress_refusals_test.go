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

package sandboxrelay

import (
	"strings"
	"testing"
)

// #1192: the refusals a relayed hook call carries round-trip, made
// header-safe and bounded; a hostile value is refused whole.
func TestEgressRefusalsHeaderBounds(t *testing.T) {
	in := []EgressRefusal{
		{Host: "Webhook.Site.", Port: 443, Category: "webhook_catcher", What: "webhook\r\ncatcher", Remedy: "unblock it"},
		{Host: "bad host", Category: "x"},
		{Host: "pipedream.net", Category: "Not-A-Code"},
		{Host: "api.example.com", Port: 443, Category: "asked", Note: "asked", What: strings.Repeat("é", 400)},
	}
	value := EncodeEgressRefusals(in)
	got := ParseEgressRefusals(value)
	if len(got) != 2 || got[0].Host != "webhook.site" || got[0].What != "webhook  catcher" || got[1].Host != "api.example.com" ||
		len(got[1].What) > MaxEgressRefusalTextBytes {
		t.Fatalf("round trip = %+v", got)
	}
	var many []EgressRefusal
	for range MaxEgressRefusals + 4 {
		many = append(many, EgressRefusal{Host: "a.example", Remedy: strings.Repeat("r", MaxEgressRefusalTextBytes)})
	}
	if fit := FitEgressRefusals(many); len(fit) == 0 || len(fit) > MaxEgressRefusals || len(ParseEgressRefusals(EncodeEgressRefusals(many))) != len(fit) {
		t.Fatalf("fit %d of %d", len(fit), len(many))
	}
	for _, bad := range []string{"", "%%%", value + "A", EncodeEgressRefusals(nil)} {
		if got := ParseEgressRefusals(bad); got != nil {
			t.Fatalf("%q parsed as %+v", bad, got)
		}
	}
	d := ParseHookDecision(`{"v":1,"action":"allow","egress_told":true}`)
	if d == nil || !d.EgressTold {
		t.Fatalf("trailer = %+v", d)
	}
}
