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

package setup

import (
	"context"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/extproc"
)

// TestChartCalloutAskKeysGAP0171: substrate.admin's ask_hosts and
// url_rules, then the profile's, reach the callout profile, deduplicated;
// a profile without its own gets the admin's; and the rendered callout
// engine really asks for an ask host and refuses by an url rule.
func TestChartCalloutAskKeysGAP0171(t *testing.T) {
	helm := helmBinary(t)
	cc := calloutConfigFrom(t, renderChart(t, helm, "ask-keys"))
	byName := map[string]extproc.ProfileConfig{}
	for _, p := range cc.Profiles {
		byName[p.Name] = p
	}
	eng, data := byName["engineering"], byName["data"]
	if !slices.Equal(eng.AskHosts, []string{"uploads.example.com", "*.files.example.com"}) {
		t.Errorf("engineering ask_hosts %v", eng.AskHosts)
	}
	if len(eng.URLRules) != 2 || eng.URLRules[0].Name != "no-repo-delete" || eng.URLRules[1].Name != "release-ask" ||
		eng.URLRules[1].Action != "ask" || eng.URLRules[1].PathPrefix != "/repos/acme/releases" {
		t.Errorf("engineering url_rules %+v", eng.URLRules)
	}
	if !slices.Equal(data.AskHosts, []string{"uploads.example.com"}) || len(data.URLRules) != 1 {
		t.Errorf("data (admin floor only): %v %+v", data.AskHosts, data.URLRules)
	}

	// The rendered file drives a real engine: the ask host asks (and with
	// no approvals service is refused as ask_denied), the url rule refuses.
	eng2, err := extproc.NewEngine(extproc.Options{Config: cc})
	if err != nil {
		t.Fatal(err)
	}
	defer eng2.Close()
	ctx := context.Background()
	r := &extproc.Request{Actor: extproc.ActorRef{Atespace: "eng-web", Name: "a1"}, Method: "PUT", Host: "uploads.example.com",
		Authority: "uploads.example.com", Path: "/x", ContentLength: -1, EndOfStream: true}
	if v := eng2.DecideHeaders(ctx, r); v.Allow || v.Category != extproc.CategoryAskDenied || v.Rule != "ask_hosts:uploads.example.com" {
		t.Errorf("ask host: %+v", v)
	}
	r = &extproc.Request{Actor: extproc.ActorRef{Atespace: "eng-web", Name: "a1"}, Method: "DELETE", Host: "api.github.com",
		Authority: "api.github.com", Path: "/repos/acme/web", ContentLength: -1, EndOfStream: true}
	if v := eng2.DecideHeaders(ctx, r); v.Allow || v.Category != extproc.CategoryURLRule {
		t.Errorf("url rule: %+v", v)
	}
}
