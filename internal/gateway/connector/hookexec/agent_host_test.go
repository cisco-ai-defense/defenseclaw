// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"strings"
	"testing"
)

// The agent host tag is attribution for managed enterprise hooks only.
func TestAgentHostHeaderIsSentOnlyByManagedHooks(t *testing.T) {
	for _, tc := range []struct {
		name    string
		managed bool
		host    string
		want    string
	}{
		{name: "managed", managed: true, host: "Devin Helper (Plugin)", want: "devin-helper--plugin-"},
		{name: "unmanaged", managed: false, host: "devin helper", want: ""},
		{name: "managed without a usable name", managed: true, host: " () ", want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := ok(`{"action":"allow"}`)
			run(t, "devin", rt, func(o *Options) {
				o.ManagedEnterprise = tc.managed
				o.AgentHost = tc.host
				o.Stdin = strings.NewReader(`{"hook_event_name":"PreToolUse"}`)
			})
			if rt.gotReq == nil {
				t.Fatal("no request captured")
			}
			if got := rt.gotReq.Header.Get(AgentHostHeader); got != tc.want {
				t.Fatalf("%s = %q, want %q", AgentHostHeader, got, tc.want)
			}
		})
	}
}
