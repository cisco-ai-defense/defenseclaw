// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package launchdstandalone

import (
	"slices"
	"strings"
	"testing"
)

// The sandbox LaunchAgents are embedded, and stay out of the LaunchDaemons.
func TestAgentPlistsAreEmbeddedApartFromTheDaemons(t *testing.T) {
	want := []string{"com.cisco.defenseclaw.openshell-gateway", "com.cisco.defenseclaw.sandbox"}
	if got := AgentLabels(); !slices.Equal(got, want) {
		t.Fatalf("AgentLabels = %v, want %v", got, want)
	}
	for _, label := range want {
		data, err := ReadAgentPlist(label)
		if err != nil || !strings.Contains(string(data), "<string>"+label+"</string>") {
			t.Fatalf("ReadAgentPlist(%s) = %d bytes, %v", label, len(data), err)
		}
		if slices.Contains(Labels(), label) {
			t.Errorf("%s is listed with the LaunchDaemons", label)
		}
		if _, err := ReadPlist(label); err == nil {
			t.Errorf("%s is embedded with the LaunchDaemons", label)
		}
	}
}
