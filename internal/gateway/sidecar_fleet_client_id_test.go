// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

func TestFleetMQTTClientIDsAreDistinctAndBrokerCompatible(t *testing.T) {
	seen := make(map[string]bool, 256)
	for i := 0; i < 256; i++ {
		id, err := newFleetMQTTClientID()
		if err != nil {
			t.Fatal(err)
		}
		if len(id) > 23 || len(id) < 1 || seen[id] {
			t.Fatalf("invalid or duplicate Fleet MQTT client ID %q", id)
		}
		seen[id] = true
	}
}
