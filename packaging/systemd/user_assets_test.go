// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package systemdunits

import (
	"slices"
	"strings"
	"testing"
)

// The sandbox user units are embedded, and stay out of the system units.
func TestUserUnitsAreEmbeddedApartFromTheSystemUnits(t *testing.T) {
	want := []string{"defenseclaw-openshell-gateway.service", "defenseclaw-sandbox.service", "defenseclaw-sandbox.socket"}
	if got := UserUnits(); !slices.Equal(got, want) {
		t.Fatalf("UserUnits = %v, want %v", got, want)
	}
	for _, name := range want {
		data, err := ReadUserUnit(name)
		if err != nil || len(data) == 0 {
			t.Fatalf("ReadUserUnit(%s) = %d bytes, %v", name, len(data), err)
		}
		if slices.Contains(Units(), name) {
			t.Errorf("%s is listed with the system units", name)
		}
		if _, err := ReadFile(name); err == nil {
			t.Errorf("%s is embedded with the system units", name)
		}
	}
	socket, _ := ReadUserUnit("defenseclaw-sandbox.socket")
	if !strings.Contains(string(socket), "WantedBy=sockets.target") {
		t.Errorf("the socket unit lacks its install section:\n%s", socket)
	}
}
