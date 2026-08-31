// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

var validBrokerArguments = []string{
	"service",
	"--service-name", "DefenseClawCMIDBroker",
	"--gateway-service-name", "DefenseClawGateway",
	"--pipe-name", `\\.\pipe\DefenseClawCMIDBroker`,
	"--auth-key", `C:\ProgramData\Cisco\broker-auth.key`,
	"--cmid-library", `C:\Program Files\Cisco\cmidapi.dll`,
	"--log", `C:\ProgramData\Cisco\cmid-broker.log`,
}

func TestParseBrokerOptions(t *testing.T) {
	options, err := parseBrokerOptions(validBrokerArguments)
	if err != nil {
		t.Fatal(err)
	}
	if options.serviceName != "DefenseClawCMIDBroker" || options.gatewayServiceName != "DefenseClawGateway" {
		t.Fatalf("options = %#v", options)
	}
}

func TestParseBrokerOptionsRejectsMissingDuplicateAndUnknown(t *testing.T) {
	cases := [][]string{
		{"service"},
		append(append([]string{}, validBrokerArguments...), "--service-name", "other"),
		append(append([]string{}, validBrokerArguments...), "--debug", "true"),
		append(append([]string{}, validBrokerArguments...), "positional"),
		append(append([]string{}, validBrokerArguments...), "--log"),
	}
	for index, arguments := range cases {
		if _, err := parseBrokerOptions(arguments); err == nil {
			t.Fatalf("case %d unexpectedly accepted", index)
		}
	}
}
