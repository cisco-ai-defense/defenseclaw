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

// A full XDR installation registers this service before Cloud Management
// exists, so the installer cannot supply --cmid-library. The broker must
// accept that and discover the library at runtime.
func TestParseBrokerOptionsAcceptsAbsentCMIDLibrary(t *testing.T) {
	arguments := []string{
		"service",
		"--service-name", "DefenseClawCMIDBroker",
		"--gateway-service-name", "DefenseClawGateway",
		"--pipe-name", `\\.\pipe\DefenseClawCMIDBroker`,
		"--auth-key", `C:\ProgramData\Cisco\broker-auth.key`,
		"--log", `C:\ProgramData\Cisco\cmid-broker.log`,
	}
	options, err := parseBrokerOptions(arguments)
	if err != nil {
		t.Fatalf("parseBrokerOptions without --cmid-library: %v", err)
	}
	if options.cmidLibraryPath != "" {
		t.Fatalf("cmidLibraryPath = %q, want empty", options.cmidLibraryPath)
	}
	if options.logPath != `C:\ProgramData\Cisco\cmid-broker.log` {
		t.Fatalf("logPath = %q", options.logPath)
	}
}

// Dropping --cmid-library from the required set must not stop the parser
// rejecting genuinely unknown options.
func TestParseBrokerOptionsRejectsUnknownWithoutCMIDLibrary(t *testing.T) {
	arguments := []string{
		"service",
		"--service-name", "DefenseClawCMIDBroker",
		"--gateway-service-name", "DefenseClawGateway",
		"--pipe-name", `\\.\pipe\DefenseClawCMIDBroker`,
		"--auth-key", `C:\ProgramData\Cisco\broker-auth.key`,
		"--log", `C:\ProgramData\Cisco\cmid-broker.log`,
		"--debug", "true",
	}
	if _, err := parseBrokerOptions(arguments); err == nil {
		t.Fatal("parser accepted an unknown option")
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
