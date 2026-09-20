// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

func TestValidateDevinExecutableIdentityRequiresExactFixedPath(t *testing.T) {
	expected := `C:\Users\alice\AppData\Local\devin\cli\bin\devin.exe`
	for _, tc := range []struct {
		name string
		path string
		ok   bool
	}{
		{name: "exact", path: expected, ok: true},
		{name: "case insensitive Windows identity", path: `c:\users\alice\appdata\local\devin\cli\bin\DEVIN.EXE`, ok: true},
		{name: "other installation", path: `C:\Program Files\Devin\devin.exe`},
		{name: "relative", path: `devin\cli\bin\devin.exe`},
		{name: "whitespace", path: expected + " "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateDevinExecutableIdentity(tc.path, expected)
			if (err == nil) != tc.ok {
				t.Fatalf("identity error = %v, want ok=%t", err, tc.ok)
			}
		})
	}
}

func TestValidateDevinSignerRequiresExactExafunctionIdentity(t *testing.T) {
	for _, tc := range []struct {
		name     string
		metadata embeddedAuthenticodeMetadata
		ok       bool
	}{
		{name: "common name", metadata: embeddedAuthenticodeMetadata{Present: true, SignerCommonName: "Exafunction, Inc."}, ok: true},
		{name: "organization", metadata: embeddedAuthenticodeMetadata{Present: true, SignerCommonName: "Devin", SignerOrganizations: "Exafunction, Inc."}, ok: true},
		{name: "organization list", metadata: embeddedAuthenticodeMetadata{Present: true, SignerOrganizations: "Vendor\x00Exafunction, Inc."}, ok: true},
		{name: "unsigned", metadata: embeddedAuthenticodeMetadata{}},
		{name: "wrong case", metadata: embeddedAuthenticodeMetadata{Present: true, SignerCommonName: "EXAFUNCTION, INC."}},
		{name: "substring", metadata: embeddedAuthenticodeMetadata{Present: true, SignerCommonName: "Exafunction, Inc. Test"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateDevinSigner(tc.metadata)
			if (err == nil) != tc.ok {
				t.Fatalf("signer error = %v, want ok=%t", err, tc.ok)
			}
		})
	}
}

func TestValidateDevinVersionOutputPins3000425(t *testing.T) {
	for _, tc := range []struct {
		output string
		ok     bool
	}{
		{output: "devin 3000.4.25\n", ok: true},
		{output: "v3000.4.25", ok: true},
		{output: "3000.4.24"},
		{output: "13000.4.25"},
		{output: "3000.4.250"},
		{output: "3000.4.25-beta.1"},
		{output: "devin 3000.4.25 runtime 1.2.3"},
	} {
		err := validateDevinVersionOutput([]byte(tc.output))
		if (err == nil) != tc.ok {
			t.Fatalf("version %q error = %v, want ok=%t", tc.output, err, tc.ok)
		}
	}
}
