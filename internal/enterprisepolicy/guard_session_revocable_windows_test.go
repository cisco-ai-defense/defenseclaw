//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"testing"

	"golang.org/x/sys/windows"
)

// Review P1 (1.0.4 guard loop round 2): on Windows the revocation marks go
// in the record folder. An allow passes an outage only while that folder's
// access list lets the gateway that wrote the records (the account
// folder's owner) add a file there, in an entry that applies to the folder
// itself, and has no deny entry or entry of another type.
func TestPublishedSessionMarkFolderMustLetItsWriterAddAFile(t *testing.T) {
	const gateway = "S-1-5-80-1111-2222-3333-4444-5555"
	writer, err := windows.StringToSid(gateway)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, sddl string
		ok         bool
	}{
		{"the lifecycle's record folder", "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a9;;;BU)(A;OICI;0x1301bf;;;" + gateway + ")", true},
		{"no entry for the writer", "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a9;;;BU)", false},
		{"read and list only", "D:P(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;" + gateway + ")", false},
		{"inherit only", "D:P(A;OICI;FA;;;SY)(A;OICIIO;FA;;;" + gateway + ")", false},
		{"a deny of adding a file", "D:P(D;;0x2;;;" + gateway + ")(A;OICI;0x1301bf;;;" + gateway + ")", false},
		{"a deny to a group", "D:P(D;;0x2;;;BU)(A;OICI;0x1301bf;;;" + gateway + ")", false},
		{"an inherit-only deny", "D:P(D;OICIIO;0x2;;;BU)(A;OICI;0x1301bf;;;" + gateway + ")", true},
		{"generic write", "D:P(A;;GW;;;" + gateway + ")", true},
	} {
		descriptor, err := windows.SecurityDescriptorFromString(c.sddl)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		dacl, _, err := descriptor.DACL()
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if err := publishedSessionDACLLetsAddAFile(c.name, dacl, writer); (err == nil) != c.ok {
			t.Fatalf("%s: %v, want ok %v", c.name, err, c.ok)
		}
	}
	if err := publishedSessionDACLLetsAddAFile("no list", nil, writer); err == nil {
		t.Fatal("a folder without an access list cannot be shown to take a mark")
	}
}
