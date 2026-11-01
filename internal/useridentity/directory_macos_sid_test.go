// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package useridentity

import "testing"

// rel-1-0-6:GAP-0275: the Active Directory node a /Search read names, and
// the SID of a read of that node.
func TestMacOSADNode(t *testing.T) {
	for _, tc := range []struct {
		name, out, want string
		ok              bool
	}{
		{"network account", "AppleMetaNodeLocation:\n /Active Directory/CORP/All Domains\nUniqueID: 1105\n", "/Active Directory/CORP/All Domains", true},
		{"mobile account: its original node", "AppleMetaNodeLocation:\n /Local/Default\n /Active Directory/CORP/All Domains\nOriginalNodeName:\n /Active Directory/CORP/corp.example.com\n", "/Active Directory/CORP/corp.example.com", true},
		{"mobile account, indented values", "AppleMetaNodeLocation:\n /Local/Default\n /Active Directory/CORP/All Domains\nOriginalNodeName:\n /Active Directory/CORP/All Domains\n", "/Active Directory/CORP/All Domains", true},
		{"local account", "AppleMetaNodeLocation: /Local/Default\nUniqueID: 501\n", "", false},
		{"LDAP account", "AppleMetaNodeLocation: /LDAPv3/ldap.example.com\n", "", false},
		{"two Active Directory nodes", "AppleMetaNodeLocation:\n /Active Directory/CORP/All Domains\n /Active Directory/OTHER/All Domains\n", "", false},
		{"path trick", "OriginalNodeName:\n /Active Directory/CORP/../../Local/Default\n", "", false},
		{"no domain part", "OriginalNodeName:\n /Active Directory/CORP\n", "", false},
		// dscl prints a value with spaces on its own indented line; one
		// printed on the attribute line is split and names no node.
		{"node on the attribute line", "OriginalNodeName: /Active Directory/CORP/All Domains\n", "", false},
		{"nothing", "", "", false},
	} {
		got, ok := MacOSADNode(tc.out)
		if got != tc.want || ok != tc.ok {
			t.Errorf("%s: %q, %v; want %q, %v", tc.name, got, ok, tc.want, tc.ok)
		}
	}
}

func TestMacOSDirectorySID(t *testing.T) {
	for _, tc := range []struct {
		name, out, want string
		ok              bool
	}{
		{"one domain SID", "SMBSID: S-1-5-21-1004336348-1177238915-682003330-1105\nUniqueID: 1105\n", "S-1-5-21-1004336348-1177238915-682003330-1105", true},
		{"none", "UniqueID: 1105\n", "", false},
		{"two", "SMBSID: S-1-5-21-1-2-3-1105 S-1-5-21-1-2-3-1106\n", "", false},
		{"well-known SID", "SMBSID: S-1-5-18\n", "", false},
		{"builtin domain", "SMBSID: S-1-5-32-544\n", "", false},
		{"not a SID", "SMBSID: alice\n", "", false},
		{"trailing text", "SMBSID: S-1-5-21-1-2-3-1105x\n", "", false},
	} {
		got, ok := MacOSDirectorySID(tc.out)
		if got != tc.want || ok != tc.ok {
			t.Errorf("%s: %q, %v; want %q, %v", tc.name, got, ok, tc.want, tc.ok)
		}
	}
}
