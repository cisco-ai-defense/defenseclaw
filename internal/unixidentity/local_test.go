//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import "testing"

func TestParseNSSwitchDirectoryConfigured(t *testing.T) {
	for content, want := range map[string]bool{
		"passwd: files systemd\ngroup: files systemd\n":         false,
		"passwd:     sss files systemd\n":                       true, // RHEL 9 authselect default
		"passwd: files ldap\n":                                  true,
		"passwd: compat\n":                                      true, // compat can pull NIS entries
		"passwd: files [NOTFOUND=return] winbind\n":             true,
		"# passwd: sss\npasswd: files # sss later\n":            false,
		"group: sss files\n":                                    false, // glibc default for passwd is files
		"passwd: files mymachines systemd\nshadow: files sss\n": false,
		"passwd:files\n":                                        false,
		"passwd: files usrfiles extrausers altfiles db\n":       false,
		"passwd: files nis\n":                                   true,
		"hosts: files dns\npasswd: files sss\npasswd: files\n":  true, // first passwd line wins
	} {
		if got := ParseNSSwitchDirectoryConfigured(content); got != want {
			t.Errorf("ParseNSSwitchDirectoryConfigured(%q) = %v, want %v", content, got, want)
		}
	}
}

func TestParseLocalPasswdAndDSCL(t *testing.T) {
	local := parseLocalPasswd("root:x:0:0:root:/root:/bin/bash\n+nisuser::::::\nalice:x:1000:1000::/home/alice:/bin/bash\nbroken\nalice:x:2000:2000::/x:/bin/sh\n")
	if len(local) != 2 || local["alice"] != 1000 || local["root"] != 0 {
		t.Fatalf("parseLocalPasswd = %v", local)
	}
	dscl := parseDSCLLocalAccounts("_www 70\nalice   501\nnobody -2\nbad line here\n")
	if dscl["alice"] != 501 || dscl["nobody"] != -2 || dscl["_www"] != 70 || len(dscl) != 3 {
		t.Fatalf("parseDSCLLocalAccounts = %v", dscl)
	}
	// GAP-0496: a bound Mac's mobile accounts sit in the local node with the
	// directory node they came from; they are directory accounts.
	nodes := parseDSCLOriginalNodes("ent-bob     /Active Directory/DCLAB/dclab.test\nent-ldap /LDAPv3/ldap.example.test\n" +
		"ent-kept /Local/Default\nbroken\n")
	if len(nodes) != 2 || nodes["ent-bob"] != "/Active Directory/DCLAB/dclab.test" || nodes["ent-ldap"] != "/LDAPv3/ldap.example.test" {
		t.Fatalf("parseDSCLOriginalNodes = %v", nodes)
	}
	// GAP-0532: a local node account linked to Platform SSO is the identity
	// provider's account; a Kerberos or malformed link is no such link.
	linked := parseDSCLPlatformSSOAccounts("alice  PlatformSSO:alice@corp.example\n" +
		"bob Kerberos:bob@LKDC:SHA1.1 PlatformSSO:Bob@Corp.Example\ncarol Kerberos:carol@LKDC:SHA1.2\n" +
		"dave PlatformSSO:\neve PlatformSSO:not-a-upn\nbroken\n")
	if len(linked) != 2 || !linked["alice"] || !linked["bob"] {
		t.Fatalf("parseDSCLPlatformSSOAccounts = %v", linked)
	}
	groups := parseLocalGroups("wheel:x:10:root\n+nisgroup:::\ndc-sbx-contractors:x:2501:ent-hank\nbroken\nwheel:x:11:\n")
	if len(groups) != 2 || groups["wheel"] != 10 || groups["dc-sbx-contractors"] != 2501 {
		t.Fatalf("parseLocalGroups = %v", groups)
	}
}

// GAP-0669: the gateway's macOS account stamp lists each local account's
// uid, GeneratedUID, home and primary group, so an account deleted and
// created again under the same name and uid is seen as another account.
func TestParseDSCLAccountRecords(t *testing.T) {
	records := mergeDSCLAccountRecords(
		parseDSCLAttribute("_www 70\nalice   501\nnobody -2\nbad 5 6\n\n"),
		parseDSCLAttribute("alice  8C1F-AAAA\n_www FFFFEEEE-0046\nnobody\n"),
		parseDSCLAttribute("alice  /Users/alice smith\n_www\t/Library/WebServer\n"),
		parseDSCLAttribute("alice 20\n_www 70\nnobody -2\n"),
	)
	want := map[string]LocalAccountRecord{
		"alice":  {UID: 501, RecordID: "8C1F-AAAA", Home: "/Users/alice smith", PrimaryGID: "20"},
		"_www":   {UID: 70, RecordID: "FFFFEEEE-0046", Home: "/Library/WebServer", PrimaryGID: "70"},
		"nobody": {UID: -2, PrimaryGID: "-2"},
	}
	if len(records) != len(want) {
		t.Fatalf("records = %+v, want %+v", records, want)
	}
	for name, record := range want {
		if records[name] != record {
			t.Fatalf("records[%q] = %+v, want %+v", name, records[name], record)
		}
	}
}

// macOS: the enumerator assumed every Mac may be bound to a directory, so a
// deleted local account whose source was not recorded as local was never
// revoked on an unbound Mac. The search policy decides it.
func TestParseDSCLSearchPolicyDirectoryConfigured(t *testing.T) {
	plist := func(entries string) []byte {
		return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
` + entries + `</dict>
</plist>
`)
	}
	localOnly := `	<key>dsAttrTypeStandard:CSPSearchPath</key>
	<array>
		<string>/Local/Default</string>
	</array>
	<key>dsAttrTypeStandard:NSPSearchPath</key>
	<array>
		<string>/Local/Default</string>
	</array>
	<key>dsAttrTypeStandard:SearchPath</key>
	<array>
		<string>/Local/Default</string>
	</array>
	<key>dsAttrTypeStandard:SearchPolicy</key>
	<array>
		<string>dsAttrTypeStandard:NSPSearchPath</string>
	</array>
`
	for name, tc := range map[string]struct {
		output []byte
		want   bool
	}{
		"unbound Mac (macOS 15 default)": {plist(localOnly), false},
		"BSD flat files": {plist(`	<key>dsAttrTypeStandard:SearchPath</key>
	<array>
		<string>/Local/Default</string>
		<string>/BSD/local</string>
	</array>
`), false},
		"Active Directory": {plist(`	<key>dsAttrTypeStandard:CSPSearchPath</key>
	<array>
		<string>/Local/Default</string>
		<string>/Active Directory/CORP/All Domains</string>
	</array>
	<key>dsAttrTypeStandard:SearchPath</key>
	<array>
		<string>/Local/Default</string>
		<string>/Active Directory/CORP/All Domains</string>
	</array>
`), true},
		"LDAP only in the automatic path": {plist(`	<key>dsAttrTypeStandard:NSPSearchPath</key>
	<array>
		<string>/Local/Default</string>
		<string>/LDAPv3/ldap.example.com</string>
	</array>
	<key>dsAttrTypeStandard:SearchPath</key>
	<array>
		<string>/Local/Default</string>
	</array>
`), true},
		"no search path":     {plist(""), true},
		"not a plist":        {[]byte("No such key: SearchPath\n"), true},
		"empty output":       {nil, true},
		"truncated document": {plist(localOnly)[:200], true},
	} {
		if got := ParseDSCLSearchPolicyDirectoryConfigured(tc.output); got != tc.want {
			t.Errorf("%s: ParseDSCLSearchPolicyDirectoryConfigured = %v, want %v", name, got, tc.want)
		}
	}
}
