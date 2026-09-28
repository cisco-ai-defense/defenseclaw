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
