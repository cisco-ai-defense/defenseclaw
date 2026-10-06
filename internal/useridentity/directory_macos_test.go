// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package useridentity

import (
	"testing"
	"time"
)

// TestParseMacOSDirectoryFacts pins the account shapes the root enumerator
// meets on a Mac, taken from dscl, dsconfigad and app-sso output captured on a
// Mac bound to a lab Active Directory (names replaced), so a change in those
// tools' output shows up here and not as a silently empty identity. The
// Platform SSO cases use the extensionIdentifier line of a configured device;
// the lab has no Entra or Okta tenant to capture one from.
func TestParseMacOSDirectoryFacts(t *testing.T) {
	const (
		mobileAccount = "AuthenticationAuthority:\n" +
			" ;LocalCachedUser;/Active Directory/CORP/corp.example.com:alice:E9F6E0ED-138E-40C9-B9E7-A7F3F661DB14\n" +
			" ;Kerberosv5;;alice@CORP.EXAMPLE.COM;CORP.EXAMPLE.COM;\n" +
			" ;ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2>\n" +
			"OriginalNodeName:\n /Active Directory/CORP/corp.example.com\n"
		networkAccount = "AuthenticationAuthority: ;Kerberosv5;;bob@CORP.EXAMPLE.COM;CORP.EXAMPLE.COM; ;NetLogon;bob;CORP\n" +
			"No such key: OriginalNodeName\n"
		localAccount = "AuthenticationAuthority: ;ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2> " +
			";Kerberosv5;;carol@LKDC:SHA1.0123456789ABCDEF0123456789ABCDEF01234567;LKDC:SHA1.0123456789ABCDEF0123456789ABCDEF01234567;\n" +
			"No such key: OriginalNodeName\n"
		dsconfigadBound = "Active Directory Forest          = corp.example.com\n" +
			"Active Directory Domain          = corp.example.com\n" +
			"Computer Account                 = mac-01$\n"
		noPlatformSSO = "Time: 2026-10-06 19:08:09 +0000\n\nDevice Configuration:\n (null)\n\nLogin Configuration:\n (null)\n"
	)
	platformSSO := func(bundle string) string {
		return "Device Configuration:\n {\n    extensionIdentifier = \"" + bundle + "\";\n    type = Credential;\n }\n"
	}
	now := time.Unix(1_800_000_000, 0)
	tests := []struct {
		name      string
		in        MacOSDirectoryInputs
		directory Directory
		source    string
		principal string
		realm     string
		domain    string
	}{
		{"mobile AD account", MacOSDirectoryInputs{DSCL: mobileAccount, DSConfigAD: dsconfigadBound, AppSSO: noPlatformSSO},
			DirectoryActiveDirectory, SourceMacOSOpenDirectory, "alice@CORP.EXAMPLE.COM", "CORP.EXAMPLE.COM", "corp.example.com"},
		{"network AD account on a bound Mac", MacOSDirectoryInputs{DSCL: networkAccount, DSConfigAD: dsconfigadBound, AppSSO: noPlatformSSO},
			DirectoryActiveDirectory, SourceMacOSOpenDirectory, "bob@CORP.EXAMPLE.COM", "CORP.EXAMPLE.COM", ""},
		{"local account with an LKDC authority", MacOSDirectoryInputs{DSCL: localAccount, AppSSO: noPlatformSSO},
			DirectoryLocal, SourceMacOSOpenDirectory, "", "", ""},
		{"Entra ID Platform SSO", MacOSDirectoryInputs{DSCL: localAccount, AppSSO: platformSSO("com.microsoft.CompanyPortalMac.ssoextension")},
			DirectoryEntraID, SourceMacOSPlatformSSO, "", "", ""},
		{"Okta Platform SSO", MacOSDirectoryInputs{DSCL: localAccount, AppSSO: platformSSO("com.okta.mobile.auth-service-extension")},
			DirectoryOkta, SourceMacOSPlatformSSO, "", "", ""},
		{"other Platform SSO", MacOSDirectoryInputs{DSCL: localAccount, AppSSO: platformSSO("com.example.psso")},
			DirectoryOther, SourceMacOSPlatformSSO, "", "", ""},
		{"a bound directory wins over Platform SSO", MacOSDirectoryInputs{DSCL: mobileAccount, DSConfigAD: dsconfigadBound, AppSSO: platformSSO("com.microsoft.CompanyPortalMac.ssoextension")},
			DirectoryActiveDirectory, SourceMacOSOpenDirectory, "alice@CORP.EXAMPLE.COM", "CORP.EXAMPLE.COM", "corp.example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseMacOSDirectoryFacts(tt.in, now)
			if got.Directory != tt.directory || got.Source != tt.source || got.Principal != tt.principal ||
				got.Realm != tt.realm || (tt.domain != "" && got.Domain != tt.domain) ||
				got.Assurance != AssuranceVerified || !got.ResolvedAt.Equal(now) {
				t.Fatalf("facts = %+v; want directory %q source %q principal %q realm %q domain %q",
					got, tt.directory, tt.source, tt.principal, tt.realm, tt.domain)
			}
		})
	}
}
