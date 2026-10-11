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
// Platform SSO cases follow an Intune-enrolled macOS 15.8 Mac with Company
// Portal (names replaced): app-sso prints JSON, and a registered account's
// record carries PlatformSSO:<UPN> in AltSecurityIdentities (GAP-0330,
// GAP-0324).
func TestParseMacOSDirectoryFacts(t *testing.T) {
	const (
		mobileAccount = "AuthenticationAuthority:\n" +
			" ;LocalCachedUser;/Active Directory/CORP/corp.example.com:alice:E9F6E0ED-138E-40C9-B9E7-A7F3F661DB14\n" +
			" ;Kerberosv5;;alice@CORP.EXAMPLE.COM;CORP.EXAMPLE.COM;\n" +
			" ;ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2>\n" +
			"OriginalNodeName:\n /Active Directory/CORP/corp.example.com\n"
		childDomainAccount = "AuthenticationAuthority:\n" +
			" ;LocalCachedUser;/Active Directory/CORP/child.corp.example.com:erin:E9F6E0ED-138E-40C9-B9E7-A7F3F661DB14\n" +
			" ;Kerberosv5;;erin@CHILD.CORP.EXAMPLE.COM;CHILD.CORP.EXAMPLE.COM;\n" +
			"OriginalNodeName:\n /Active Directory/CORP/child.corp.example.com\n"
		networkAccount = "AuthenticationAuthority: ;Kerberosv5;;bob@CORP.EXAMPLE.COM;CORP.EXAMPLE.COM; ;NetLogon;bob;CORP\n" +
			"No such key: OriginalNodeName\n"
		forestAccount = "AuthenticationAuthority: ;Kerberosv5;;dave@CORP.EXAMPLE.COM;CORP.EXAMPLE.COM;\n" +
			"OriginalNodeName:\n /Active Directory/CORP/All Domains\n"
		localAccount = "AuthenticationAuthority: ;ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2> " +
			";Kerberosv5;;carol@LKDC:SHA1.0123456789ABCDEF0123456789ABCDEF01234567;LKDC:SHA1.0123456789ABCDEF0123456789ABCDEF01234567;\n" +
			"No such key: OriginalNodeName\n"
		dsconfigadBound = "Active Directory Forest          = corp.example.com\n" +
			"Active Directory Domain          = corp.example.com\n" +
			"Computer Account                 = mac-01$\n"
		noPlatformSSO = "Time: 2026-10-06 19:08:09 +0000\n\nDevice Configuration:\n (null)\n\nLogin Configuration:\n (null)\n"
	)
	platformSSO := func(bundle string) string {
		return "Device Configuration:\n{\n  \"extensionIdentifier\" : \"" + bundle + "\",\n  \"loginType\" : \"POLoginTypePassword (1)\",\n}\n"
	}
	plistPlatformSSO := "Device Configuration:\n {\n    extensionIdentifier = \"com.microsoft.CompanyPortalMac.ssoextension\";\n    type = Credential;\n }\n"
	registered := localAccount + "AltSecurityIdentities: PlatformSSO:Erin@Contoso.Example\n"
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
			DirectoryActiveDirectory, SourceMacOSOpenDirectory, "alice@corp.example.com", "CORP.EXAMPLE.COM", "corp.example.com"},
		{"network AD account on a bound Mac", MacOSDirectoryInputs{DSCL: networkAccount, DSConfigAD: dsconfigadBound, AppSSO: noPlatformSSO},
			DirectoryActiveDirectory, SourceMacOSOpenDirectory, "bob@corp.example.com", "CORP.EXAMPLE.COM", ""},
		// A mobile account original node identifies AD without dsconfigad.
		{"mobile AD account on a Mac without dsconfigad", MacOSDirectoryInputs{DSCL: mobileAccount, AppSSO: noPlatformSSO},
			DirectoryActiveDirectory, SourceMacOSOpenDirectory, "alice@corp.example.com", "CORP.EXAMPLE.COM", "corp.example.com"},
		// The account's own node names its domain; the Mac's bound (parent) domain must not replace it.
		{"AD account of a child domain on a Mac bound to the parent", MacOSDirectoryInputs{DSCL: childDomainAccount, DSConfigAD: dsconfigadBound, AppSSO: noPlatformSSO},
			DirectoryActiveDirectory, SourceMacOSOpenDirectory, "erin@child.corp.example.com", "CHILD.CORP.EXAMPLE.COM", "child.corp.example.com"},
		// The forest-wide node ("All Domains") names no domain: dsconfigad's applies.
		{"AD account of a forest-wide search node", MacOSDirectoryInputs{DSCL: forestAccount, DSConfigAD: dsconfigadBound, AppSSO: noPlatformSSO},
			DirectoryActiveDirectory, SourceMacOSOpenDirectory, "dave@corp.example.com", "CORP.EXAMPLE.COM", "corp.example.com"},
		{"local account with an LKDC authority", MacOSDirectoryInputs{DSCL: localAccount, AppSSO: noPlatformSSO},
			DirectoryLocal, SourceMacOSOpenDirectory, "", "", ""},
		{"Entra ID Platform SSO", MacOSDirectoryInputs{DSCL: registered, AppSSO: platformSSO("com.microsoft.CompanyPortalMac.ssoextension")},
			DirectoryEntraID, SourceMacOSPlatformSSO, "erin@contoso.example", "", "contoso.example"},
		{"Entra ID Platform SSO, property-list app-sso", MacOSDirectoryInputs{DSCL: registered, AppSSO: plistPlatformSSO},
			DirectoryEntraID, SourceMacOSPlatformSSO, "erin@contoso.example", "", "contoso.example"},
		{"unregistered local account on a Platform SSO Mac", MacOSDirectoryInputs{DSCL: localAccount, AppSSO: platformSSO("com.microsoft.CompanyPortalMac.ssoextension")},
			DirectoryLocal, SourceMacOSOpenDirectory, "", "", ""},
		{"Okta Platform SSO", MacOSDirectoryInputs{DSCL: registered, AppSSO: platformSSO("com.okta.mobile.auth-service-extension")},
			DirectoryOkta, SourceMacOSPlatformSSO, "erin@contoso.example", "", "contoso.example"},
		{"other Platform SSO", MacOSDirectoryInputs{DSCL: registered, AppSSO: platformSSO("com.example.psso")},
			DirectoryOther, SourceMacOSPlatformSSO, "erin@contoso.example", "", "contoso.example"},
		{"a bound directory wins over Platform SSO", MacOSDirectoryInputs{DSCL: mobileAccount, DSConfigAD: dsconfigadBound, AppSSO: platformSSO("com.microsoft.CompanyPortalMac.ssoextension")},
			DirectoryActiveDirectory, SourceMacOSOpenDirectory, "alice@corp.example.com", "CORP.EXAMPLE.COM", "corp.example.com"},
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
	// The NetBIOS name is the DOMAIN\user namespace and never masks the DNS
	// domain (GAP-0365, GAP-0635); an account of another domain of the
	// forest gets none from the bound domain's node.
	for _, tt := range []struct {
		name, dscl, domain, accountDomain string
	}{
		{"network", networkAccount, "corp.example.com", "CORP"},
		{"mobile", mobileAccount, "corp.example.com", "CORP"},
		{"child domain", childDomainAccount, "child.corp.example.com", ""},
	} {
		got := ParseMacOSDirectoryFacts(MacOSDirectoryInputs{DSCL: tt.dscl, DSConfigAD: dsconfigadBound, AppSSO: noPlatformSSO}, now)
		if got.Domain != tt.domain || got.AccountDomain != tt.accountDomain {
			t.Fatalf("%s: domain %q account domain %q; want %q %q", tt.name, got.Domain, got.AccountDomain, tt.domain, tt.accountDomain)
		}
	}
}

// A network AD account may lack OriginalNodeName. Its own NetLogon
// authority still identifies the account when dsconfigad is unavailable.
func TestParseMacOSNetworkADWithoutDSConfigAD(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	got := ParseMacOSDirectoryFacts(MacOSDirectoryInputs{
		DSCL: "AuthenticationAuthority: ;Kerberosv5;;alice@CORP.EXAMPLE.COM;CORP.EXAMPLE.COM; ;NetLogon;alice;CORP\n" +
			"No such key: OriginalNodeName\n",
	}, now)
	if got.Directory != DirectoryActiveDirectory || got.Domain != "corp.example.com" ||
		got.AccountDomain != "CORP" || got.Principal != "alice@corp.example.com" ||
		got.Assurance != AssuranceVerified {
		t.Fatalf("network AD facts = %+v", got)
	}
}
