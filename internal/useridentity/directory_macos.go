// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package useridentity

import (
	"strings"
	"time"
)

// macOS directory facts, verified by the root enumerator from:
//
//   - dscl /Search -read /Users/<name> AuthenticationAuthority
//     OriginalNodeName: an AD-bound or mobile account carries a
//     ;Kerberosv5;;user@REALM;REALM; authority (local accounts carry an LKDC
//     one, which is skipped) and its original node names the directory;
//   - dsconfigad -show: the AD domain the Mac is bound to;
//   - app-sso platform -s: the Platform SSO extension, which names the
//     identity provider (Microsoft Company Portal for Entra ID, Okta Verify
//     for Okta);
//   - dscl ... AltSecurityIdentities: an account registered with Platform SSO
//     (linked at registration, or created at the login window) carries
//     PlatformSSO:<login UPN>, which root can read (GAP-0324).
//
// An account is a Platform SSO account only when its own record carries that
// link: a Mac with Platform SSO also has local accounts that never registered
// (the administrator, service accounts), and those stay local. macOS 15
// prints app-sso as JSON ("extensionIdentifier" : "..."); older releases
// printed a property list (extensionIdentifier = "..."). Both are read: the
// JSON form went unread, so every account reported local (GAP-0330).

// MacOSDirectoryInputs are the raw outputs of the three commands.
type MacOSDirectoryInputs struct {
	DSCL       string
	DSConfigAD string
	AppSSO     string
}

// ParseMacOSDirectoryFacts composes the verified facts of one account.
func ParseMacOSDirectoryFacts(in MacOSDirectoryInputs, now time.Time) DirectoryFacts {
	attrs := parseDSCLAttributes(in.DSCL)
	facts := DirectoryFacts{Source: SourceMacOSOpenDirectory, Assurance: AssuranceVerified, ResolvedAt: now}
	for _, authority := range attrs["AuthenticationAuthority"] {
		fields := strings.Split(authority, ";")
		if len(fields) >= 5 && fields[1] == "Kerberosv5" && !strings.HasPrefix(fields[4], "LKDC:") {
			if principal := NormalizePrincipal(fields[3]); principal != "" {
				facts.Principal = NormalizeUPN(principal)
				facts.Realm = RealmOf(principal)
			}
		}
		// ;NetLogon;bob;CORP names the account's NetBIOS domain: the
		// DOMAIN\user namespace, not its DNS domain (GAP-0365).
		if len(fields) >= 4 && fields[1] == "NetLogon" && facts.AccountDomain == "" {
			facts.AccountDomain = macOSNetBIOSDomain(fields[3])
		}
	}
	node := ""
	if values := attrs["OriginalNodeName"]; len(values) > 0 {
		node = values[0]
	}
	adDomain := parseDSConfigADDomain(in.DSConfigAD)
	switch {
	case strings.HasPrefix(node, "/Active Directory/"):
		facts.Directory = DirectoryActiveDirectory
		// "/Active Directory/CORP/corp.example.com", or ".../All Domains"
		// for a forest-wide search node, which names no domain.
		if parts := strings.Split(node, "/"); len(parts) >= 4 && !strings.ContainsAny(parts[len(parts)-1], " \t") {
			facts.Domain = parts[len(parts)-1]
			// The middle part is the NetBIOS name of the domain the Mac is
			// bound to, so it is the account's DOMAIN\user namespace only
			// when the account is in that domain: the one macOS lists the
			// account's groups in (CORP\group), and a users entry
			// CORP\user names (GAP-0635). An account of another domain of
			// the forest keeps none.
			if facts.AccountDomain == "" && adDomain != "" && strings.EqualFold(facts.Domain, adDomain) {
				facts.AccountDomain = macOSNetBIOSDomain(parts[2])
			}
		}
	case strings.HasPrefix(node, "/LDAPv3/"):
		facts.Directory = DirectoryLDAP
		facts.Domain = strings.TrimPrefix(node, "/LDAPv3/")
	case facts.Principal != "" && adDomain != "":
		facts.Directory = DirectoryActiveDirectory
	}
	if facts.Directory == DirectoryActiveDirectory && facts.Domain == "" {
		// A network account has no original node: its Kerberos realm names
		// its DNS domain, else the domain the Mac is bound to.
		facts.Domain = strings.ToLower(facts.Realm)
		if facts.Domain == "" {
			facts.Domain = adDomain
		}
	}
	if facts.Directory != DirectoryActiveDirectory {
		facts.AccountDomain = ""
	}
	if upn := platformSSOLoginUPN(attrs["AltSecurityIdentities"]); upn != "" && facts.Directory == "" {
		facts.Directory = platformSSOProvider(in.AppSSO)
		if facts.Directory == "" {
			facts.Directory = DirectoryOther
		}
		facts.Source = SourceMacOSPlatformSSO
		facts.UPN, facts.Principal = upn, upn
		facts.Domain = upn[strings.LastIndexByte(upn, '@')+1:]
	}
	if facts.Directory == "" {
		facts.Directory = DirectoryLocal
	}
	return facts
}

// parseDSCLAttributes parses dscl -read output: "Name: v1 v2" on one line,
// or "Name:" followed by indented value lines when a value has spaces.
func parseDSCLAttributes(output string) map[string][]string {
	attrs := map[string][]string{}
	current := ""
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if current != "" {
				attrs[current] = append(attrs[current], strings.TrimSpace(line))
			}
			continue
		}
		name, rest, found := strings.Cut(line, ":")
		if !found {
			current = ""
			continue
		}
		current = strings.TrimSpace(name)
		if strings.HasPrefix(current, "dsAttrTypeNative") || strings.ContainsAny(current, " \t") {
			current = ""
			continue
		}
		attrs[current] = append(attrs[current], strings.Fields(rest)...)
	}
	return attrs
}

// macOSNetBIOSDomain returns name when it can be a NetBIOS domain name (no
// separators, spaces or controls, at most 15 characters), else "".
func macOSNetBIOSDomain(name string) string {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 15 || strings.ContainsAny(name, "\\/@.:;*?\"<>| \t") {
		return ""
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return ""
		}
	}
	return name
}

func parseDSConfigADDomain(output string) string {
	for _, line := range strings.Split(output, "\n") {
		key, value, found := strings.Cut(line, "=")
		if found && strings.TrimSpace(key) == "Active Directory Domain" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// platformSSOLoginUPN returns the login UPN of a PlatformSSO:<upn> entry of
// AltSecurityIdentities, or "".
func platformSSOLoginUPN(values []string) string {
	for _, value := range values {
		if rest, ok := strings.CutPrefix(value, "PlatformSSO:"); ok {
			if upn := NormalizeUPN(rest); upn != "" {
				return upn
			}
		}
	}
	return ""
}

// platformSSOProvider maps the device's Platform SSO extension to the
// directory behind it.
func platformSSOProvider(output string) Directory {
	for _, line := range strings.Split(output, "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found {
			key, value, found = strings.Cut(line, ":")
		}
		if !found || strings.Trim(strings.TrimSpace(key), `"`) != "extensionIdentifier" {
			continue
		}
		bundle := strings.ToLower(strings.Trim(strings.TrimSpace(value), `";, `))
		switch {
		case strings.HasPrefix(bundle, "com.microsoft."):
			return DirectoryEntraID
		case strings.HasPrefix(bundle, "com.okta."):
			return DirectoryOkta
		case bundle != "":
			return DirectoryOther
		}
	}
	return ""
}
