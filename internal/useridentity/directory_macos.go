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
//     for Okta).
//
// The Platform SSO login UPN is per user and is not reported here: until a
// root-readable source for it is confirmed it stays a claimed fact.

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
				facts.Principal = principal
				facts.Realm = RealmOf(principal)
			}
		}
		if len(fields) >= 4 && fields[1] == "NetLogon" && facts.Domain == "" {
			facts.Domain = strings.TrimSpace(fields[3])
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
		}
	case strings.HasPrefix(node, "/LDAPv3/"):
		facts.Directory = DirectoryLDAP
		facts.Domain = strings.TrimPrefix(node, "/LDAPv3/")
	case facts.Principal != "" && adDomain != "":
		facts.Directory = DirectoryActiveDirectory
	}
	if facts.Directory == DirectoryActiveDirectory && facts.Domain == "" {
		facts.Domain = adDomain
	}
	if provider := platformSSOProvider(in.AppSSO); provider != "" && facts.Directory == "" {
		facts.Directory = provider
		facts.Source = SourceMacOSPlatformSSO
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

func parseDSConfigADDomain(output string) string {
	for _, line := range strings.Split(output, "\n") {
		key, value, found := strings.Cut(line, "=")
		if found && strings.TrimSpace(key) == "Active Directory Domain" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// platformSSOProvider maps the device's Platform SSO extension to the
// directory behind it.
func platformSSOProvider(output string) Directory {
	for _, line := range strings.Split(output, "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found || strings.TrimSpace(key) != "extensionIdentifier" {
			continue
		}
		bundle := strings.ToLower(strings.Trim(strings.TrimSpace(value), `";`))
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
