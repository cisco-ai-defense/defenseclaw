//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"io"
	"strings"
)

// Local accounts and directory configuration.
//
// getent exits 2 whenever getpwnam/getpwuid returns no entry, which is also
// what an NSS backend that is unavailable (sssd stopped, nslcd unable to
// reach LDAP, ypbind down) produces. So ErrNotFound is definitive for the
// local account database, but for a directory account only when something
// corroborates that the directory is answering. These helpers let callers
// tell the two apart.

// LocalAccounts returns the accounts of the local account database by
// name (Linux /etc/passwd, the macOS local directory node). Directory,
// systemd-homed and dynamic accounts are not in it.
func LocalAccounts(ctx context.Context) (map[string]int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	return platformLocalAccounts(ctx)
}

// DirectoryConfigured reports whether account lookups on this host may be
// answered by a remote directory. When it is false every "no such user"
// answer is definitive. Unknown configurations report true.
func DirectoryConfigured() bool {
	return platformDirectoryConfigured()
}

// nssLocalPasswdSources answer from local data only; any other passwd
// source in nsswitch.conf may be a remote directory.
var nssLocalPasswdSources = map[string]bool{
	"files": true, "systemd": true, "altfiles": true, "db": true,
	"usrfiles": true, "extrausers": true, "mymachines": true,
}

// ParseNSSwitchDirectoryConfigured reports whether nsswitch.conf content
// lists a passwd source other than the local ones. A missing passwd line
// is glibc's default ("files").
func ParseNSSwitchDirectoryConfigured(content string) bool {
	for _, line := range strings.Split(content, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		key, sources, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok || strings.TrimSpace(key) != "passwd" {
			continue
		}
		for _, source := range strings.Fields(sources) {
			if strings.HasPrefix(source, "[") {
				continue // an action such as [NOTFOUND=return]
			}
			if !nssLocalPasswdSources[strings.ToLower(source)] {
				return true
			}
		}
		return false
	}
	return false
}

// ParseDSCLSearchPolicyDirectoryConfigured reports whether the macOS Open
// Directory search policy, as printed by `dscl -plist /Search -read /
// SearchPath CSPSearchPath NSPSearchPath`, names a node other than the
// local ones (/Local/..., /BSD/local). A Mac bound to Active Directory or
// LDAP lists that node (for example "/Active Directory/CORP/All Domains"
// or "/LDAPv3/ldap.example.com"). Output that does not parse, or that
// names no node, reports true: a lookup may then reach a directory.
func ParseDSCLSearchPolicyDirectoryConfigured(output []byte) bool {
	decoder := xml.NewDecoder(bytes.NewReader(output))
	key := ""
	nodes := 0
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return true
		}
		start, ok := token.(xml.StartElement)
		if !ok || (start.Name.Local != "key" && start.Name.Local != "string") {
			continue
		}
		var text string
		if err := decoder.DecodeElement(&text, &start); err != nil {
			return true
		}
		text = strings.TrimSpace(text)
		if start.Name.Local == "key" {
			key = text
			continue
		}
		if !strings.HasSuffix(key, "SearchPath") || text == "" {
			continue
		}
		nodes++
		if !strings.HasPrefix(text, "/Local/") && text != "/BSD/local" {
			return true
		}
	}
	return nodes == 0
}

// parseLocalPasswd returns name → uid for the entries of a passwd(5) file.
// NIS compat markers (+/-) and malformed lines are skipped.
func parseLocalPasswd(content string) map[string]int {
	out := map[string]int{}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "+") || strings.HasPrefix(line, "-") {
			continue
		}
		account, err := ParsePasswdLine(line)
		if err != nil {
			continue
		}
		if _, dup := out[account.Name]; !dup {
			out[account.Name] = account.UID
		}
	}
	return out
}

// parseDSCLLocalAccounts parses `dscl . -list /Users UniqueID` rows.
func parseDSCLLocalAccounts(output string) map[string]int {
	out := map[string]int{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || validName(fields[0]) != nil {
			continue
		}
		uid, err := parseSignedDSCLID(fields[1])
		if err != nil {
			continue
		}
		out[fields[0]] = uid
	}
	return out
}

// parseSignedDSCLID accepts dscl's uid column, where nobody is "-2".
func parseSignedDSCLID(raw string) (int, error) {
	if strings.HasPrefix(raw, "-") {
		value, err := parseID(strings.TrimPrefix(raw, "-"), "uid")
		return -value, err
	}
	return parseID(raw, "uid")
}
