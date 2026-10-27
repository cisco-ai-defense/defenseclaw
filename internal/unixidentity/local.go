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

// LocalGroups returns the groups of the local group database by name (Linux
// /etc/group, the macOS local directory node). A directory group of the same
// name is another group: a bare group entry of a guardrail profile matches
// both, and the profile warnings name the local one (GAP-0356).
func LocalGroups(ctx context.Context) (map[string]int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	return platformLocalGroups(ctx)
}

// parseLocalGroups returns name → gid for the entries of a group(5) file.
// NIS compat markers (+/-) and malformed lines are skipped.
func parseLocalGroups(content string) map[string]int {
	out := map[string]int{}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "+") || strings.HasPrefix(line, "-") {
			continue
		}
		group, err := ParseGroupLine(line)
		if err != nil {
			continue
		}
		if _, dup := out[group.Name]; !dup {
			out[group.Name] = group.GID
		}
	}
	return out
}

// MobileAccounts returns, by name, the accounts of the macOS local directory
// node that are mobile copies of a directory account, with the directory node
// they came from (OriginalNodeName, such as /Active Directory/CORP/corp.example.com).
// A bound Mac keeps such an account in its local node, so LocalAccounts lists
// it, but it is the directory's account: its domain groups are listed only
// while the directory answers (GAP-0496). Linux has none.
func MobileAccounts(ctx context.Context) (map[string]string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	return platformMobileAccounts(ctx)
}

// parseDSCLOriginalNodes parses `dscl . -list /Users OriginalNodeName` rows
// ("name   /Active Directory/CORP/corp.example.com"; the node name holds
// spaces) into name -> node, keeping only nodes of a directory.
func parseDSCLOriginalNodes(output string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		cut := strings.IndexAny(line, " \t")
		if cut <= 0 {
			continue
		}
		name, node := line[:cut], strings.TrimSpace(line[cut:])
		if validName(name) != nil || !strings.HasPrefix(node, "/") || strings.HasPrefix(node, "/Local/") {
			continue
		}
		out[name] = node
	}
	return out
}

// LocalAccountRecord is an account of the macOS local directory node as any
// account may list it. RecordID is the record's GeneratedUID, which Open
// Directory gives every account it creates: an account deleted and created
// again under the same name and uid has a new one, so it tells the two
// apart where the name and uid do not (GAP-0669).
type LocalAccountRecord struct {
	UID        int
	RecordID   string
	Home       string
	PrimaryGID string
}

// LocalAccountRecords returns the accounts of the macOS local directory node
// by name, with their record identifier, home and primary group. Other
// platforms have none.
func LocalAccountRecords(ctx context.Context) (map[string]LocalAccountRecord, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	return platformLocalAccountRecords(ctx)
}

// LocalAccountRecordByName returns the record of the local account name as
// LocalAccountRecords lists it, read for that account alone (macOS), and
// false when the local node holds no such account. Other platforms have
// none.
func LocalAccountRecordByName(ctx context.Context, name string) (LocalAccountRecord, bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validName(name); err != nil {
		return LocalAccountRecord{}, false, err
	}
	return platformLocalAccountRecord(ctx, name)
}

// AccountRecordGone reports whether a fresh directory read, in its own
// process, has no record of the account name. On macOS a long-running
// process keeps answering os/user lookups of a deleted account from
// libSystem's per-process cache (the hook guardian found a deleted local
// account minutes after `sysadminctl -deleteUser`, rel-1-0-5 GAP-0029),
// so a "found" from such a process is confirmed here before it keeps a
// decision open. It is true only for Open Directory's definitive "record
// not found" while no bound directory node is offline; any other answer,
// and every other platform (whose lookups already run in a fresh getent
// process), is false.
func AccountRecordGone(ctx context.Context, name string) bool {
	if ctx == nil {
		ctx = context.Background()
	}
	if validName(name) != nil {
		return false
	}
	return platformAccountRecordGone(ctx, name)
}

// dsclRecordNotFoundExit is dscl's exit status for eDSRecordNotFound
// (DS Error -14136).
const dsclRecordNotFoundExit = 56

// dsclRecordNotFound reads the result of `dscl /Search -read /Users/<name>
// UniqueID`: only Open Directory's own "record not found" with no output
// says the account is gone; a timeout, a run error or any other exit says
// nothing.
func dsclRecordNotFound(result commandResult, err error) bool {
	return err == nil && result.exitCode == dsclRecordNotFoundExit && len(strings.TrimSpace(string(result.stdout))) == 0
}

// parseDSCLAttribute parses `dscl . -list /Users <attribute>` rows ("name
// value"; a home may hold spaces, and a record without the attribute is
// listed with no value) into name -> value.
func parseDSCLAttribute(output string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		name, value := line, ""
		if cut := strings.IndexAny(line, " \t"); cut > 0 {
			name, value = line[:cut], strings.TrimSpace(line[cut:])
		}
		if validName(name) != nil {
			continue
		}
		out[name] = value
	}
	return out
}

// mergeDSCLAccountRecords joins the UniqueID listing with the GeneratedUID,
// NFSHomeDirectory and PrimaryGroupID listings. An account is kept when its
// one uid parses.
func mergeDSCLAccountRecords(uids, recordIDs, homes, gids map[string]string) map[string]LocalAccountRecord {
	out := make(map[string]LocalAccountRecord, len(uids))
	for name, raw := range uids {
		uid, err := parseSignedDSCLID(raw)
		if err != nil {
			continue
		}
		out[name] = LocalAccountRecord{UID: uid, RecordID: recordIDs[name], Home: homes[name], PrimaryGID: gids[name]}
	}
	return out
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
