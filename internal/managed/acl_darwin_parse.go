// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"fmt"
	"strconv"
	"strings"
)

// darwinACLEntry is one extended ACL entry as `/bin/ls -lde` prints it, for
// example ` 0: group:admin inherited allow write,file_inherit`. The parser has
// no build tag so the verdict can be table tested on every platform.
type darwinACLEntry struct {
	Index       int
	Principal   string
	Allow       bool
	Inherited   bool
	Permissions []string
}

// darwinACLWritePermissions are the rights that let a principal change an
// object or the entries of a folder.
var darwinACLWritePermissions = map[string]bool{
	"write": true, "add_file": true, "append": true, "add_subdirectory": true,
	"delete": true, "delete_child": true, "writeattr": true, "writeextattr": true,
	"writesecurity": true, "chown": true,
}

// darwinTrustedACLPrincipals hold administrator authority on macOS already: an
// allow entry for them grants nothing an attacker can use.
var darwinTrustedACLPrincipals = map[string]bool{
	"user:root":   true,
	"group:wheel": true,
	"group:admin": true,
}

// onlyInherit reports an inherit-only entry, which grants nothing on the
// object itself and only seeds new children.
func (e darwinACLEntry) onlyInherit() bool {
	for _, permission := range e.Permissions {
		if permission == "only_inherit" {
			return true
		}
	}
	return false
}

func (e darwinACLEntry) grantsWrite() bool {
	for _, permission := range e.Permissions {
		if darwinACLWritePermissions[permission] {
			return true
		}
	}
	return false
}

// parseDarwinACLEntries reads the numbered ACL lines from `ls -lde` output.
// Lines that are not ACL entries (the long-listing line itself) are skipped.
// An allow or deny entry with no permission list is malformed output and is
// returned as a plain error, never as a permission verdict, so an ancestor
// downgrade cannot swallow an ACL that could not be read.
func parseDarwinACLEntries(path string, output []byte) ([]darwinACLEntry, error) {
	var entries []darwinACLEntry
	for _, line := range strings.Split(string(output), "\n") {
		normalized := strings.ToLower(strings.TrimSpace(line))
		colon := strings.IndexByte(normalized, ':')
		if colon <= 0 {
			continue
		}
		index, err := strconv.ParseUint(normalized[:colon], 10, 32)
		if err != nil {
			continue
		}
		fields := strings.Fields(normalized[colon+1:])
		entry := darwinACLEntry{Index: int(index)}
		verb := -1
		for i, field := range fields {
			if field == "allow" || field == "deny" {
				verb = i
				break
			}
		}
		if verb < 1 || verb+1 >= len(fields) {
			return nil, fmt.Errorf("cannot parse macOS ACL entry on %s: %q", path, strings.TrimSpace(line))
		}
		entry.Principal = fields[0]
		entry.Allow = fields[verb] == "allow"
		for _, qualifier := range fields[1:verb] {
			if qualifier == "inherited" {
				entry.Inherited = true
			}
		}
		entry.Permissions = strings.Split(fields[verb+1], ",")
		entries = append(entries, entry)
	}
	return entries, nil
}

// darwinACLJudgement is the R3 decision over one object's ACL.
type darwinACLJudgement struct {
	// Entries is the number of ACL entries; any entry at all is drift from
	// the canonical form, which carries none.
	Entries int
	// UntrustedWriters names principals other than root, wheel and admin that
	// an effective allow entry grants write-class rights.
	UntrustedWriters []string
	// InheritOnlyWriters names principals an inherit-only entry would grant
	// write to on new children. Drift, never a verdict on the object itself.
	InheritOnlyWriters []string
}

// judgeDarwinACLEntries decides on effective write authority for untrusted
// principals, not on exact equality: read entries, deny entries, inherit-only
// entries and entries for root, wheel or admin never make an object untrusted.
func judgeDarwinACLEntries(entries []darwinACLEntry) darwinACLJudgement {
	judgement := darwinACLJudgement{Entries: len(entries)}
	for _, entry := range entries {
		if !entry.Allow || !entry.grantsWrite() || darwinTrustedACLPrincipals[entry.Principal] {
			continue
		}
		if entry.onlyInherit() {
			judgement.InheritOnlyWriters = append(judgement.InheritOnlyWriters, entry.Principal)
			continue
		}
		judgement.UntrustedWriters = append(judgement.UntrustedWriters, entry.Principal)
	}
	return judgement
}

// JudgeDarwinACLOutput returns a permission verdict (see NewTrustVerdict) when
// `/bin/ls -lde` output for path shows an untrusted principal with effective
// write-class rights, nil when the ACL grants no such authority, and a plain
// error when the output cannot be parsed. Trust walks inside and outside this
// package share it so the macOS ACL rule cannot drift between them.
func JudgeDarwinACLOutput(path string, output []byte) error {
	entries, err := parseDarwinACLEntries(path, output)
	if err != nil {
		return err
	}
	judgement := judgeDarwinACLEntries(entries)
	if len(judgement.UntrustedWriters) > 0 {
		return newTrustVerdict("%s has a write-capable macOS ACL entry for %s", path, strings.Join(judgement.UntrustedWriters, ","))
	}
	return nil
}

// JudgeDarwinACLOutputStrict is the standalone profile's rule over the same
// `/bin/ls -lde` output: any allow entry with a write-class right is a
// permission verdict, whatever principal it names, inherit-only entries
// included. Output that cannot be parsed is a plain error.
func JudgeDarwinACLOutputStrict(path string, output []byte) error {
	entries, err := ParseDarwinACLListing(string(output), []string{path})
	if err != nil {
		// Malformed `ls -lde` output is not a judgement about the permissions
		// themselves. Keep it a plain error so the ancestor downgrade cannot
		// swallow an ACL this code failed to read (see
		// relaxAncestorTrustJudgement).
		return fmt.Errorf("inspect macOS ACL: %w", err)
	}
	for _, entry := range entries[path] {
		if entry.GrantsWrite() {
			return newTrustVerdict("%s has write-capable macOS ACL entry", path)
		}
	}
	return nil
}

// JudgeDarwinACLOutputForAccount is the rule for a path the account itself
// owns (its own configuration folders): the strict rule of
// JudgeDarwinACLOutputStrict, except that an allow entry for root, wheel,
// admin or the account itself is not judged. Those principals can change the
// path whatever its list says, so the entry adds no authority; an entry for
// any other principal, "everyone" and inherit-only entries included, is a
// permission verdict. Output that cannot be parsed is a plain error.
func JudgeDarwinACLOutputForAccount(path string, output []byte, account string) error {
	entries, err := parseDarwinACLEntries(path, output)
	if err != nil {
		return err
	}
	self := ""
	if account != "" {
		self = "user:" + strings.ToLower(account)
	}
	var writers []string
	for _, entry := range entries {
		if !entry.Allow || !entry.grantsWrite() || darwinTrustedACLPrincipals[entry.Principal] || entry.Principal == self {
			continue
		}
		writers = append(writers, entry.Principal)
	}
	if len(writers) > 0 {
		return newTrustVerdict("%s has a write-capable macOS ACL entry for %s", path, strings.Join(writers, ","))
	}
	return nil
}
