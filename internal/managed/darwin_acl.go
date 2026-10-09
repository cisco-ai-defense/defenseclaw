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

// DarwinACLEntry is one entry of a macOS access control list as
// `/bin/ls -le` prints it, for example "user:alice allow write,append".
// macOS grants an entry without changing the owner or the mode bits, so a
// check of those alone reads a path another account can change (or read)
// as trusted.
type DarwinACLEntry struct {
	// Text is the entry without its index ("group:staff inherited allow
	// read"), for messages.
	Text string
	// Allow is false for a deny entry.
	Allow bool
	// Rights are the rights and inheritance flags of the entry.
	Rights []string
}

// darwinACLWriteRights let a principal change a file or folder, or its
// owner, mode or ACL.
var darwinACLWriteRights = map[string]bool{
	"write": true, "add_file": true, "append": true, "add_subdirectory": true, "delete": true,
	"delete_child": true, "writeattr": true, "writeextattr": true, "writesecurity": true, "chown": true,
}

// darwinACLFlags are inheritance flags, not rights.
var darwinACLFlags = map[string]bool{
	"file_inherit": true, "directory_inherit": true, "limit_inherit": true, "only_inherit": true,
}

// GrantsWrite reports an allow entry with a write-capable right.
func (e DarwinACLEntry) GrantsWrite() bool {
	if !e.Allow {
		return false
	}
	for _, right := range e.Rights {
		if darwinACLWriteRights[right] {
			return true
		}
	}
	return false
}

// GrantsAccess reports an allow entry with any right, read-only ones
// included: on a path whose mode gives other accounts no access, such an
// entry is the only way another account reaches it.
func (e DarwinACLEntry) GrantsAccess() bool {
	if !e.Allow {
		return false
	}
	for _, right := range e.Rights {
		if !darwinACLFlags[right] {
			return true
		}
	}
	return false
}

// DeniesDirectoryAccess reports a deny entry that stops a user from
// traversing a published policy directory or, for a drop-in directory,
// listing its policy files. Inherited-only entries do not affect this path.
func (e DarwinACLEntry) DeniesDirectoryAccess(requireList bool) bool {
	if e.Allow {
		return false
	}
	for _, right := range e.Rights {
		if right == "only_inherit" {
			return false
		}
	}
	for _, right := range e.Rights {
		if right == "search" || (requireList && (right == "list" || right == "read")) {
			return true
		}
	}
	return false
}

// DeniesFileRead reports a deny entry that prevents an agent from reading a
// published policy file. Inherited-only entries do not affect this file.
func (e DarwinACLEntry) DeniesFileRead() bool {
	if e.Allow {
		return false
	}
	for _, right := range e.Rights {
		if right == "only_inherit" {
			return false
		}
	}
	for _, right := range e.Rights {
		if right == "read" {
			return true
		}
	}
	return false
}

// ParseDarwinACLListing reads what `/bin/ls -lde -- <paths>` printed: the
// ACL entries of each listed path, by the path as it was passed. ls prints a
// line per path that ends with the path, followed by one indented
// "N: <entry>" line per ACL entry. A path ls did not list (it is gone) is
// absent from the map; one it listed without an ACL maps to no entries. With
// a single path every entry belongs to it.
func ParseDarwinACLListing(output string, paths []string) (map[string][]DarwinACLEntry, error) {
	listed := map[string][]DarwinACLEntry{}
	current := ""
	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if rest, ok := darwinACLLine(line); ok {
			if current == "" {
				continue
			}
			entry, err := parseDarwinACLEntry(rest)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", current, err)
			}
			listed[current] = append(listed[current], entry)
			continue
		}
		current = ""
		for _, path := range paths {
			if (len(paths) == 1 || strings.HasSuffix(line, " "+path)) && len(path) > len(current) {
				current = path
			}
		}
		if _, seen := listed[current]; current != "" && !seen {
			listed[current] = nil
		}
	}
	return listed, nil
}

// darwinACLLine returns the entry of an ACL line (" 0: user:alice allow
// write").
func darwinACLLine(line string) (string, bool) {
	trimmed := strings.TrimSpace(line)
	index, rest, found := strings.Cut(trimmed, ":")
	if !found || index == "" {
		return "", false
	}
	if _, err := strconv.ParseUint(index, 10, 32); err != nil {
		return "", false
	}
	return strings.TrimSpace(rest), true
}

func parseDarwinACLEntry(text string) (DarwinACLEntry, error) {
	normalized := strings.ToLower(text)
	allow, deny := strings.LastIndex(normalized, " allow "), strings.LastIndex(normalized, " deny ")
	entry := DarwinACLEntry{Text: text}
	rights := ""
	switch {
	case allow > deny:
		entry.Allow, rights = true, normalized[allow+len(" allow "):]
	case deny >= 0:
		rights = normalized[deny+len(" deny "):]
	}
	fields := strings.Fields(rights)
	if len(fields) == 0 {
		return DarwinACLEntry{}, fmt.Errorf("cannot parse macOS ACL entry %q", text)
	}
	for _, right := range strings.Split(fields[0], ",") {
		if right = strings.TrimSpace(right); right != "" {
			entry.Rights = append(entry.Rights, right)
		}
	}
	return entry, nil
}
