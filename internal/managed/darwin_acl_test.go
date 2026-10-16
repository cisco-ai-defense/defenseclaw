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

import "testing"

// GAP-1323: a repair removes single entries with `chmod -a# <index>`, so
// the parsed entries carry the index ls printed.
func TestParseDarwinACLListingKeepsTheEntryIndex(t *testing.T) {
	listing := "drwxr-xr-x+ 3 root  wheel  96 Oct 13 06:00 /Library/Application Support/ClaudeCode\n" +
		" 0: user:admin allow read,write\n" +
		" 1: group:everyone deny list,search\n" +
		" 12: group:staff inherited deny search,file_inherit\n"
	listed, err := ParseDarwinACLListing(listing, []string{"/Library/Application Support/ClaudeCode"})
	if err != nil {
		t.Fatal(err)
	}
	entries := listed["/Library/Application Support/ClaudeCode"]
	if len(entries) != 3 || entries[0].Index != 0 || entries[1].Index != 1 || entries[2].Index != 12 ||
		entries[1].Text != "group:everyone deny list,search" || !entries[2].DeniesDirectoryAccess(false) {
		t.Fatalf("entries = %+v", entries)
	}
}
