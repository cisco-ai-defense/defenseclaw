//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// The four `dscl . -list /Users <attribute>` listings that
// platformLocalAccountRecords ran before rel-1-0-6 GAP-0326, parsed as they
// were: one "name value" row per record, the value trimmed.
func listedDSCLAttribute(output string) map[string]string {
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

func listedDSCLAccountRecords(uids, recordIDs, homes, gids map[string]string) map[string]LocalAccountRecord {
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

// listingStamp mirrors the gateway's localAccountsListing and
// accountRecordToken: the account database stamp and each account's record
// token.
func listingStamp(accounts map[string]LocalAccountRecord) (string, map[string]string) {
	names := make([]string, 0, len(accounts))
	for name := range accounts {
		names = append(names, name)
	}
	sort.Strings(names)
	sum, tokens := sha256.New(), map[string]string{}
	for _, name := range names {
		a := accounts[name]
		record := fmt.Sprintf("%d\x00%s\x00%s\x00%s", a.UID, a.RecordID, a.Home, a.PrimaryGID)
		fmt.Fprintf(sum, "%s\x00%s\n", name, record)
		token := sha256.Sum256([]byte(record))
		tokens[name] = "record:" + hex.EncodeToString(token[:16])
	}
	return hex.EncodeToString(sum.Sum(nil)[:16]), tokens
}

// rel-1-0-6 GAP-0326: one `dscl -plist . -readall` gives the same records,
// stamp and record tokens as the four listings it replaced. The fixtures are
// the output of both commands on macOS 15 for stock accounts and synthetic
// ones (names changed): a uid above int32 and a negative one, a multi-valued
// UniqueID (dropped by both), a multi-valued home and gid (joined by both), a
// record without GeneratedUID, home and gid, an alias RecordName, a hidden
// record, a non-ASCII name and home, a home with a space, & and <>, a gid
// stored with spaces; c2 is c1 after alice was deleted and created again
// under the same name, uid and home.
func TestDSCLReadallMatchesTheFourListings(t *testing.T) {
	read := func(name string) string {
		body, err := os.ReadFile(filepath.Join("testdata", "dscl-listing", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	stamps, tokens := map[string]string{}, map[string]map[string]string{}
	for _, tag := range []string{"c1", "c2"} {
		listed := listedDSCLAccountRecords(
			listedDSCLAttribute(read(tag+"-list-UniqueID.txt")),
			listedDSCLAttribute(read(tag+"-list-GeneratedUID.txt")),
			listedDSCLAttribute(read(tag+"-list-NFSHomeDirectory.txt")),
			listedDSCLAttribute(read(tag+"-list-PrimaryGroupID.txt")))
		readall, err := parseDSCLAccountRecordsPlist([]byte(read(tag + "-plist.xml")))
		if err != nil {
			t.Fatalf("%s: %v", tag, err)
		}
		if len(listed) < 9 || !reflect.DeepEqual(listed, readall) {
			t.Fatalf("%s: listings %+v\nreadall %+v", tag, listed, readall)
		}
		if _, ok := readall["carol"]; ok {
			t.Fatalf("%s: carol, with two uids, was kept: %+v", tag, readall["carol"])
		}
		if got := readall["dave"]; got.Home != "/var/empty/d1 /var/empty/d 2" || got.PrimaryGID != "20 21" {
			t.Fatalf("%s: dave = %+v; want both homes and gids joined", tag, got)
		}
		stampListed, tokensListed := listingStamp(listed)
		stamps[tag], tokens[tag] = listingStamp(readall)
		if stampListed != stamps[tag] || !reflect.DeepEqual(tokensListed, tokens[tag]) {
			t.Fatalf("%s: stamp or record tokens differ", tag)
		}
	}
	if stamps["c1"] == stamps["c2"] || tokens["c1"]["alice"] == tokens["c2"]["alice"] {
		t.Fatal("alice deleted and created again did not change the stamp and her record token (GAP-0392)")
	}
	if tokens["c1"]["dave"] != tokens["c2"]["dave"] {
		t.Fatal("an unchanged account changed its record token")
	}
}
