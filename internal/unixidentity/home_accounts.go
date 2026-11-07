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
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

// HomeAccount is a live account found at a home folder: its name and uid.
type HomeAccount struct {
	Name string
	UID  int
}

// homeAccountsLimit bounds the accounts read for one home.
const homeAccountsLimit = 32

// AccountsAtHome lists the accounts a fresh read across the whole directory
// search policy (local and bound directory nodes) finds with home as their
// home folder, in a fresh process. It is how a caller learns who holds the
// home of an account that has gone: a replacement may be a local account or a
// directory account, and its name and uid are its own. No account is an empty
// list and no error; a directory that does not answer, an answer that is not
// a complete property list and every platform other than macOS are an error,
// so a caller never takes them for a free home.
func AccountsAtHome(ctx context.Context, home string) ([]HomeAccount, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(home) == "" || strings.ContainsAny(home, "\n\x00") {
		return nil, errors.New("unixidentity: invalid home")
	}
	return platformAccountsAtHome(ctx, home)
}

// dsclHomeAccounts decides AccountsAtHome from the structured answer of
// `dscl -plist /Search -readall /Users UniqueID NFSHomeDirectory RecordName`.
// It is shared so it can be tested on every platform. The answer must be one
// complete property list in which every record carries the three fields; any
// other answer (truncated, odd, a record missing a field) is an error, never
// an empty list.
func dsclHomeAccounts(home string, readall func() (commandResult, error)) ([]HomeAccount, error) {
	result, err := readall()
	if err != nil {
		return nil, err
	}
	if result.exitCode != 0 {
		return nil, fmt.Errorf("unixidentity: dscl exited %d", result.exitCode)
	}
	records, err := parseDSCLHomeRecords(result.stdout)
	if err != nil {
		return nil, err
	}
	var accounts []HomeAccount
	for _, record := range records {
		if !record.holds(home) {
			continue
		}
		if len(accounts) >= homeAccountsLimit {
			return nil, errors.New("unixidentity: too many accounts at one home")
		}
		accounts = append(accounts, HomeAccount{Name: record.name, UID: record.uid})
	}
	return accounts, nil
}

// dsclHomeRecord is one account record of the plist answer.
type dsclHomeRecord struct {
	name  string
	uid   int
	homes []string
}

// holds reports whether home is one of the home folders of the record.
func (r dsclHomeRecord) holds(home string) bool {
	want := comparableHome(home)
	for _, candidate := range r.homes {
		if comparableHome(candidate) == want {
			return true
		}
	}
	return false
}

// comparableHome is a home path in the one spelling used to compare two:
// cleaned, with the /private prefix of the firmlinked /var, /etc and /tmp
// dropped.
func comparableHome(path string) string {
	path = filepath.Clean(path)
	for _, link := range []string{"/var", "/etc", "/tmp"} {
		if rest, ok := strings.CutPrefix(path, "/private"+link); ok && (rest == "" || strings.HasPrefix(rest, "/")) {
			return link + rest
		}
	}
	return path
}

// plistNode is an XML element with its text and child elements.
type plistNode struct {
	XMLName  xml.Name
	Text     string      `xml:",chardata"`
	Children []plistNode `xml:",any"`
}

// onlyElements reports whether the node holds nothing but white space between
// its child elements. Text beside the elements of a container is not part of
// a property list, so the answer is not one complete list.
func (n plistNode) onlyElements() bool { return strings.TrimSpace(n.Text) == "" }

const (
	dsclHomeKeyUID  = "dsAttrTypeStandard:UniqueID"
	dsclHomeKeyHome = "dsAttrTypeStandard:NFSHomeDirectory"
	dsclHomeKeyName = "dsAttrTypeStandard:RecordName"
)

// parseDSCLHomeRecords reads the plist answer: one <plist> holding one
// <array> of <dict> records, each with the UniqueID, NFSHomeDirectory and
// RecordName fields as non-empty arrays of strings (UniqueID exactly one). A
// document that does not end where it should, an element that is not where
// the format puts it, text beside the elements of a container and a record
// missing a field are errors.
func parseDSCLHomeRecords(output []byte) ([]dsclHomeRecord, error) {
	unclear := errors.New("unixidentity: unclear account record answer")
	decoder := xml.NewDecoder(strings.NewReader(string(output)))
	var root plistNode
	if err := decoder.Decode(&root); err != nil || root.XMLName.Local != "plist" {
		return nil, unclear
	}
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, unclear
		}
		switch t := token.(type) {
		case xml.Comment:
		case xml.CharData:
			if strings.TrimSpace(string(t)) != "" {
				return nil, unclear
			}
		default:
			return nil, unclear
		}
	}
	if !root.onlyElements() || len(root.Children) != 1 || root.Children[0].XMLName.Local != "array" || !root.Children[0].onlyElements() {
		return nil, unclear
	}
	var records []dsclHomeRecord
	for _, dict := range root.Children[0].Children {
		record, ok := dsclHomeRecordOf(dict)
		if !ok {
			return nil, unclear
		}
		records = append(records, record)
	}
	return records, nil
}

// dsclHomeRecordOf reads one <dict> record.
func dsclHomeRecordOf(dict plistNode) (dsclHomeRecord, bool) {
	if dict.XMLName.Local != "dict" || !dict.onlyElements() || len(dict.Children)%2 != 0 {
		return dsclHomeRecord{}, false
	}
	fields := map[string][]string{}
	for i := 0; i < len(dict.Children); i += 2 {
		key, value := dict.Children[i], dict.Children[i+1]
		if key.XMLName.Local != "key" || len(key.Children) != 0 || value.XMLName.Local != "array" || !value.onlyElements() {
			return dsclHomeRecord{}, false
		}
		name := strings.TrimSpace(key.Text)
		if _, repeated := fields[name]; repeated {
			return dsclHomeRecord{}, false
		}
		var values []string
		for _, item := range value.Children {
			if item.XMLName.Local != "string" || len(item.Children) != 0 || strings.TrimSpace(item.Text) == "" {
				return dsclHomeRecord{}, false
			}
			values = append(values, strings.TrimSpace(item.Text))
		}
		fields[name] = values
	}
	uids, homes, names := fields[dsclHomeKeyUID], fields[dsclHomeKeyHome], fields[dsclHomeKeyName]
	if len(uids) != 1 || len(homes) == 0 || len(names) == 0 || validName(names[0]) != nil {
		return dsclHomeRecord{}, false
	}
	uid, err := parseSignedDSCLID(uids[0])
	if err != nil {
		return dsclHomeRecord{}, false
	}
	return dsclHomeRecord{name: names[0], uid: uid, homes: homes}, true
}
