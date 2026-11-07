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
	"encoding/json"
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
// list and no error; a directory that does not answer, an answer the system
// property list tool does not convert and every platform other than macOS are
// an error, so a caller never takes them for a free home.
func AccountsAtHome(ctx context.Context, home string) ([]HomeAccount, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(home) == "" || strings.ContainsAny(home, "\n\x00") {
		return nil, errors.New("unixidentity: invalid home")
	}
	return platformAccountsAtHome(ctx, home)
}

// errUnclearHomeAnswer is the one error for an answer that does not prove
// who holds a home: the home stays pending and its holders stay kept.
var errUnclearHomeAnswer = errors.New("unixidentity: unclear account record answer")

// dsclHomeAccounts decides AccountsAtHome from the structured answer of
// `dscl -plist /Search -readall /Users UniqueID NFSHomeDirectory RecordName`.
// The plist is not read here: toJSON converts it with the system tool
// (`plutil -convert json -o - -`), and only that tool's JSON is read, with
// strict types. A failed read, a failed conversion, output that is not the
// expected structure and a record missing a field are errors, never an empty
// list. It is shared so it can be tested on every platform.
func dsclHomeAccounts(home string, readall func() (commandResult, error), toJSON func(plist []byte) (commandResult, error)) ([]HomeAccount, error) {
	result, err := readall()
	if err != nil {
		return nil, err
	}
	if result.exitCode != 0 {
		return nil, fmt.Errorf("unixidentity: dscl exited %d", result.exitCode)
	}
	converted, err := toJSON(result.stdout)
	if err != nil {
		return nil, err
	}
	if converted.exitCode != 0 {
		return nil, fmt.Errorf("unixidentity: plutil exited %d", converted.exitCode)
	}
	records, err := parseDSCLHomeRecords(converted.stdout)
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

// dsclHomeRecord is one account record of the answer.
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

const (
	dsclHomeKeyUID  = "dsAttrTypeStandard:UniqueID"
	dsclHomeKeyHome = "dsAttrTypeStandard:NFSHomeDirectory"
	dsclHomeKeyName = "dsAttrTypeStandard:RecordName"
)

// parseDSCLHomeRecords reads the JSON the system tool made of the answer: one
// array of objects, each with the UniqueID, NFSHomeDirectory and RecordName
// fields as non-empty arrays of non-empty strings (UniqueID exactly one),
// followed by nothing. Anything else (not JSON, cut short, text after it, an
// object where an array belongs, a field of another type, a repeated field,
// a record missing a field) is an error.
func parseDSCLHomeRecords(output []byte) ([]dsclHomeRecord, error) {
	decoder := json.NewDecoder(bytes.NewReader(output))
	if !jsonDelim(decoder, '[') {
		return nil, errUnclearHomeAnswer
	}
	records := []dsclHomeRecord{}
	for decoder.More() {
		fields, ok := jsonRecordFields(decoder)
		if !ok {
			return nil, errUnclearHomeAnswer
		}
		record, ok := dsclHomeRecordOf(fields)
		if !ok {
			return nil, errUnclearHomeAnswer
		}
		records = append(records, record)
	}
	if !jsonDelim(decoder, ']') {
		return nil, errUnclearHomeAnswer
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errUnclearHomeAnswer
	}
	return records, nil
}

// jsonDelim reads the next token and reports whether it is want.
func jsonDelim(decoder *json.Decoder, want json.Delim) bool {
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	got, ok := token.(json.Delim)
	return ok && got == want
}

// jsonRecordFields reads one object whose every value is an array of
// strings. A repeated key, which a map would silently resolve, and a null or
// another type are not accepted.
func jsonRecordFields(decoder *json.Decoder) (map[string][]string, bool) {
	if !jsonDelim(decoder, '{') {
		return nil, false
	}
	fields := map[string][]string{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, false
		}
		key, ok := token.(string)
		if !ok {
			return nil, false
		}
		if _, repeated := fields[key]; repeated {
			return nil, false
		}
		var values []string
		if err := decoder.Decode(&values); err != nil || values == nil {
			return nil, false
		}
		fields[key] = values
	}
	return fields, jsonDelim(decoder, '}')
}

// dsclHomeRecordOf checks the fields of one record.
func dsclHomeRecordOf(fields map[string][]string) (dsclHomeRecord, bool) {
	for _, values := range fields {
		for _, value := range values {
			if strings.TrimSpace(value) == "" {
				return dsclHomeRecord{}, false
			}
		}
	}
	uids, homes, names := fields[dsclHomeKeyUID], fields[dsclHomeKeyHome], fields[dsclHomeKeyName]
	if len(uids) != 1 || len(homes) == 0 || len(names) == 0 || validName(strings.TrimSpace(names[0])) != nil {
		return dsclHomeRecord{}, false
	}
	uid, err := parseSignedDSCLID(strings.TrimSpace(uids[0]))
	if err != nil {
		return dsclHomeRecord{}, false
	}
	for i := range homes {
		homes[i] = strings.TrimSpace(homes[i])
	}
	return dsclHomeRecord{name: strings.TrimSpace(names[0]), uid: uid, homes: homes}, true
}
