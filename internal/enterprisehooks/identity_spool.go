// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// The identity spool.
//
// Some verified directory facts can only be read with privilege: SSSD
// InfoPipe answers root only, the gateway's sandbox hides /proc and user
// homes, and on Windows the token-group cache is SYSTEM-only. The root
// guardian (Linux, macOS) or SYSTEM enumerator (Windows) resolves them for
// each enrolled account and writes one record per account, <uid>.json or
// <SID>.json, in the identity directory under the guardian authorization
// directory: owned by root or SYSTEM and readable by the gateway's group,
// exactly like the AI discovery user-scan spool. The gateway merges a record
// into the facts it resolves itself for the same verified uid or SID.

// IdentitySpoolDirName is the spool directory under the guardian
// authorization directory.
const IdentitySpoolDirName = "identity"

// IdentitySpoolRecordVersion is the record schema version.
const IdentitySpoolRecordVersion = 1

// IdentitySpoolMaxAge is how long the gateway trusts a record (four times the
// 15 minute identity cache lifetime) and how long the guardian keeps the
// record of an account it no longer lists.
const IdentitySpoolMaxAge = time.Hour

// maxIdentitySpoolRecordBytes bounds one record.
const maxIdentitySpoolRecordBytes = 256 << 10

// UPN sources recorded in IdentitySpoolRecord.UPNSource.
const (
	UPNSourceInfoPipe      = "infopipe"
	UPNSourceDerived       = "derived"
	UPNSourceIdentityStore = "identity_store"
	UPNSourceTranslateName = "translate_name"
)

// IdentitySpoolRecord is one account's spool file.
type IdentitySpoolRecord struct {
	Version int `json:"version"`
	// Key is the uid (Linux, macOS) or SID (Windows) the record is for; it
	// must match the file name.
	Key       string    `json:"key"`
	User      string    `json:"user,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
	// UPNSource says where Facts.UPN, or the derived Facts.Principal, came
	// from: infopipe, identity_store, translate_name, or derived (the
	// sAMAccountName@REALM fallback; Facts.UPN is then empty).
	UPNSource string `json:"upn_source,omitempty"`
	// SSSDDomain is the SSSD domain that holds the uid by InfoPipe
	// Users.FindByID (Linux): the gateway drops a domain, realm and
	// principal of its own that name another domain (mergeSpoolFacts).
	SSSDDomain string                      `json:"sssd_domain,omitempty"`
	Facts      useridentity.DirectoryFacts `json:"facts"`
}

// IdentitySpoolDir is the spool directory for a guardian authorization
// directory.
func IdentitySpoolDir(authorizationDir string) string {
	if strings.TrimSpace(authorizationDir) == "" {
		return ""
	}
	return filepath.Join(authorizationDir, IdentitySpoolDirName)
}

// ReadIdentitySpoolRecord reads the record for key from dir. trust validates
// the file (root- or SYSTEM-owned, not writable by others) before it is
// opened. A missing record is os.ErrNotExist.
func ReadIdentitySpoolRecord(dir, key string, trust func(path, label string) error) (IdentitySpoolRecord, error) {
	var record IdentitySpoolRecord
	key = strings.TrimSpace(key)
	if dir == "" || !validIdentitySpoolKey(key) {
		return record, os.ErrNotExist
	}
	path := filepath.Join(dir, key+".json")
	info, err := os.Lstat(path)
	if err != nil {
		return record, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxIdentitySpoolRecordBytes {
		return record, errors.New("identity spool record is not a regular file within the size limit")
	}
	if trust != nil {
		if err := trust(path, "identity spool record"); err != nil {
			return record, err
		}
	}
	file, err := os.Open(path)
	if err != nil {
		return record, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxIdentitySpoolRecordBytes+1))
	if err != nil {
		return record, err
	}
	return ParseIdentitySpoolRecord(data, key)
}

// ParseIdentitySpoolRecord decodes a record and checks it names key.
func ParseIdentitySpoolRecord(data []byte, key string) (IdentitySpoolRecord, error) {
	var record IdentitySpoolRecord
	if len(data) > maxIdentitySpoolRecordBytes {
		return record, errors.New("identity spool record exceeds the size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return record, fmt.Errorf("parse identity spool record: %w", err)
	}
	if record.Version != IdentitySpoolRecordVersion {
		return record, fmt.Errorf("unsupported identity spool record version %d", record.Version)
	}
	if !strings.EqualFold(record.Key, key) {
		return record, errors.New("identity spool record names another account")
	}
	record.Facts.Assurance = useridentity.AssuranceVerified
	return record, nil
}

// KeepLastKnownUPN carries the UPN of the account's previous record into a
// fresh record that resolved none, with the principal it gave. Windows
// resolves a UPN only while the user is signed in, so without it a signed-out
// account's record fell back to account@REALM and the account showed two
// principals (GAP-0284). The SID or uid is the record key, so the previous
// record is the same account.
func KeepLastKnownUPN(record, previous IdentitySpoolRecord) IdentitySpoolRecord {
	if record.Facts.UPN != "" || previous.Facts.UPN == "" || !strings.EqualFold(record.Key, previous.Key) {
		return record
	}
	record.Facts.UPN = previous.Facts.UPN
	record.Facts.Principal = previous.Facts.UPN
	record.UPNSource = previous.UPNSource
	if record.Facts.Domain == "" {
		record.Facts.Domain = previous.Facts.Domain
	}
	return record
}

// MarshalIdentitySpoolRecord serializes a record.
func MarshalIdentitySpoolRecord(record IdentitySpoolRecord) ([]byte, error) {
	record.Version = IdentitySpoolRecordVersion
	return json.Marshal(record)
}

// validIdentitySpoolKey accepts a decimal uid or a SID.
func validIdentitySpoolKey(key string) bool {
	if key == "" || len(key) > 184 {
		return false
	}
	if strings.HasPrefix(strings.ToUpper(key), "S-1-") {
		for i := 4; i < len(key); i++ {
			if c := key[i]; !(c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
		return true
	}
	for i := 0; i < len(key); i++ {
		if key[i] < '0' || key[i] > '9' {
			return false
		}
	}
	return true
}

// writeIdentitySpoolFile replaces dir/name atomically with its final mode
// and ownership set before the rename.
func writeIdentitySpoolFile(dir, name string, record IdentitySpoolRecord, setOwnership func(string) error) error {
	data, err := MarshalIdentitySpoolRecord(record)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".identity-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Chmod(0o640)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err == nil && setOwnership != nil {
		err = setOwnership(tmpName)
	}
	if err == nil {
		err = os.Rename(tmpName, filepath.Join(dir, name))
	}
	return err
}
