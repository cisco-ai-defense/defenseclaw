// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

// The migration map of the upgrade to 1.0.4: which account incarnation held
// each uid when the upgrade ran (Linux, macOS).
//
// DefenseClaw 1.0.0 to 1.0.3 keyed a uid's agent identities on the bare
// account name only (agentidentity.LegacyAgentID), so a guardrail profile
// assignment's agents entry written for one of them cannot tell the account
// it was written for from a later account given the same uid and name, or
// a namesake of another domain. At its first identity pass after the
// upgrade, while the 1.0.x identities are still the ones in use, the root
// guardian records the account that holds each uid it enrolls: its name as
// the host gives it, and a token of the incarnation (LegacyAgentOwnerToken).
// The file is written once, never changed, owned by the guardian
// authorization and read by the gateway only after that trust check. A
// legacy entry then keeps applying to the account the map records, and to
// no other; a request of an account the map does not record is refused,
// naming the unproven agent ownership (the gateway's selectProfile).
// Windows needs no map: 1.0.x keyed its identities on the SID, which is
// what they are keyed on now. Remove with agentidentity.LegacyAgentID.

// LegacyAgentOwnersFile is the file of the identity spool that holds the
// migration map.
const LegacyAgentOwnersFile = "legacy-agent-owners.map"

// Builds before 1.0.4 stored the map beside uid.json records. Published
// 1.0.2 reads that name as a uid after rollback, so the root guardian moves
// an existing map out of the record namespace before its next pass.
const oldLegacyAgentOwnersFile = "legacy-agent-owners.json"

var legacyAgentOwnersOpen = os.Open

const (
	legacyAgentOwnersVersion = 1
	maxLegacyAgentOwners     = 65536
	// maxLegacyAgentOwnerField bounds the bytes of an owner's user and of
	// its token (validLegacyAgentOwner).
	maxLegacyAgentOwnerField = 256
	// maxLegacyAgentOwnersBytes is the largest map WriteLegacyAgentOwners
	// can write, and the largest the reader takes. The map is written once,
	// so a map the reader refused would leave every legacy agents entry
	// unbound for good. It is the header with the longest time plus
	// maxLegacyAgentOwners entries with the longest uid, user and token, a
	// byte of which json.Marshal spells in at most six (\u003c for <, > and
	// &; earlier 1.0.4 builds also wrote \ufffd for a byte that is not
	// UTF-8). A map of real account names is far smaller (about 8 MiB for
	// 65,536 qualified AD accounts).
	maxLegacyAgentOwnersBytes    = int64(legacyAgentOwnersHeaderBytes + maxLegacyAgentOwners*legacyAgentOwnerEntryBytes)
	legacyAgentOwnersHeaderBytes = len(`{"v":1,"written_at":"","owners":{}}`) + len("9999-12-31T23:59:59.999999999Z")
	legacyAgentOwnerEntryBytes   = len(`"":{"user":"","token":""},`) + len("9223372036854775807") + 2*6*maxLegacyAgentOwnerField
)

// LegacyAgentOwner is the account that held a uid at the upgrade.
type LegacyAgentOwner struct {
	// User is the account name as the host gave it (an SSSD account may be
	// qualified, alice@corp.example).
	User string `json:"user"`
	// Token is LegacyAgentOwnerToken of the account.
	Token string `json:"token"`
}

type legacyAgentOwnersDoc struct {
	Version   int                         `json:"v"`
	WrittenAt time.Time                   `json:"written_at"`
	Owners    map[string]LegacyAgentOwner `json:"owners"`
}

// LegacyAgentOwnerToken names one account incarnation: the SID SSSD or
// winbind holds for the uid (incarnation, unixidentity's AccountIncarnation
// "sid:..."), which an account created again never keeps; otherwise the
// identity of its home directory (device, inode and, where the file system
// keeps it, creation time), which a new account's home does not share with a
// removed one's, even when the file system hands it the freed inode. An
// account created again over the very same home directory keeps it. "" when
// neither is known.
func LegacyAgentOwnerToken(incarnation, home string) string {
	if sid, ok := strings.CutPrefix(strings.TrimSpace(incarnation), "sid:"); ok && sid != "" {
		return "sid:" + strings.ToUpper(sid)
	}
	home = strings.TrimSpace(home)
	if home == "" || !filepath.IsAbs(home) {
		return ""
	}
	info, err := os.Stat(home)
	if err != nil || !info.IsDir() {
		return ""
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	token := "home:" + strconv.FormatUint(uint64(st.Dev), 10) + ":" + strconv.FormatUint(uint64(st.Ino), 10)
	if birth, ok := homeBirth(home); ok {
		token += ":" + strconv.FormatInt(birth, 10)
	}
	return token
}

// LegacyAgentOwnersRecorded reports whether dir holds the migration map.
func LegacyAgentOwnersRecorded(dir string) bool {
	if dir == "" {
		return false
	}
	_, err := os.Lstat(filepath.Join(dir, LegacyAgentOwnersFile))
	return err == nil
}

// WriteLegacyAgentOwners writes the migration map owners (by uid) to dir
// once: an existing map is kept as it is, and an empty one is not written,
// so the next pass tries again. setOwnership gives the file the guardian
// authorization ownership before it is renamed into place. Every map it
// writes is within maxLegacyAgentOwnersBytes, the reader's bound.
func WriteLegacyAgentOwners(dir string, owners map[int]LegacyAgentOwner, now time.Time, setOwnership func(string) error) (bool, error) {
	if dir == "" {
		return false, nil
	}
	if _, err := moveLegacyAgentOwners(dir); err != nil {
		return false, err
	}
	if LegacyAgentOwnersRecorded(dir) {
		return false, nil
	}
	doc := legacyAgentOwnersDoc{Version: legacyAgentOwnersVersion, WrittenAt: now.UTC(), Owners: map[string]LegacyAgentOwner{}}
	for uid, owner := range owners {
		if uid < 0 || !validLegacyAgentOwner(owner) || len(doc.Owners) >= maxLegacyAgentOwners {
			continue
		}
		doc.Owners[strconv.Itoa(uid)] = owner
	}
	if len(doc.Owners) == 0 {
		return false, nil
	}
	data, err := json.Marshal(doc)
	if err != nil {
		return false, err
	}
	if err := writeSpoolBytes(dir, LegacyAgentOwnersFile, ".legacy-agents-*", data, setOwnership); err != nil {
		return false, err
	}
	return true, nil
}

// ReadLegacyAgentOwners returns the migration map of dir by uid, when the
// file exists and trust accepts it; false otherwise.
func ReadLegacyAgentOwners(dir string, trust func(path, label string) error) (map[int]LegacyAgentOwner, bool) {
	if dir == "" {
		return nil, false
	}
	if owners, ok, _ := readLegacyAgentOwnersFile(filepath.Join(dir, LegacyAgentOwnersFile), trust); ok {
		return owners, true
	}
	// A guardian already running before this upgrade may not have moved its
	// old map yet. Keep its agent assignments working during that handoff.
	owners, ok, _ := readLegacyAgentOwnersFile(filepath.Join(dir, oldLegacyAgentOwnersFile), trust)
	return owners, ok
}

// A false result with no error means the bytes cannot be a migration map.
// I/O and trust errors are distinct so the guardian never moves a valid map
// aside merely because it could not read it on this pass.
func readLegacyAgentOwnersFile(path string, trust func(path, label string) error) (map[int]LegacyAgentOwner, bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, false, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxLegacyAgentOwnersBytes {
		return nil, false, nil
	}
	if trust != nil {
		if err := trust(path, "agent identity migration map"); err != nil {
			return nil, false, err
		}
	}
	file, err := legacyAgentOwnersOpen(path)
	if err != nil {
		return nil, false, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxLegacyAgentOwnersBytes+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > maxLegacyAgentOwnersBytes {
		return nil, false, nil
	}
	var doc legacyAgentOwnersDoc
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&doc) != nil || doc.Version != legacyAgentOwnersVersion {
		return nil, false, nil
	}
	out := make(map[int]LegacyAgentOwner, len(doc.Owners))
	for key, owner := range doc.Owners {
		uid, err := strconv.Atoi(key)
		if err != nil || uid < 0 || strconv.Itoa(uid) != key || !validLegacyAgentOwner(owner) {
			continue
		}
		out[uid] = owner
	}
	return out, true, nil
}

// moveLegacyAgentOwners moves a valid previous map to its rollback-safe
// name. An invalid map proves no account binding; quarantine it so the
// guardian can publish fresh records and, when possible, a new map.
func moveLegacyAgentOwners(dir string) (invalid bool, err error) {
	oldPath := filepath.Join(dir, oldLegacyAgentOwnersFile)
	if _, err := os.Lstat(oldPath); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	_, ok, err := readLegacyAgentOwnersFile(oldPath, nil)
	if err != nil {
		return false, err
	}
	if !ok {
		quarantine, err := os.CreateTemp(dir, "legacy-agent-owners-corrupt-*.bad")
		if err != nil {
			return false, err
		}
		path := quarantine.Name()
		if err := quarantine.Close(); err != nil {
			_ = os.Remove(path)
			return false, err
		}
		if err := os.Rename(oldPath, path); err != nil {
			_ = os.Remove(path)
			return false, err
		}
		return true, nil
	}
	if LegacyAgentOwnersRecorded(dir) {
		return false, os.Remove(oldPath)
	}
	return false, os.Rename(oldPath, filepath.Join(dir, LegacyAgentOwnersFile))
}

// validLegacyAgentOwner reports whether owner is one the map can carry and
// give back unchanged. A user or token that is not UTF-8 is refused: JSON
// would carry another name (U+FFFD), which binds no account.
func validLegacyAgentOwner(owner LegacyAgentOwner) bool {
	if !utf8.ValidString(owner.User) || !utf8.ValidString(owner.Token) {
		return false
	}
	if owner.User == "" || len(owner.User) > maxLegacyAgentOwnerField || owner.Token == "" || len(owner.Token) > maxLegacyAgentOwnerField {
		return false
	}
	return !strings.ContainsFunc(owner.User+owner.Token, func(r rune) bool { return r < 0x20 || r == 0x7f })
}
