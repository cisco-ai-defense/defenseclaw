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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
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
//
// An account the first pass listed but could not prove (its lookup failed,
// or its automounted home was not there) is recorded as pending, by uid and
// name, and a later pass that proves it adds its owner: the map is never
// changed otherwise, and an account the first pass did not list is never
// added. Such an account was dropped for good before (review of r104
// Q-identity, continuation 2, loop round 2). The map holds every account:
// past maxLegacyAgentOwners a file, the rest go to shards
// (legacyAgentOwnersShardFile) that the main file counts, so no account is
// dropped for the map's size either.
//
// A listed account the first pass cannot name at all (the listing and its
// lookup give no name, and the guardian holds no recent record of its uid)
// is looked up once more; while it stays unnamed the map is not recorded
// (unnamedLegacyAgentOwners). Recorded without it, the map was closed and
// could never add it, so its 1.0.x agents entry was refused for good once
// its lookup answered again (review of r104 Q-identity, continuation 2,
// loop round 3).

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
	// maxLegacyAgentOwners bounds the accounts (owners and pending) of one
	// file of the map.
	maxLegacyAgentOwners = 65536
	// maxLegacyAgentOwnerShards bounds the shards. With the main file they
	// hold 2^32 accounts, one for every uid a host can give.
	maxLegacyAgentOwnerShards = 1<<16 - 1
	// maxLegacyAgentOwnerField bounds the bytes of an owner's user and of
	// its token (validLegacyAgentOwner).
	maxLegacyAgentOwnerField = 256
	// maxLegacyAgentOwnersBytes is the largest file of the map
	// WriteLegacyAgentOwners can write, and the largest the reader takes. A
	// map the reader refused would leave every legacy agents entry unbound
	// for good. It is the header with the longest time, the open mark and
	// the most shards, plus maxLegacyAgentOwners entries with the longest
	// uid, user and token, a byte of which json.Marshal spells in at most six
	// (\u003c for <, > and &; earlier 1.0.4 builds also wrote \ufffd for a
	// byte that is not UTF-8). A pending entry is shorter than an owner's. A
	// map of real account names is far smaller (about 8 MiB for 65,536
	// qualified AD accounts).
	maxLegacyAgentOwnersBytes    = int64(legacyAgentOwnersHeaderBytes + maxLegacyAgentOwners*legacyAgentOwnerEntryBytes)
	legacyAgentOwnersHeaderBytes = len(`{"v":1,"written_at":"","owners":{},"pending":{},"open":true,"shards":}`) +
		len("9999-12-31T23:59:59.999999999Z") + len("65535")
	legacyAgentOwnerEntryBytes   = len(`"":{"user":"","token":""},`) + len("9223372036854775807") + 2*6*maxLegacyAgentOwnerField
	legacyAgentPendingEntryBytes = len(`"":"",`) + len("9223372036854775807") + 6*maxLegacyAgentOwnerField
)

// legacyAgentOwnersShardFile is the name of shard i (1 to the main file's
// shards) of the migration map: outside the uid.json record namespace, as
// the main file is.
func legacyAgentOwnersShardFile(i int) string {
	return "legacy-agent-owners-" + strconv.Itoa(i) + ".map"
}

// isLegacyAgentOwnersFile reports whether name is a file of the migration
// map (the main file or a shard) or a quarantined invalid map: files the
// spool's cleanup keeps.
func isLegacyAgentOwnersFile(name string) bool {
	if name == LegacyAgentOwnersFile {
		return true
	}
	if strings.HasPrefix(name, "legacy-agent-owners-corrupt-") && strings.HasSuffix(name, ".bad") {
		return true
	}
	index := strings.TrimSuffix(strings.TrimPrefix(name, "legacy-agent-owners-"), ".map")
	i, err := strconv.Atoi(index)
	return err == nil && i >= 1 && i <= maxLegacyAgentOwnerShards && legacyAgentOwnersShardFile(i) == name
}

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
	// Pending are the accounts (uid to name) the first pass listed without
	// an owner proof; a later pass that proves one moves it to Owners.
	Pending map[string]string `json:"pending,omitempty"`
	// Open, in the main file, marks a map with an account still pending in
	// any of its files.
	Open bool `json:"open,omitempty"`
	// Shards, in the main file, is how many shards hold the rest of the map.
	Shards int `json:"shards,omitempty"`
}

// legacyAgentOwnersFileDoc is one file of the map as read: its owners and
// pending accounts by uid.
type legacyAgentOwnersFileDoc struct {
	writtenAt time.Time
	owners    map[int]LegacyAgentOwner
	pending   map[int]string
	open      bool
	shards    int
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

// WriteLegacyAgentOwners records the migration map of owners (by uid) in
// dir. An owner without a Token is an account listed without its owner
// proof (its lookup failed, or its home was not there): it is recorded as
// pending. The first call writes the map, in shards past
// maxLegacyAgentOwners accounts (an empty one is not written, so the next
// pass tries again). Later calls only add the owner of a pending account
// whose name owners now gives with a proof, and change nothing else.
// setOwnership gives each file the guardian authorization ownership before
// it is renamed into place; shards are written before the main file that
// counts them. Every file it writes is within maxLegacyAgentOwnersBytes, the
// reader's bound. It reports whether it wrote anything.
func WriteLegacyAgentOwners(dir string, owners map[int]LegacyAgentOwner, now time.Time, setOwnership func(string) error) (bool, error) {
	if dir == "" {
		return false, nil
	}
	if _, err := moveLegacyAgentOwners(dir); err != nil {
		return false, err
	}
	if LegacyAgentOwnersRecorded(dir) {
		return fillLegacyAgentOwners(dir, owners, setOwnership)
	}
	proven, pending := map[int]LegacyAgentOwner{}, map[int]string{}
	for uid, owner := range owners {
		switch {
		case uid < 0:
		case owner.Token == "" && validLegacyAgentOwnerField(owner.User):
			pending[uid] = owner.User
		case validLegacyAgentOwner(owner):
			proven[uid] = owner
		}
	}
	uids := make([]int, 0, len(proven)+len(pending))
	for uid := range proven {
		uids = append(uids, uid)
	}
	for uid := range pending {
		uids = append(uids, uid)
	}
	if len(uids) == 0 {
		return false, nil
	}
	slices.Sort(uids)
	files := (len(uids) + maxLegacyAgentOwners - 1) / maxLegacyAgentOwners
	if files-1 > maxLegacyAgentOwnerShards {
		// Never published short: a map without an account refuses its
		// agents entries for good.
		return false, fmt.Errorf("%d accounts are more than the agent identity migration map holds", len(uids))
	}
	docs := make([]legacyAgentOwnersDoc, files)
	for i := range docs {
		docs[i] = legacyAgentOwnersDoc{Version: legacyAgentOwnersVersion, WrittenAt: now.UTC(), Owners: map[string]LegacyAgentOwner{}}
		for _, uid := range uids[i*maxLegacyAgentOwners : min((i+1)*maxLegacyAgentOwners, len(uids))] {
			if user, ok := pending[uid]; ok {
				if docs[i].Pending == nil {
					docs[i].Pending = map[string]string{}
				}
				docs[i].Pending[strconv.Itoa(uid)] = user
			} else {
				docs[i].Owners[strconv.Itoa(uid)] = proven[uid]
			}
		}
	}
	docs[0].Open, docs[0].Shards = len(pending) > 0, files-1
	for i := files - 1; i >= 0; i-- {
		if err := writeLegacyAgentOwnersDoc(dir, i, docs[i], setOwnership); err != nil {
			return false, err
		}
	}
	legacyAgentOwnersClosed.forget(dir)
	if !docs[0].Open {
		legacyAgentOwnersClosed.set(dir)
	}
	return true, nil
}

// legacyAgentHolderOfRecord is the account name the guardian's identity
// record of uid in dir gives, when the record is recent (written within
// IdentitySpoolMaxAge, not in the future): before the first pass of 1.0.4,
// the account the 1.0.x guardian last saw holding the uid. "" otherwise.
func legacyAgentHolderOfRecord(dir string, uid int, now time.Time) string {
	record, err := ReadIdentitySpoolRecord(dir, strconv.Itoa(uid), nil)
	if err != nil || record.UpdatedAt.IsZero() || record.UpdatedAt.After(now.Add(time.Minute)) ||
		now.Sub(record.UpdatedAt) > IdentitySpoolMaxAge {
		return ""
	}
	return record.User
}

// unnamedLegacyAgentOwners names, in owners as pending, each uid in unnamed:
// a listed account of a pass before the map is recorded that neither the
// listing, its lookup nor a recent guardian record named. Its account is
// looked up once more. It reports whether the map may be recorded now:
// false while one stays unnamed (a lookup that fails or does not finish),
// so the map is recorded at a later pass that names every account. A uid
// that two successive passes find unresolved holds no account, and is left
// out: an account given it later is another one. A single not-found answer
// can miss an account its directory still holds (GAP-1236).
func unnamedLegacyAgentOwners(ctx context.Context, dir string, owners map[int]LegacyAgentOwner, unnamed []int,
	logf func(string, ...any)) bool {
	before := legacyAgentOwnersUnresolved.take(dir)
	gone := map[int]bool{}
	var unknown []int
	for _, uid := range unnamed {
		lookupCtx, cancel := context.WithTimeout(ctx, identitySpoolLookupTimeout)
		account, err := identityLookupGated(lookupCtx, &identitySpoolDepartureGate, strconv.Itoa(uid),
			func(ctx context.Context) (unixidentity.Account, error) { return identitySpoolLookupUID(ctx, uid) })
		notFound := err != nil && lookupCtx.Err() == nil && unixidentity.IsNotFound(err)
		cancel()
		switch {
		case err == nil && account.UID == uid && account.Name != "":
			owners[uid] = LegacyAgentOwner{User: account.Name}
		case notFound && before[uid]:
			// No account holds the uid: nothing to bind.
		case notFound:
			gone[uid] = true
			unknown = append(unknown, uid)
		default:
			unknown = append(unknown, uid)
		}
	}
	if len(unknown) == 0 {
		return true
	}
	legacyAgentOwnersUnresolved.set(dir, gone)
	if logf != nil {
		logf("[hook-guardian] agent identity migration map: no account name for uid %v (the lookup did not answer); "+
			"the map is recorded at a later pass that names every listed account", unknown)
	}
	return false
}

// legacyAgentOwnersUnresolved holds, per spool directory, the unnamed uids
// the last pass that did not record the map found unresolved.
var legacyAgentOwnersUnresolved = unresolvedLegacyAgentOwners{byDir: map[string]map[int]bool{}}

type unresolvedLegacyAgentOwners struct {
	sync.Mutex
	byDir map[string]map[int]bool
}

// take returns dir's marks and clears them: a mark counts only for the
// next pass.
func (u *unresolvedLegacyAgentOwners) take(dir string) map[int]bool {
	u.Lock()
	defer u.Unlock()
	marks := u.byDir[dir]
	delete(u.byDir, dir)
	return marks
}

func (u *unresolvedLegacyAgentOwners) set(dir string, marks map[int]bool) {
	u.Lock()
	defer u.Unlock()
	if len(marks) == 0 {
		delete(u.byDir, dir)
		return
	}
	u.byDir[dir] = marks
}

// legacyAgentOwnersClosed remembers, per spool directory, a map with no
// account pending, so later passes do not read it again.
var legacyAgentOwnersClosed = closedLegacyAgentOwnerMaps{byDir: map[string]bool{}}

type closedLegacyAgentOwnerMaps struct {
	sync.Mutex
	byDir map[string]bool
}

func (c *closedLegacyAgentOwnerMaps) closed(dir string) bool {
	c.Lock()
	defer c.Unlock()
	return c.byDir[dir]
}

func (c *closedLegacyAgentOwnerMaps) set(dir string) {
	c.Lock()
	defer c.Unlock()
	c.byDir[dir] = true
}

func (c *closedLegacyAgentOwnerMaps) forget(dir string) {
	c.Lock()
	defer c.Unlock()
	delete(c.byDir, dir)
}

// fillLegacyAgentOwners adds to the published map of dir the owner of each
// pending account that owners proves under the name the map recorded for
// it (a uid now held by another name stays pending). Shards it changes are
// written before the main file, which is rewritten last, with its open mark
// cleared once nothing is pending.
func fillLegacyAgentOwners(dir string, owners map[int]LegacyAgentOwner, setOwnership func(string) error) (bool, error) {
	if legacyAgentOwnersClosed.closed(dir) {
		return false, nil
	}
	main, ok, err := readLegacyAgentOwnersFile(filepath.Join(dir, LegacyAgentOwnersFile), nil)
	if err != nil {
		return false, err
	}
	if !ok || !main.open {
		// A map this build cannot read is not rewritten: what it binds is
		// unknown.
		if ok {
			legacyAgentOwnersClosed.set(dir)
		}
		return false, nil
	}
	files := []legacyAgentOwnersFileDoc{main}
	for i := 1; i <= main.shards; i++ {
		shard, ok, err := readLegacyAgentOwnersFile(filepath.Join(dir, legacyAgentOwnersShardFile(i)), nil)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
		files = append(files, shard)
	}
	changed, open := make([]bool, len(files)), false
	for i, file := range files {
		for uid, user := range file.pending {
			if owner, ok := owners[uid]; ok && owner.Token != "" && validLegacyAgentOwner(owner) && strings.EqualFold(owner.User, user) {
				file.owners[uid] = owner
				delete(file.pending, uid)
				changed[i] = true
			}
		}
		open = open || len(file.pending) > 0
	}
	if !slices.Contains(changed, true) {
		return false, nil
	}
	files[0].open = open
	for i := len(files) - 1; i >= 0; i-- {
		if !changed[i] && i > 0 {
			continue
		}
		if err := writeLegacyAgentOwnersDoc(dir, i, files[i].doc(), setOwnership); err != nil {
			return false, err
		}
	}
	if !open {
		legacyAgentOwnersClosed.set(dir)
	}
	return true, nil
}

// doc is the file as WriteLegacyAgentOwners writes it.
func (f legacyAgentOwnersFileDoc) doc() legacyAgentOwnersDoc {
	doc := legacyAgentOwnersDoc{Version: legacyAgentOwnersVersion, WrittenAt: f.writtenAt.UTC(),
		Owners: make(map[string]LegacyAgentOwner, len(f.owners)), Open: f.open, Shards: f.shards}
	for uid, owner := range f.owners {
		doc.Owners[strconv.Itoa(uid)] = owner
	}
	for uid, user := range f.pending {
		if doc.Pending == nil {
			doc.Pending = map[string]string{}
		}
		doc.Pending[strconv.Itoa(uid)] = user
	}
	return doc
}

// writeLegacyAgentOwnersDoc writes file i of the map: 0 is the main file,
// and the others are shards.
func writeLegacyAgentOwnersDoc(dir string, i int, doc legacyAgentOwnersDoc, setOwnership func(string) error) error {
	data, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	name := LegacyAgentOwnersFile
	if i > 0 {
		name = legacyAgentOwnersShardFile(i)
	}
	return writeSpoolBytes(dir, name, ".legacy-agents-*", data, setOwnership)
}

// ReadLegacyAgentOwners returns the proven owners of the migration map of
// dir by uid, and whether an account is still pending (open: a later pass
// may add its owner), when every file of the map exists and trust accepts
// it; false otherwise.
func ReadLegacyAgentOwners(dir string, trust func(path, label string) error) (map[int]LegacyAgentOwner, bool, bool) {
	if dir == "" {
		return nil, false, false
	}
	if main, ok, _ := readLegacyAgentOwnersFile(filepath.Join(dir, LegacyAgentOwnersFile), trust); ok {
		owners := main.owners
		for i := 1; i <= main.shards; i++ {
			shard, ok, _ := readLegacyAgentOwnersFile(filepath.Join(dir, legacyAgentOwnersShardFile(i)), trust)
			if !ok {
				// A map without one of its shards binds no account it lists:
				// it is read again once the shard is there.
				return nil, false, false
			}
			for uid, owner := range shard.owners {
				if _, seen := owners[uid]; !seen {
					owners[uid] = owner
				}
			}
		}
		return owners, main.open, true
	}
	// A guardian already running before this upgrade may not have moved its
	// old map yet. Keep its agent assignments working during that handoff.
	// Builds that wrote the old name wrote no pending accounts or shards.
	old, ok, _ := readLegacyAgentOwnersFile(filepath.Join(dir, oldLegacyAgentOwnersFile), trust)
	if !ok || old.open || old.shards != 0 || len(old.pending) != 0 {
		return nil, false, false
	}
	return old.owners, false, true
}

// A false result with no error means the bytes cannot be a file of a
// migration map. I/O and trust errors are distinct so the guardian never
// moves a valid map aside merely because it could not read it on this pass.
func readLegacyAgentOwnersFile(path string, trust func(path, label string) error) (legacyAgentOwnersFileDoc, bool, error) {
	var none legacyAgentOwnersFileDoc
	info, err := os.Lstat(path)
	if err != nil {
		return none, false, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxLegacyAgentOwnersBytes {
		return none, false, nil
	}
	if trust != nil {
		if err := trust(path, "agent identity migration map"); err != nil {
			return none, false, err
		}
	}
	file, err := legacyAgentOwnersOpen(path)
	if err != nil {
		return none, false, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxLegacyAgentOwnersBytes+1))
	if err != nil {
		return none, false, err
	}
	if int64(len(data)) > maxLegacyAgentOwnersBytes {
		return none, false, nil
	}
	var doc legacyAgentOwnersDoc
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&doc) != nil || doc.Version != legacyAgentOwnersVersion ||
		doc.Shards < 0 || doc.Shards > maxLegacyAgentOwnerShards || len(doc.Owners)+len(doc.Pending) > maxLegacyAgentOwners {
		return none, false, nil
	}
	out := legacyAgentOwnersFileDoc{writtenAt: doc.WrittenAt, owners: make(map[int]LegacyAgentOwner, len(doc.Owners)),
		pending: make(map[int]string, len(doc.Pending)), open: doc.Open, shards: doc.Shards}
	for key, owner := range doc.Owners {
		if uid, ok := legacyAgentOwnerUID(key); ok && validLegacyAgentOwner(owner) {
			out.owners[uid] = owner
		}
	}
	for key, user := range doc.Pending {
		if uid, ok := legacyAgentOwnerUID(key); ok && validLegacyAgentOwnerField(user) {
			if _, proven := out.owners[uid]; !proven {
				out.pending[uid] = user
			}
		}
	}
	return out, true, nil
}

// legacyAgentOwnerUID is the uid a map key names, in its one spelling.
func legacyAgentOwnerUID(key string) (int, bool) {
	uid, err := strconv.Atoi(key)
	return uid, err == nil && uid >= 0 && strconv.Itoa(uid) == key
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
	return validLegacyAgentOwnerField(owner.User) && validLegacyAgentOwnerField(owner.Token)
}

// validLegacyAgentOwnerField reports whether a user or token (or a pending
// account's name) is one the map can carry and give back unchanged.
func validLegacyAgentOwnerField(field string) bool {
	return field != "" && len(field) <= maxLegacyAgentOwnerField && utf8.ValidString(field) &&
		!strings.ContainsFunc(field, func(r rune) bool { return r < 0x20 || r == 0x7f })
}
