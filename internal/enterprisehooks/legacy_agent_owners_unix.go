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
// The file is written once, owned by the guardian authorization and read by
// the gateway only after that trust check. A legacy entry then keeps
// applying to the account the map records, and to no other; a request of an
// account the map does not record is refused, naming the unproven agent
// ownership (the gateway's selectProfile). It changes only after a rollback
// to a release without the map: the accounts that release served, which
// the map does not record yet, are added at the first pass after the
// upgrade back, as the first upgrade recorded its accounts
// (AddLegacyAgentOwners, GAP-0709). Entries already recorded never change.
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
// lookup give no name, and the guardian holds no record of its uid) is
// looked up once more; while it stays unnamed the map is not recorded
// (unnamedLegacyAgentOwners). Recorded without it, the map was closed and
// could never add it, so its 1.0.x agents entry was refused for good once
// its lookup answered again (review of r104 Q-identity, continuation 2,
// loop round 3). An account still unnamed at the next pass is recorded as
// pending without a name, and the map stays open for it: a later pass binds
// the account that holds the uid then only when its home directory was
// created before the map was written (legacyAgentOwnerHomeCreatedBy), so an
// account given the uid after the upgrade is never bound. That pass took
// two not-found answers as proof that the uid held no account and closed
// the map without it, so an account a directory missed twice (SSSD offline)
// lost its 1.0.x agents entry for good (review of r104 Q-identity,
// continuation 3, loop round 2).

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
	proof, ok := homeIdentity(home)
	if !ok {
		return ""
	}
	return proof.token()
}

// LegacyAgentOwnerTokenFor is LegacyAgentOwnerToken(incarnation, home),
// or the token the migration map recorded for the account (recorded gives
// it, with the time the map was written) when that is the token the 1.0.4
// builds before the GAP-0939 fix wrote for this same home. Those builds
// (r104 trains t7 to t10; no release) took the device and inode of the
// directory a symlinked home names but the creation time of the symlink
// itself, so the token of a symlinked home changed with the fix, and a map
// they wrote no longer bound its account (review of r104 Q-identity,
// continuation 3, loop round 2). The recorded token is kept only while home
// is a symlink whose own creation time and target inode are the ones it
// records, and the directory it names was created no later than the map
// (or its file system keeps no creation time, where the token of this
// build proves the inode alone too): a home created again behind the
// symlink after the map, on the inode the removed one freed, is another
// account's. Remove with LegacyAgentOwnerToken.
func LegacyAgentOwnerTokenFor(incarnation, home string, recorded func() (string, time.Time)) string {
	token := LegacyAgentOwnerToken(incarnation, home)
	if recorded == nil || !strings.HasPrefix(token, "home:") {
		return token
	}
	home = strings.TrimSpace(home)
	linkBirth, isLink := symlinkBirth(home)
	if !isLink {
		return token
	}
	proof, ok := homeIdentity(home)
	if !ok {
		return token
	}
	was, writtenAt := recorded()
	if was == "" || was == token || writtenAt.IsZero() || (proof.hasBirth && proof.birth > writtenAt.UnixNano()) {
		return token
	}
	before := homeProof{dev: proof.dev, ino: proof.ino, birth: linkBirth, hasBirth: true}
	if sameHomeTokenInode(was, before.token()) {
		return was
	}
	return token
}

// sameHomeTokenInode reports whether two home tokens with a creation time
// name the same inode with the same creation time, whatever their device
// (an automounted home gets another device number at each mount).
func sameHomeTokenInode(a, b string) bool {
	pa, pb := strings.Split(a, ":"), strings.Split(b, ":")
	return len(pa) == 4 && len(pb) == 4 && pa[0] == "home" && pb[0] == "home" && pa[2] == pb[2] && pa[3] == pb[3]
}

// token is the owner token of the home proof.
func (p homeProof) token() string {
	token := "home:" + strconv.FormatUint(p.dev, 10) + ":" + strconv.FormatUint(p.ino, 10)
	if p.hasBirth {
		token += ":" + strconv.FormatInt(p.birth, 10)
	}
	return token
}

// homeProof is what one stat of a home directory gives the owner token:
// its device and inode, and its creation time in nanoseconds where the file
// system keeps one.
type homeProof struct {
	dev, ino uint64
	birth    int64
	hasBirth bool
}

// HomeBirth is the creation time of the directory home, Unix nanoseconds,
// as LegacyAgentOwnerToken names it; false where the file system keeps none.
func HomeBirth(home string) (int64, bool) {
	proof, ok := homeIdentity(home)
	if !ok || !proof.hasBirth {
		return 0, false
	}
	return proof.birth, true
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
// pending, by its name, or without one when User is empty too (an account
// no lookup named). The first call writes the map, in shards past
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
		case owner.Token == "" && (owner.User == "" || validLegacyAgentOwnerField(owner.User)):
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

// AddLegacyAgentOwners adds to dir's migration map the owners (by uid) of
// uids it records neither as owners nor as pending, and reports whether it
// added any. Recorded and pending uids keep their entries, and each file
// keeps when it was written (the pending rule reads it). The guardian
// calls it only for a recorded map: at the passes after an upgrade from a
// release that kept no map (a rollback window: a 1.0.3 guardian rewrote
// every identity record without the account incarnation, so a 1.0.3 agent
// identity of an account added then was derived for the account that holds
// its uid now, as at the first upgrade, GAP-0709) and for the 1.0.3 holders
// a 1.0.4 map left out (GAP-2085). New owners go to the last file of the
// map, and to a new shard past maxLegacyAgentOwners. A map with a shard
// that cannot be read is not rewritten. Shards are written before the main
// file, which is always rewritten: it counts the shards, and its change
// tells a running gateway to read the map again.
func AddLegacyAgentOwners(dir string, owners map[int]LegacyAgentOwner, setOwnership func(string) error) (bool, error) {
	if dir == "" {
		return false, nil
	}
	main, ok, err := readLegacyAgentOwnersFile(filepath.Join(dir, LegacyAgentOwnersFile), nil)
	if err != nil || !ok {
		return false, err
	}
	files := []legacyAgentOwnersFileDoc{main}
	for i := 1; i <= main.shards; i++ {
		shard, ok, err := readLegacyAgentOwnersFile(filepath.Join(dir, legacyAgentOwnersShardFile(i)), nil)
		if err != nil || !ok {
			return false, err
		}
		files = append(files, shard)
	}
	known := map[int]bool{}
	for _, file := range files {
		for uid := range file.owners {
			known[uid] = true
		}
		for uid := range file.pending {
			known[uid] = true
		}
	}
	var uids []int
	for uid, owner := range owners {
		if uid >= 0 && !known[uid] && validLegacyAgentOwner(owner) {
			uids = append(uids, uid)
		}
	}
	if len(uids) == 0 {
		return false, nil
	}
	slices.Sort(uids)
	changed := make([]bool, len(files))
	for _, uid := range uids {
		last := len(files) - 1
		if len(files[last].owners)+len(files[last].pending) >= maxLegacyAgentOwners {
			if last >= maxLegacyAgentOwnerShards {
				return false, fmt.Errorf("%d more accounts are more than the agent identity migration map holds", len(uids))
			}
			files = append(files, legacyAgentOwnersFileDoc{writtenAt: main.writtenAt, owners: map[int]LegacyAgentOwner{}, pending: map[int]string{}})
			changed = append(changed, false)
			last++
		}
		files[last].owners[uid] = owners[uid]
		changed[last] = true
	}
	files[0].shards = len(files) - 1
	for i := len(files) - 1; i >= 1; i-- {
		if !changed[i] {
			continue
		}
		if err := writeLegacyAgentOwnersDoc(dir, i, files[i].doc(), setOwnership); err != nil {
			return false, err
		}
	}
	if err := writeLegacyAgentOwnersDoc(dir, 0, files[0].doc(), setOwnership); err != nil {
		return false, err
	}
	return true, nil
}

// legacyAgentHolderOfRecord is the account name the guardian's identity
// record of uid in dir gives, "" without one: before the first pass of
// 1.0.4, the account the 1.0.x guardian last saw holding the uid. The
// record's age does not matter. The name only makes the account pending,
// and a later pass binds it only once it proves the account that holds
// the uid under that name. Taking only a record written within
// IdentitySpoolMaxAge left an account out for good when the 1.0.x guardian
// had not rewritten its record in the last hour (a host that was off, or
// a directory that had not answered) and the lookups at the upgrade found
// it twice not found (SSSD offline), although its 1.0.x record named it
// (review of r104 Q-identity, continuation 3, loop round 1).
func legacyAgentHolderOfRecord(dir string, uid int) string {
	record, err := ReadIdentitySpoolRecord(dir, strconv.Itoa(uid), nil)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(record.User)
}

// unnamedLegacyAgentOwners names, in owners as pending, each uid in unnamed:
// a listed account of a pass before the map is recorded that neither the
// listing, its lookup nor a guardian record named. Its account is looked up
// once more. It reports whether the map may be recorded now: false while one
// is unnamed for the first time, so the next pass can name it. A uid the
// pass before left unnamed too is recorded as pending without a name, and
// the map is recorded: whatever its lookups answer (not found, an error, no
// answer), it does not keep the map from the other accounts, and the
// account that holds it is bound once its home proves it held the uid at
// the upgrade (fillLegacyAgentOwners). A not-found answer is not taken as
// proof that no account holds the uid: a directory that is offline or
// misses an account answers it too (GAP-1236).
func unnamedLegacyAgentOwners(ctx context.Context, dir string, owners map[int]LegacyAgentOwner, unnamed []int,
	logf func(string, ...any)) bool {
	before := legacyAgentOwnersUnresolved.take(dir)
	still := map[int]bool{}
	var unknown []int
	for _, uid := range unnamed {
		lookupCtx, cancel := context.WithTimeout(ctx, identitySpoolLookupTimeout)
		account, err := identityLookupGated(lookupCtx, &identitySpoolDepartureGate, strconv.Itoa(uid),
			func(ctx context.Context) (unixidentity.Account, error) { return identitySpoolLookupUID(ctx, uid) })
		cancel()
		switch {
		case err == nil && account.UID == uid && account.Name != "":
			owners[uid] = LegacyAgentOwner{User: account.Name}
		case before[uid]:
			// Unnamed at two passes: pending without a name.
			owners[uid] = LegacyAgentOwner{}
			still[uid] = true
		default:
			still[uid] = true
			unknown = append(unknown, uid)
		}
	}
	if len(unknown) == 0 {
		return true
	}
	// Every uid still unnamed is marked, also one this pass recorded as
	// pending: the map is not recorded at this pass, and the next pass must
	// not take it for unnamed the first time again.
	legacyAgentOwnersUnresolved.set(dir, still)
	if logf != nil {
		logf("[hook-guardian] agent identity migration map: no account name for uid %v (the lookup did not answer); "+
			"the map is recorded at the next pass, with any account still unnamed then pending until its home proves it", unknown)
	}
	return false
}

// legacyAgentOwnerHomeCreatedBy reports whether home, the home directory
// of the account that holds a uid now, was created no later than at, when
// the migration map was written: the account held the uid at the upgrade,
// since an account given the uid later gets a home created later. false
// when the home is not there or its file system keeps no creation time.
func legacyAgentOwnerHomeCreatedBy(home string, at time.Time) bool {
	home = strings.TrimSpace(home)
	if home == "" || !filepath.IsAbs(home) || at.IsZero() {
		return false
	}
	proof, ok := homeIdentity(home)
	return ok && proof.hasBirth && proof.birth <= at.UnixNano()
}

// legacyAgentOwnersUnresolved holds, per spool directory, the uids the last
// pass that did not record the map left unnamed.
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
// it (a uid now held by another name stays pending). A pending account
// without a name is bound to the account owners proves for its uid only
// when that account's home was created before the map was written
// (legacyAgentOwnerHomeCreatedBy). Shards it changes are
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
			owner, ok := owners[uid]
			if !ok || owner.Token == "" || !validLegacyAgentOwner(owner) {
				continue
			}
			if (user == "" && legacyAgentOwnerHomeCreatedBy(identitySpoolAccountHome(uid), file.writtenAt)) ||
				(user != "" && strings.EqualFold(owner.User, user)) {
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
// dir by uid, whether an account is still pending (open: a later pass may
// add its owner), and when the map was written, when every file of the map
// exists and trust accepts it; false otherwise.
func ReadLegacyAgentOwners(dir string, trust func(path, label string) error) (map[int]LegacyAgentOwner, bool, time.Time, bool) {
	if dir == "" {
		return nil, false, time.Time{}, false
	}
	if main, ok, _ := readLegacyAgentOwnersFile(filepath.Join(dir, LegacyAgentOwnersFile), trust); ok {
		owners := main.owners
		for i := 1; i <= main.shards; i++ {
			shard, ok, _ := readLegacyAgentOwnersFile(filepath.Join(dir, legacyAgentOwnersShardFile(i)), trust)
			if !ok {
				// A map without one of its shards binds no account it lists:
				// it is read again once the shard is there.
				return nil, false, time.Time{}, false
			}
			for uid, owner := range shard.owners {
				if _, seen := owners[uid]; !seen {
					owners[uid] = owner
				}
			}
		}
		return owners, main.open, main.writtenAt, true
	}
	// A guardian already running before this upgrade may not have moved its
	// old map yet. Keep its agent assignments working during that handoff.
	// Builds that wrote the old name wrote no pending accounts or shards.
	old, ok, _ := readLegacyAgentOwnersFile(filepath.Join(dir, oldLegacyAgentOwnersFile), trust)
	if !ok || old.open || old.shards != 0 || len(old.pending) != 0 {
		return nil, false, time.Time{}, false
	}
	return old.owners, false, old.writtenAt, true
}

// legacyAgentOwnerOfRecord returns what LegacyAgentOwnerTokenFor needs of
// the migration map of dir for the account user that holds uid: the token
// the map records for it, and when the map was written; "" when the map
// records another name for the uid, or none. The map is read at the first
// call, once.
func legacyAgentOwnerOfRecord(dir string) func(uid int, user string) (string, time.Time) {
	var (
		read      bool
		owners    map[int]LegacyAgentOwner
		writtenAt time.Time
	)
	return func(uid int, user string) (string, time.Time) {
		if !read {
			read = true
			owners, _, writtenAt, _ = ReadLegacyAgentOwners(dir, nil)
		}
		owner, ok := owners[uid]
		if !ok || !strings.EqualFold(owner.User, user) {
			return "", time.Time{}
		}
		return owner.Token, writtenAt
	}
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
		if uid, ok := legacyAgentOwnerUID(key); ok && (user == "" || validLegacyAgentOwnerField(user)) {
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
