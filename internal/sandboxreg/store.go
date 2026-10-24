// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package sandboxreg

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// Store errors. Callers map them to the sandbox routes' refusal reasons;
// none of them names another uid's state.
var (
	// ErrNotFound: no registration with that id for the uid (another uid's
	// id included).
	ErrNotFound = errors.New("sandboxreg: registration not found")
	// ErrExpired: a pending registration outlived PendingTTL.
	ErrExpired = errors.New("sandboxreg: registration expired")
	// ErrRevoked: the registration is a tombstone.
	ErrRevoked = errors.New("sandboxreg: registration revoked")
	// ErrNotPending: Bind on a registration that is already live.
	ErrNotPending = errors.New("sandboxreg: registration is not pending")
	// ErrTombstoned: the binding id or sandbox id of a Bind matches a
	// tombstone or a retired revoked sandbox, so that sandbox can never
	// register again.
	ErrTombstoned = errors.New("sandboxreg: the sandbox was revoked and cannot register again")
	// ErrInUse: the binding id or sandbox id is already bound to another
	// registration on the managed gateway.
	ErrInUse = errors.New("sandboxreg: the sandbox is already registered")
	// ErrDriverMismatch: the sandbox was created on another compute driver
	// than the one its registration was resolved for (a sandbox never
	// switches driver).
	ErrDriverMismatch = errors.New("sandboxreg: the sandbox runs on another compute driver than it was registered for")
	// ErrFull: the uid holds MaxEntriesPerUID registrations none of which
	// can be evicted, or its run records reached MaxRunBytesPerUID.
	ErrFull = errors.New("sandboxreg: too many sandbox registrations")
	// ErrInvalid: a record or request fails validation.
	ErrInvalid = errors.New("sandboxreg: invalid registration")
	// ErrCorrupt: a store file is unreadable, mis-owned or malformed; the
	// store fails closed for that uid.
	ErrCorrupt = errors.New("sandboxreg: registration store is unreadable")
)

// Revocation reasons the store itself sets or tells apart.
const (
	// ReasonDeleted is the revoked_reason of a live registration whose
	// sandbox its daemon reported deleted. Only this reason is the user's
	// own: every other reason is the gateway's (a changed subject, a
	// re-match stop the sandbox outlived) and its sandbox's ids stay
	// refused after the tombstone is dropped.
	ReasonDeleted = "deleted"
	// ReasonPolicyChanged is the revoked_reason of a sandbox revoked
	// because a re-match found its create-time policy no longer allowed
	// (GAP-0623, GAP-0644). The revocation is final: a later relaxation of
	// the policy does not bring the registration back.
	ReasonPolicyChanged = "policy_changed"
	// ReasonForeign is the revoked_reason of a registration bound to a
	// sandbox its account's daemon reported foreign (not created for any of
	// its registrations): the registration never named that daemon's
	// sandbox, and the sandbox never registers again.
	ReasonForeign = "foreign_sandbox"
)

// Run record and retirement bounds.
const (
	// MaxRunBytes bounds one run record (its JSON).
	MaxRunBytes = 256 << 10
	// MaxRunBytesPerUID bounds the run records of one uid, so one account's
	// registrations hold at most this much of the gateway's memory and of
	// its store file (maxStoreFileBytes).
	MaxRunBytesPerUID = 8 << 20
	// MaxRetiredPerUID bounds the retired sandbox ids kept per uid; the
	// oldest go first. Only gateway revocations are retired, which a user
	// cannot cause at will.
	MaxRetiredPerUID = 4096
)

// storeFileVersion is the "v" of a per-uid store file.
const storeFileVersion = 1

// maxStoreFileBytes bounds one per-uid store file on read.
const maxStoreFileBytes = 16 << 20

// expiredPendingKeep is how long an expired pending entry is kept so a late
// bind is told "expired" rather than "unknown"; writes drop it after that.
const expiredPendingKeep = time.Hour

var (
	idPattern          = regexp.MustCompile(`^` + IDPrefix + `[a-z2-7]{26}$`)
	bindingIDPattern   = regexp.MustCompile(`^sb_[0-9a-f]{32}$`)
	sandboxIDPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	sandboxNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	uidFilePattern     = regexp.MustCompile(`^(0|[1-9][0-9]{0,9})\.json$`)
	idEncoding         = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)
)

// RegistrationsDir is the registration store under the gateway's data
// directory: <DataDir>/sandbox/registrations.
func RegistrationsDir(dataDir string) string {
	return filepath.Join(dataDir, "sandbox", "registrations")
}

// NewID returns a fresh registration id: IDPrefix and IDRandomChars
// lowercase base32 characters (128 random bits).
func NewID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("sandboxreg: registration id: %w", err)
	}
	return IDPrefix + idEncoding.EncodeToString(raw[:]), nil
}

// ValidID reports whether id has the registration id shape. Anything else
// is never looked up.
func ValidID(id string) bool { return idPattern.MatchString(id) }

// PendingExpired reports whether r is a pending registration older than
// PendingTTL at now.
func PendingExpired(r Registration, now time.Time) bool {
	return r.State == StatePending && !now.Before(r.CreatedAt.Add(PendingTTL))
}

// EffectiveState is r's state at now as the routes and the views judge it:
// a pending registration past PendingTTL is StateExpired, and a live one
// whose daemon has not reported its sandbox running for LiveLease is
// StateStopped (GAP-0479, GAP-0488).
func EffectiveState(r Registration, now time.Time) string {
	switch {
	case PendingExpired(r, now):
		return StateExpired
	case r.State == StateLive && !now.Before(leaseStart(r).Add(LiveLease)):
		return StateStopped
	}
	return r.State
}

// leaseStart is when r's LiveLease began: its daemon's last running
// report, else its bind.
func leaseStart(r Registration) time.Time {
	if r.SeenAt.After(r.BoundAt) {
		return r.SeenAt
	}
	return r.BoundAt
}

// PolicyUpdatedAt is when r's policy last changed: its last re-match that
// changed it, else its resolve. It is the policy age a user's explain and
// status show, never the bind or a re-match that changed nothing
// (GAP-0690).
func PolicyUpdatedAt(r Registration) time.Time {
	if !r.PolicyAt.IsZero() {
		return r.PolicyAt
	}
	return r.CreatedAt
}

// SessionStart is when the session r's sandbox runs now began: the running
// report that followed its last stop (SessionAt), else its bind. A
// session-scope decision made before it was an earlier session's, which
// ended when the sandbox stopped (GAP-0009).
func SessionStart(r Registration) time.Time {
	if r.SessionAt.After(r.BoundAt) {
		return r.SessionAt
	}
	return r.BoundAt
}

// ValidBind checks the sandbox a bind names: the binding id the daemon
// minted (sb_ and 32 hex), the OpenShell sandbox name and its id. A bind
// without the id names no sandbox OpenShell made, so neither a foreign
// report nor a tombstone could ever match it (GAP-0446).
func ValidBind(b sandboxrelay.BindRequest) error {
	switch {
	case !bindingIDPattern.MatchString(b.BindingID):
		return fmt.Errorf("%w: binding id is malformed", ErrInvalid)
	case !sandboxNamePattern.MatchString(b.SandboxName):
		return fmt.Errorf("%w: sandbox name is malformed", ErrInvalid)
	case !sandboxIDPattern.MatchString(b.SandboxID):
		return fmt.Errorf("%w: sandbox id is missing or malformed", ErrInvalid)
	case b.Driver != "" && b.Driver != "docker" && b.Driver != "vm":
		return fmt.Errorf("%w: compute driver is not docker or vm", ErrInvalid)
	}
	return nil
}

// Run is the gateway's working state of a pending or live registration,
// kept next to it in the uid's file so a restarted gateway has it too: the
// run inputs a re-match resolves again, the policy key and floor digest
// it was last matched under, and the stop a re-match asked for. A
// tombstone has none, except the stop (StopAt and StopText) of a registration
// a re-match revoked: its daemon is told that text when it polls.
type Run struct {
	// Flags, RepoOverlay and UserPack are the resolve's run inputs.
	Flags       sandboxrelay.RunFlags `json:"flags"`
	RepoOverlay []byte                `json:"repo_overlay,omitempty"`
	UserPack    []byte                `json:"user_pack,omitempty"`
	// PolicyKey is the content digest of the sandbox policy inputs the
	// registration was last matched under; it survives a restart, unlike
	// the in-process generation counter. A different key is a re-match.
	PolicyKey string `json:"policy_key,omitempty"`
	// FloorDigest is the digest of the floor of that match.
	FloorDigest string `json:"floor_digest,omitempty"`
	// StopAt and StopText are the stop a re-match asked for (zero: none);
	// the registration is revoked in the same step, and this is what its
	// daemon is told.
	StopAt   time.Time `json:"stop_at,omitzero"`
	StopText string    `json:"stop_text,omitempty"`
	// HostPorts are the --host-port ports the create's policy opened: a
	// re-match whose policy no longer opens one of them stops the sandbox.
	HostPorts []int `json:"host_ports,omitempty"`
}

// Retired is a sandbox whose gateway-revoked tombstone was dropped: its
// binding id and sandbox id still never register again.
type Retired struct {
	BindingID string    `json:"binding_id,omitempty"`
	SandboxID string    `json:"sandbox_id,omitempty"`
	At        time.Time `json:"at"`
}

// FileStore is the Store kept as one JSON file per uid under a directory
// (RegistrationsDir), directory 0700 and files 0600 owned by the gateway's
// service account, each written atomically (temp file, fsync, rename).
// Files are read once per uid and cached; every mutation rewrites that
// uid's file before it is visible.
type FileStore struct {
	dir string
	// Now is the store's clock; nil means time.Now.
	Now func() time.Time
	// OnGone, when set, is called with each registration a write revoked
	// (Revoke, RevokeSandbox, Deleted of a bound entry), removed (Deleted)
	// or evicted (Create, CreateRun), once the write is stored and the
	// store unlocked. The managed gateway ends the tracked phase of the
	// registration's sandbox there, whatever its daemon last reported.
	OnGone func(Registration)

	// limit and runLimit override MaxEntriesPerUID and MaxRunBytesPerUID
	// in tests.
	limit, runLimit int

	mu   sync.Mutex
	uids map[int]*uidRecords
}

// uidRecords is one uid's file as cached: its registrations, the run
// records of its pending and live ones, and its retired sandboxes.
type uidRecords struct {
	regs    []Registration
	runs    map[string]Run
	retired []Retired
}

func (u *uidRecords) clone() *uidRecords {
	return &uidRecords{regs: slices.Clone(u.regs), runs: maps.Clone(u.runs), retired: slices.Clone(u.retired)}
}

var _ Store = (*FileStore)(nil)

// NewFileStore returns the store kept under dir. Nothing is read or
// created until the first call.
func NewFileStore(dir string) *FileStore {
	return &FileStore{dir: dir, uids: make(map[int]*uidRecords)}
}

type registrationFile struct {
	V             int            `json:"v"`
	Registrations []Registration `json:"registrations"`
	Runs          map[string]Run `json:"runs,omitempty"`
	Retired       []Retired      `json:"retired,omitempty"`
}

func (s *FileStore) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *FileStore) path(uid int) string {
	return filepath.Join(s.dir, strconv.Itoa(uid)+".json")
}

// loadLocked returns uid's records, reading its file on first use. The
// caller never mutates them in place: it saves a clone.
func (s *FileStore) loadLocked(uid int) (*uidRecords, error) {
	if uid < 0 {
		return nil, fmt.Errorf("%w: negative uid", ErrInvalid)
	}
	if u, ok := s.uids[uid]; ok {
		return u, nil
	}
	var file registrationFile
	if err := readStoreFile(s.path(uid), &file); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			u := &uidRecords{}
			s.uids[uid] = u
			return u, nil
		}
		return nil, err
	}
	if file.V != storeFileVersion {
		return nil, fmt.Errorf("%w: uid %d: unsupported version %d", ErrCorrupt, uid, file.V)
	}
	for _, r := range file.Registrations {
		if r.UID != uid || !ValidID(r.ID) {
			return nil, fmt.Errorf("%w: uid %d: a record names another uid or a malformed id", ErrCorrupt, uid)
		}
	}
	u := &uidRecords{regs: file.Registrations, runs: file.Runs, retired: file.Retired}
	if len(u.retired) > MaxRetiredPerUID {
		u.retired = u.retired[len(u.retired)-MaxRetiredPerUID:]
	}
	s.uids[uid] = u
	return u, nil
}

// saveLocked writes u as uid's file and then publishes it. Expired pending
// entries past their keep window are dropped, and so are the run records
// of tombstones (but for the stop a re-match revoked one with) and of
// dropped entries.
func (s *FileStore) saveLocked(uid int, u *uidRecords) error {
	now := s.now()
	kept := u.regs[:0:0]
	runs := map[string]Run{}
	for _, r := range u.regs {
		if r.State == StatePending && now.Sub(r.CreatedAt) >= PendingTTL+expiredPendingKeep {
			continue
		}
		kept = append(kept, r)
		run, ok := u.runs[r.ID]
		switch {
		case !ok:
		case r.State != StateRevoked:
			runs[r.ID] = run
		case run.StopText != "":
			runs[r.ID] = Run{StopAt: run.StopAt, StopText: run.StopText}
		}
	}
	if len(runs) == 0 {
		runs = nil
	}
	retired := u.retired
	if len(retired) > MaxRetiredPerUID {
		retired = retired[len(retired)-MaxRetiredPerUID:]
	}
	if err := writeStoreFile(s.dir, s.path(uid), registrationFile{V: storeFileVersion, Registrations: kept, Runs: runs, Retired: retired}); err != nil {
		return err
	}
	s.uids[uid] = &uidRecords{regs: kept, runs: runs, retired: retired}
	return nil
}

// runSize is the stored size of run, or an error when it exceeds
// MaxRunBytes.
func runSize(run Run) (int, error) {
	raw, err := json.Marshal(run)
	if err != nil {
		return 0, fmt.Errorf("%w: run record: %v", ErrInvalid, err)
	}
	if len(raw) > MaxRunBytes {
		return 0, fmt.Errorf("%w: the run record is too large", ErrInvalid)
	}
	return len(raw), nil
}

// runCost bounds the stored size of run from above without encoding it:
// base64 bytes, strings and a fixed allowance for the JSON keys.
func runCost(run Run) int {
	n := 512 + (len(run.RepoOverlay)+len(run.UserPack))*4/3 + 2*(len(run.PolicyKey)+len(run.FloorDigest)+len(run.StopText))
	f := run.Flags
	for _, s := range append([]string{f.Pack, f.Profile, f.CPU, f.Memory}, f.Unmask...) {
		n += 2*len(s) + 4
	}
	return n + 8*(len(f.HostPorts)+len(run.HostPorts))
}

// runBytes is the bounded size of u's run records.
func runBytes(u *uidRecords) int {
	total := 0
	for _, run := range u.runs {
		total += runCost(run)
	}
	return total
}

// Create adds r as uid's pending registration without a run record.
func (s *FileStore) Create(uid int, r Registration) error {
	return s.CreateRun(uid, r, nil)
}

// CreateRun adds r as uid's pending registration with its run record (nil:
// none). r.ID, r.SubjectKey and the connector must be set; UID, state and
// version are the store's. A uid whose run records would pass
// MaxRunBytesPerUID is full.
func (s *FileStore) CreateRun(uid int, r Registration, run *Run) error {
	if !ValidID(r.ID) || r.SubjectKey == "" || r.Connector == "" {
		return fmt.Errorf("%w: id, subject key and connector are required", ErrInvalid)
	}
	size := 0
	if run != nil {
		var err error
		if size, err = runSize(*run); err != nil {
			return err
		}
	}
	var gone []Registration
	defer func() { s.notifyGone(gone) }()
	s.mu.Lock()
	defer s.mu.Unlock()
	have, err := s.loadLocked(uid)
	if err != nil {
		return err
	}
	for _, existing := range have.regs {
		if existing.ID == r.ID {
			return fmt.Errorf("%w: duplicate id", ErrInvalid)
		}
	}
	r.V, r.UID, r.State = RecordVersion, uid, StatePending
	r.SandboxID, r.SandboxName, r.BindingID = "", "", ""
	r.RevokedReason, r.BoundAt, r.RevokedAt, r.SessionAt = "", time.Time{}, time.Time{}, time.Time{}
	r.GuestWatch, r.GuestSeenAt = false, time.Time{}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = s.now()
	}
	next := have.clone()
	var evicted []Registration
	if len(next.regs) >= s.maxEntries() {
		evicted = s.evict(next)
		if len(next.regs) >= s.maxEntries() {
			return ErrFull
		}
	}
	if run != nil {
		s.dropExpiredRuns(next)
		if runBytes(next)+max(size, runCost(*run)) > s.maxRunBytes() {
			return ErrFull
		}
		if next.runs == nil {
			next.runs = map[string]Run{}
		}
		next.runs[r.ID] = *run
	}
	next.regs = append(next.regs, r)
	if err := s.saveLocked(uid, next); err != nil {
		return err
	}
	gone = evicted
	return nil
}

// dropExpiredRuns drops the run records of u's expired pending entries:
// they can never bind, so nothing re-matches them.
func (s *FileStore) dropExpiredRuns(u *uidRecords) {
	now := s.now()
	for _, r := range u.regs {
		if PendingExpired(r, now) {
			delete(u.runs, r.ID)
		}
	}
}

// evict drops entries of u until there is room for one more: the user's
// own deleted tombstones first (oldest first), then expired pending
// entries, then the gateway's tombstones, whose sandboxes are retired.
// Live and unexpired pending entries are never evicted. It returns the
// entries it dropped.
func (s *FileStore) evict(u *uidRecords) []Registration {
	now, limit := s.now(), s.maxEntries()
	var dropped []Registration
	for _, evictable := range []func(Registration) bool{
		func(r Registration) bool { return r.State == StateRevoked && r.RevokedReason == ReasonDeleted },
		func(r Registration) bool { return PendingExpired(r, now) },
		func(r Registration) bool {
			return r.State == StateRevoked && (r.RevokedReason != ReasonPolicyChanged ||
				!now.Before(r.RevokedAt.Add(RevokedTelemetryWindow)))
		},
	} {
		for len(u.regs) >= limit {
			oldest := -1
			for i, r := range u.regs {
				if evictable(r) && (oldest < 0 || regEventTime(r).Before(regEventTime(u.regs[oldest]))) {
					oldest = i
				}
			}
			if oldest < 0 {
				break
			}
			s.retire(u, u.regs[oldest])
			delete(u.runs, u.regs[oldest].ID)
			dropped = append(dropped, u.regs[oldest])
			u.regs = slices.Delete(u.regs, oldest, oldest+1)
		}
	}
	return dropped
}

// notifyGone tells OnGone of the registrations a stored write revoked,
// removed or evicted. The caller no longer holds s.mu.
func (s *FileStore) notifyGone(gone []Registration) {
	if s.OnGone == nil {
		return
	}
	for _, r := range gone {
		s.OnGone(r)
	}
}

// retire keeps the sandbox ids of r, a tombstone being dropped, when the
// gateway revoked it, so its sandbox never registers again.
func (s *FileStore) retire(u *uidRecords, r Registration) {
	if r.State != StateRevoked || r.RevokedReason == ReasonDeleted || (r.BindingID == "" && r.SandboxID == "") {
		return
	}
	u.retired = append(u.retired, Retired{BindingID: r.BindingID, SandboxID: r.SandboxID, At: s.now()})
	if len(u.retired) > MaxRetiredPerUID {
		u.retired = slices.Delete(u.retired, 0, len(u.retired)-MaxRetiredPerUID)
	}
}

func (s *FileStore) maxRunBytes() int {
	if s.runLimit > 0 {
		return s.runLimit
	}
	return MaxRunBytesPerUID
}

func (s *FileStore) maxEntries() int {
	if s.limit > 0 {
		return s.limit
	}
	return MaxEntriesPerUID
}

func regEventTime(r Registration) time.Time {
	if !r.RevokedAt.IsZero() {
		return r.RevokedAt
	}
	return r.CreatedAt
}

// Get returns uid's registration id. Another uid's id, or a malformed one,
// is not found.
func (s *FileStore) Get(uid int, id string) (Registration, bool, error) {
	if !ValidID(id) {
		return Registration{}, false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u, err := s.loadLocked(uid)
	if err != nil {
		return Registration{}, false, err
	}
	for _, r := range u.regs {
		if r.ID == id {
			return r, true, nil
		}
	}
	return Registration{}, false, nil
}

// Run returns the run record of uid's registration id; ok is false when it
// has none (a tombstone without a stop, an unknown id, another uid's id).
func (s *FileStore) Run(uid int, id string) (Run, bool, error) {
	if !ValidID(id) {
		return Run{}, false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u, err := s.loadLocked(uid)
	if err != nil {
		return Run{}, false, err
	}
	run, ok := u.runs[id]
	return run, ok, nil
}

// Bind turns uid's pending, unexpired registration id live for the sandbox
// b names. A binding id or sandbox id that matches a tombstone or a
// retired sandbox, or that another registration already holds, is
// refused.
func (s *FileStore) Bind(uid int, id string, b sandboxrelay.BindRequest) (Registration, error) {
	if err := ValidBind(b); err != nil {
		return Registration{}, err
	}
	if !ValidID(id) {
		return Registration{}, ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u, err := s.loadLocked(uid)
	if err != nil {
		return Registration{}, err
	}
	// The IDs are caller supplied. A different account can make the same
	// claim, so reserve each ID across the whole managed gateway.
	uids, err := storeUIDs(s.dir)
	if err != nil {
		return Registration{}, err
	}
	seen := map[int]bool{}
	for _, otherUID := range uids {
		seen[otherUID] = true
	}
	for otherUID := range s.uids {
		seen[otherUID] = true
	}
	for otherUID := range seen {
		if otherUID == uid {
			continue
		}
		other, err := s.loadLocked(otherUID)
		if err != nil {
			return Registration{}, err
		}
		for _, held := range other.regs {
			if held.BindingID == b.BindingID || held.SandboxID == b.SandboxID {
				return Registration{}, ErrInUse
			}
		}
		for _, retired := range other.retired {
			if retired.BindingID == b.BindingID || retired.SandboxID == b.SandboxID {
				return Registration{}, ErrInUse
			}
		}
	}
	at := -1
	for i, r := range u.regs {
		if r.ID == id {
			at = i
			continue
		}
		same := r.BindingID == b.BindingID || r.SandboxID == b.SandboxID
		if !same {
			continue
		}
		if r.State == StateRevoked {
			return Registration{}, ErrTombstoned
		}
		return Registration{}, ErrInUse
	}
	if at < 0 {
		return Registration{}, ErrNotFound
	}
	for _, gone := range u.retired {
		if gone.BindingID == b.BindingID || gone.SandboxID == b.SandboxID {
			return Registration{}, ErrTombstoned
		}
	}
	r := u.regs[at]
	now := s.now()
	switch {
	case r.State == StateRevoked:
		return Registration{}, ErrRevoked
	case r.State != StatePending:
		return Registration{}, ErrNotPending
	case PendingExpired(r, now):
		return Registration{}, ErrExpired
	case b.Driver != "" && r.Driver != "" && b.Driver != r.Driver:
		return Registration{}, ErrDriverMismatch
	}
	r.State, r.BoundAt, r.SeenAt = StateLive, now, now
	r.GuestWatch, r.GuestSeenAt = true, time.Time{}
	r.SandboxID, r.SandboxName, r.BindingID = b.SandboxID, b.SandboxName, b.BindingID
	next := u.clone()
	next.regs[at] = r
	if err := s.saveLocked(uid, next); err != nil {
		return Registration{}, err
	}
	return r, nil
}

// MarkGuestSeen stores the first accepted record for a bound sandbox. A
// duplicate leaves the original sighting and store file unchanged.
func (s *FileStore) MarkGuestSeen(uid int, id string, at time.Time) error {
	if !ValidID(id) {
		return ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u, err := s.loadLocked(uid)
	if err != nil {
		return err
	}
	for i, r := range u.regs {
		if r.ID != id {
			continue
		}
		switch {
		case r.State == StateRevoked:
			return ErrRevoked
		case !r.GuestWatch || r.BoundAt.IsZero() || r.SandboxName == "":
			return ErrNotPending
		case at.IsZero() || at.Before(r.BoundAt):
			return ErrInvalid
		case !r.GuestSeenAt.IsZero():
			return nil
		}
		r.GuestSeenAt = at.UTC()
		next := u.clone()
		next.regs[i] = r
		return s.saveLocked(uid, next)
	}
	return ErrNotFound
}

// Revoke keeps uid's registration id as a tombstone with reason and drops
// its run record but for the stop a re-match asked for. Revoking a
// tombstone again keeps its first reason.
func (s *FileStore) Revoke(uid int, id, reason string) error {
	if !ValidID(id) {
		return ErrNotFound
	}
	var gone []Registration
	defer func() { s.notifyGone(gone) }()
	s.mu.Lock()
	defer s.mu.Unlock()
	u, err := s.loadLocked(uid)
	if err != nil {
		return err
	}
	for i, r := range u.regs {
		if r.ID != id {
			continue
		}
		if r.State == StateRevoked {
			return nil
		}
		r.State, r.RevokedReason, r.RevokedAt = StateRevoked, boundedReason(reason), s.now()
		next := u.clone()
		next.regs[i] = r
		if err := s.saveLocked(uid, next); err != nil {
			return err
		}
		gone = append(gone, r)
		return nil
	}
	return ErrNotFound
}

// Deleted records that the sandbox of uid's registration id is gone:
//
//   - a pending entry is removed;
//   - a live entry becomes a tombstone (ReasonDeleted), so its sandbox ids
//     never register again;
//   - a tombstone is removed; when the gateway revoked it, its sandbox ids
//     are retired and still never register again.
func (s *FileStore) Deleted(uid int, id string) error {
	if !ValidID(id) {
		return ErrNotFound
	}
	var gone []Registration
	defer func() { s.notifyGone(gone) }()
	s.mu.Lock()
	defer s.mu.Unlock()
	u, err := s.loadLocked(uid)
	if err != nil {
		return err
	}
	for i, r := range u.regs {
		if r.ID != id {
			continue
		}
		next := u.clone()
		switch r.State {
		case StateLive, StateStopped:
			r.State, r.RevokedReason, r.RevokedAt = StateRevoked, ReasonDeleted, s.now()
			next.regs[i] = r
		case StateRevoked:
			if r.RevokedReason != ReasonPolicyChanged || !s.now().Before(r.RevokedAt.Add(RevokedTelemetryWindow)) {
				s.retire(next, r)
				next.regs = slices.Delete(next.regs, i, i+1)
			}
		default:
			next.regs = slices.Delete(next.regs, i, i+1)
		}
		delete(next.runs, id)
		if err := s.saveLocked(uid, next); err != nil {
			return err
		}
		gone = append(gone, r)
		return nil
	}
	return ErrNotFound
}

// seenWriteEvery bounds how often a running report that changes nothing
// but the time rewrites the uid's file; LiveLease leaves room for it and
// two missed polls.
const seenWriteEvery = 2 * time.Minute

// Report records what uid's daemon sees of registration id's sandbox now
// (GAP-0505):
//
//   - running: the registration is live again and its LiveLease renewed.
//     After a stop (a not-running report, or none for LiveLease) the
//     sandbox runs a new session from now on (SessionAt): the daemon ends
//     its session decisions when it starts the sandbox again, and the
//     gateway no longer applies its own record of them (GAP-0009);
//   - not running: it is stopped, so it authorizes no relayed call until a
//     running report.
//
// A pending entry is ErrNotPending (only a bound sandbox runs), a tombstone
// ErrRevoked. It returns the registration as stored afterwards.
func (s *FileStore) Report(uid int, id string, running bool) (Registration, error) {
	if !ValidID(id) {
		return Registration{}, ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u, err := s.loadLocked(uid)
	if err != nil {
		return Registration{}, err
	}
	for i, r := range u.regs {
		if r.ID != id {
			continue
		}
		switch r.State {
		case StateRevoked:
			return r, ErrRevoked
		case StatePending:
			return r, ErrNotPending
		}
		now := s.now()
		next := r
		switch {
		case running:
			if r.State == StateLive && now.Sub(leaseStart(r)) < seenWriteEvery {
				return r, nil
			}
			if EffectiveState(r, now) == StateStopped {
				next.SessionAt = now
			}
			next.State, next.SeenAt = StateLive, now
		case r.State == StateStopped:
			return r, nil
		default:
			next.State = StateStopped
		}
		nu := u.clone()
		nu.regs[i] = next
		if err := s.saveLocked(uid, nu); err != nil {
			return r, err
		}
		return next, nil
	}
	return Registration{}, ErrNotFound
}

// RevokeSandbox revokes uid's bound registrations of one sandbox, the one
// with id sandboxID (a registration bound without an id: named
// sandboxName), with reason, and returns them as revoked. The sandbox ids
// of a gateway revocation never register again (GAP-0529).
func (s *FileStore) RevokeSandbox(uid int, sandboxID, sandboxName, reason string) ([]Registration, error) {
	if sandboxID == "" && sandboxName == "" {
		return nil, nil
	}
	var gone []Registration
	defer func() { s.notifyGone(gone) }()
	s.mu.Lock()
	defer s.mu.Unlock()
	u, err := s.loadLocked(uid)
	if err != nil {
		return nil, err
	}
	var next *uidRecords
	var revoked []Registration
	now := s.now()
	for i, r := range u.regs {
		if r.State != StateLive && r.State != StateStopped {
			continue
		}
		same := sandboxID != "" && r.SandboxID == sandboxID
		if r.SandboxID == "" {
			same = sandboxName != "" && r.SandboxName == sandboxName
		}
		if !same {
			continue
		}
		if next == nil {
			next = u.clone()
		}
		r.State, r.RevokedReason, r.RevokedAt = StateRevoked, boundedReason(reason), now
		next.regs[i] = r
		revoked = append(revoked, r)
	}
	if next == nil {
		return nil, nil
	}
	if err := s.saveLocked(uid, next); err != nil {
		return nil, err
	}
	gone = revoked
	return revoked, nil
}

// List returns uid's registrations, oldest first.
func (s *FileStore) List(uid int) ([]Registration, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, err := s.loadLocked(uid)
	if err != nil {
		return nil, err
	}
	return slices.Clone(u.regs), nil
}

// ListAll returns every uid's registrations: the files on disk and any uid
// cached since. A unreadable file fails the whole call.
func (s *FileStore) ListAll() ([]Registration, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	uids, err := storeUIDs(s.dir)
	if err != nil {
		return nil, err
	}
	for uid := range s.uids {
		if !slices.Contains(uids, uid) {
			uids = append(uids, uid)
		}
	}
	slices.Sort(uids)
	var out []Registration
	for _, uid := range uids {
		u, err := s.loadLocked(uid)
		if err != nil {
			return nil, err
		}
		out = append(out, u.regs...)
	}
	return out, nil
}

// Update rewrites uid's registration r.ID in place (re-match). The id, uid,
// subject, state, sandbox and times stay the store's but for a later
// PolicyAt, and a CreateProfile once set stays; only the match, digests,
// generation and provisional flag change. Its run record stays.
func (s *FileStore) Update(uid int, r Registration) error {
	return s.UpdateRun(uid, r, nil)
}

// UpdateRun is Update that also replaces the run record of a pending or
// live registration (nil: keep it).
func (s *FileStore) UpdateRun(uid int, r Registration, run *Run) error {
	if !ValidID(r.ID) {
		return ErrNotFound
	}
	if run != nil {
		if _, err := runSize(*run); err != nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u, err := s.loadLocked(uid)
	if err != nil {
		return err
	}
	for i, have := range u.regs {
		if have.ID != r.ID {
			continue
		}
		have.Profile, have.ProfileMatch, have.MatchedGroup = r.Profile, r.ProfileMatch, r.MatchedGroup
		have.ProfileMembers = slices.Clone(r.ProfileMembers)
		have.ProfileDigest, have.EffectiveDigest, have.FactsDigest = r.ProfileDigest, r.EffectiveDigest, r.FactsDigest
		have.Generation, have.Provisional = r.Generation, r.Provisional
		if have.CreateProfile == nil && r.CreateProfile != nil {
			// Set once: the profile a sandbox was created under never moves.
			created := *r.CreateProfile
			have.CreateProfile = &created
			have.CreateProfileMembers = slices.Clone(r.CreateProfileMembers)
		}
		if r.PolicyAt.After(have.PolicyAt) {
			have.PolicyAt = r.PolicyAt
		}
		next := u.clone()
		next.regs[i] = have
		if run != nil && have.State != StateRevoked {
			if next.runs == nil {
				next.runs = map[string]Run{}
			}
			next.runs[r.ID] = *run
		}
		return s.saveLocked(uid, next)
	}
	return ErrNotFound
}

// Purge removes the whole store.
func (s *FileStore) Purge() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.uids = make(map[int]*uidRecords)
	if err := os.RemoveAll(s.dir); err != nil {
		return fmt.Errorf("sandboxreg: purge %s: %w", s.dir, err)
	}
	return nil
}

func boundedReason(reason string) string {
	reason = strings.TrimSpace(reason)
	if len(reason) > 256 {
		reason = reason[:256]
	}
	return reason
}

// readStoreFile decodes one store file into v after checking it is a
// private regular file (no link, mode 0600 or tighter). A missing file
// returns an error wrapping os.ErrNotExist.
func readStoreFile(path string, v any) error {
	if _, err := os.Lstat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return err
		}
		return fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	if err := safefile.ValidatePrivateFile(path); err != nil {
		return fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	data, err := safefile.ReadRegularFileBounded(path, maxStoreFileBytes)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("%w: decode %s: %v", ErrCorrupt, filepath.Base(path), err)
	}
	return nil
}

// writeStoreFile writes v as path atomically inside the private directory
// dir (created 0700).
func writeStoreFile(dir, path string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if err := safefile.ProtectDirectory(dir); err != nil {
		return fmt.Errorf("sandboxreg: store directory: %w", err)
	}
	if err := safefile.Write(path, data); err != nil {
		return fmt.Errorf("sandboxreg: write %s: %w", filepath.Base(path), err)
	}
	return nil
}

// storeUIDs lists the uids with a file in dir; a missing dir has none.
func storeUIDs(dir string) ([]int, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	var uids []int
	for _, entry := range entries {
		name := entry.Name()
		if !uidFilePattern.MatchString(name) {
			continue
		}
		uid, err := strconv.Atoi(strings.TrimSuffix(name, ".json"))
		if err == nil {
			uids = append(uids, uid)
		}
	}
	return uids, nil
}
