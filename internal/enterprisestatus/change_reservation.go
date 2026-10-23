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

package enterprisestatus

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
)

// A command that changes the trust anchors or a credential reserves room
// for its change event before it changes anything (Reserve) and holds the
// reservation until the event is written. Without it two commands could
// both find room, the first fill the spool, and the second be left with a
// change it cannot record. The spool lock (<StateDir>/change-events.lock)
// is held only while a command counts and reserves, or writes an event.
// A reservation is <Dir>/reserved/<event_id>.json, with the access of the
// spool: the event the change records if its command ends before it
// writes one (failed, interrupted), flushed with its folder before the
// change is made. Its command holds a lock on it from before the event is
// in it until the file is emptied. The outcome the command then writes is
// another event, with its own id (the hash of its content), that names the
// reservation (reservation_id); the spool settles a reservation with that
// event or with the reserved event itself. A reservation nobody holds
// belongs to a command that ended. Unless the spool settles it, the gateway
// reports its event at its next poll, a restart included
// (EndedChangeReservations), and the next writer moves it into the spool,
// so the attempt is reported even when no other command runs.

const (
	changeSpoolLockName = "change-events.lock"
	// ChangeReservedDirName is the folder of the reservations in the spool.
	ChangeReservedDirName = "reserved"
	// ChangeInterrupted is the reason code of a change whose command ended
	// before it recorded the outcome.
	ChangeInterrupted = "interrupted"
)

var (
	// changeSpoolLockWait bounds the wait for the spool lock, which a
	// writer holds for one count or one write.
	changeSpoolLockWait = 30 * time.Second
	changeSpoolLockPoll = 10 * time.Millisecond
	// changeReservationLockWait bounds the wait for the lock of a new
	// reservation, which the gateway holds only while it reads it.
	changeReservationLockWait = time.Second

	errChangeSpoolBusy       = errors.New("another command is writing a change event; try again")
	errChangeReservationUsed = errors.New("the change event reservation was already used")

	// syncChangeDir and syncChangeFile flush a folder of the spool (a new
	// or removed entry in it) and a file whose access Publish changed;
	// syncChangeHandle flushes an emptied reservation through its open
	// handle. Tests replace them.
	syncChangeDir    = configwrite.SyncDir
	syncChangeFile   = configwrite.SyncFile
	syncChangeHandle = (*os.File).Sync
	// flushEndedReservation flushes a reservation the gateway read through
	// its read-only handle (POSIX fsync needs no write access; Windows
	// cannot flush a read-only handle and journals the file).
	flushEndedReservation = func(file *os.File) error {
		if runtime.GOOS == "windows" {
			return nil
		}
		return file.Sync()
	}
)

// ChangeReservation is the room in the spool for the event of one change in
// progress.
type ChangeReservation struct {
	spool ChangeSpool
	id    string
	path  string
	file  *os.File
}

// Reserve holds room for the event of a change about to be made; kind,
// action and name (the credential, "" for none) say what it changes. It
// returns ErrChangeSpoolFull when the spool cannot take one more event.
// The command then writes the outcome with Write, or calls Release when it
// changed nothing. The reservation is durable when Reserve returns: its
// file, its entry in the reserved folder and the folders created for it
// are flushed, so a power loss after the change cannot lose the event.
func (s ChangeSpool) Reserve(kind, action, name string) (*ChangeReservation, error) {
	ev := NewChangeEvent(kind, action, ChangeFailed, ChangeInterrupted)
	if kind == ChangeKindSecret && ValidChangeSecretName(name) {
		ev.SecretName = name
	}
	return s.reserve(ev)
}

// reserve holds room for ev under its id (ContentID); ev is what the spool
// records if its command ends before it writes its outcome.
func (s ChangeSpool) reserve(ev ChangeEvent) (*ChangeReservation, error) {
	ev, data, err := marshalChangeEvent(ev)
	if err != nil {
		return nil, err
	}
	unlock, err := s.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := s.ready(); err != nil {
		return nil, err
	}
	dir := s.reservedDir()
	if err := s.prepareDir(dir); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, ev.EventID+".json")
	file, err := openChangeFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*ChangeReservation, error) {
		// The command changes nothing: the reservation is emptied and
		// flushed before it goes, so one a power loss brings back records
		// nothing.
		_ = dropChangeReservation(file, path)
		return nil, err
	}
	// Locked before the event is in it: a reader takes the lock first, so
	// it finds a reservation in progress held, or empty.
	if err := lockNewChangeFile(file, path); err != nil {
		return fail(err)
	}
	if s.Publish != nil {
		if err := s.Publish(path); err != nil {
			return fail(err)
		}
	}
	if _, err := file.Write(data); err != nil {
		return fail(err)
	}
	if err := file.Sync(); err != nil {
		return fail(err)
	}
	if err := syncChangeDir(dir); err != nil {
		return fail(err)
	}
	return &ChangeReservation{spool: s, id: ev.EventID, path: path, file: file}, nil
}

// lockNewChangeFile locks a reservation just created. Only a reader that
// found it before its event was written can hold the lock, and only for
// that read.
func lockNewChangeFile(file *os.File, path string) error {
	deadline := time.Now().Add(changeReservationLockWait)
	for {
		locked, err := tryLockChangeFile(file)
		if err != nil {
			return err
		}
		if locked {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("cannot lock the change event reservation %s", path)
		}
		time.Sleep(changeSpoolLockPoll)
	}
}

func (s ChangeSpool) reservedDir() string { return filepath.Join(s.Dir, ChangeReservedDirName) }

// Write records ev, the outcome of the change, in the reserved room: ev
// names the reservation (reservation_id) and gets its own id, the hash of
// its content. When it cannot, the reservation is left for the next writer,
// which records the change as interrupted.
func (r *ChangeReservation) Write(ev ChangeEvent) error {
	if r == nil || r.file == nil {
		return errChangeReservationUsed
	}
	ev.ReservationID = r.id
	ev, data, err := marshalChangeEvent(ev)
	if err != nil {
		r.abandon()
		return err
	}
	return r.commit(ev.EventID, data)
}

// commit writes the event id (data, which settles the reservation) into the
// spool, then lets go of the reservation.
func (r *ChangeReservation) commit(id string, data []byte) error {
	unlock, err := r.spool.lock()
	if err != nil {
		r.abandon()
		return err
	}
	defer unlock()
	if err := r.spool.writeEvent(id, data); err != nil {
		r.abandon()
		return err
	}
	// The event that settles the reservation is durable, so a reservation a
	// power loss brings back is not recorded again (recordInterrupted,
	// EndedChangeReservations): a release that is not flushed changes
	// nothing here.
	_ = r.drop()
	return nil
}

// Release gives the room back when the change was not made and records
// nothing. It does nothing after Write. The release is durable when it
// returns nil. Its error says it could not be flushed: a power loss could
// then bring the reservation back, and the gateway would report the
// command as a change that was interrupted.
func (r *ChangeReservation) Release() error {
	if r == nil || r.file == nil {
		return nil
	}
	return r.drop()
}

func (r *ChangeReservation) drop() error {
	file := r.file
	r.file = nil
	return dropChangeReservation(file, r.path)
}

// dropChangeReservation empties the reservation file before it unlocks,
// closes and removes it: a reader that takes the lock in between finds no
// event in it and records nothing. The emptied file is flushed while it is
// still in the reserved folder, and the folder after the removal (POSIX),
// so a power loss cannot bring the event back. It is durable when either
// flush worked: an empty reservation records nothing, and a removed one is
// gone. A removal that fails (Windows, while the gateway has it open)
// leaves the empty file, which the next writer removes. On Windows the
// folder cannot be flushed (configwrite.SyncDir), so only the emptied file
// makes it durable there. The error says neither could be flushed.
func dropChangeReservation(file *os.File, path string) error {
	emptied := file.Truncate(0)
	if emptied == nil {
		emptied = syncChangeHandle(file)
	}
	unlockChangeFile(file)
	_ = file.Close()
	removed := os.Remove(path)
	if removed == nil || errors.Is(removed, fs.ErrNotExist) {
		removed = syncChangeDir(filepath.Dir(path))
	}
	if runtime.GOOS == "windows" && removed == nil {
		removed = errors.New("a removal is not flushed on Windows")
	}
	if emptied == nil || removed == nil {
		return nil
	}
	return fmt.Errorf("the change event reservation %s could not be flushed: %w", filepath.Base(path), errors.Join(emptied, removed))
}

func (r *ChangeReservation) abandon() {
	unlockChangeFile(r.file)
	_ = r.file.Close()
	r.file = nil
}

// lock takes the spool lock, waiting at most changeSpoolLockWait.
func (s ChangeSpool) lock() (func(), error) {
	if strings.TrimSpace(s.StateDir) == "" {
		return nil, errors.New("the change spool has no state directory")
	}
	if err := requireDirectory(s.StateDir); err != nil {
		return nil, err
	}
	file, err := openChangeFile(filepath.Join(s.StateDir, changeSpoolLockName), os.O_RDWR|os.O_CREATE)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(changeSpoolLockWait)
	for {
		locked, err := tryLockChangeFile(file)
		if err != nil {
			_ = file.Close()
			return nil, err
		}
		if locked {
			return func() {
				unlockChangeFile(file)
				_ = file.Close()
			}, nil
		}
		if !time.Now().Before(deadline) {
			_ = file.Close()
			return nil, errChangeSpoolBusy
		}
		time.Sleep(changeSpoolLockPoll)
	}
}

func requireDirectory(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a regular directory", dir)
	}
	return nil
}

// settleReservations counts the reservations still held and records the
// event of every other one, whose command ended before it wrote its own.
// The caller holds the spool lock.
func (s ChangeSpool) settleReservations() (held int, err error) {
	dir := s.reservedDir()
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	settled := lazyChangeSettlements(s.Dir)
	for _, entry := range entries {
		id, ok := strings.CutSuffix(entry.Name(), ".json")
		if !ok || !ValidChangeEventID(id) || !entry.Type().IsRegular() {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		file, err := openChangeFile(path, os.O_RDWR)
		if err != nil {
			held++
			continue
		}
		locked, err := tryLockChangeFile(file)
		if err != nil || !locked {
			_ = file.Close()
			held++
			continue
		}
		err = s.recordInterrupted(id, file, settled)
		unlockChangeFile(file)
		_ = file.Close()
		if err != nil {
			return held, err
		}
		_ = os.Remove(path)
	}
	return held, nil
}

// recordInterrupted writes the event of a reservation whose command ended,
// unless the gateway already reported it or the spool settles it (settled:
// the outcome its command wrote, or the reserved event already moved in).
// The caller removes the reservation only when it returns nil, so an event
// that settles it is kept only once it validates and Publish gave it the
// gateway's access again (an access changed since is restored; a failure
// keeps the reservation). An event file under the reservation's id that
// does not validate is replaced by the reservation's event. A damaged
// reservation records nothing.
func (s ChangeSpool) recordInterrupted(id string, file *os.File, settled func(id string) (string, bool)) error {
	if s.Reported != nil && s.Reported(id) {
		return nil
	}
	if path, ok := settled(id); ok {
		if s.Publish != nil {
			if err := s.Publish(path); err != nil {
				return err
			}
			// The access is durable before the reservation goes.
			if err := syncChangeFile(path); err != nil {
				return err
			}
		}
		// Its command may have stopped after the rename and before it
		// flushed the spool: the event's entry is durable before the
		// reservation goes.
		return syncChangeDir(s.Dir)
	}
	raw, _, ok := readReservation(file, id)
	if !ok {
		return nil
	}
	return s.writeEvent(id, raw)
}

// changeSettlements maps the id of every reservation the spool dir settles
// to the event file that settles it: each event that validates settles its
// own id (a reserved event moved into the spool) and the reservation it
// names (the outcome its command wrote).
func changeSettlements(dir string) map[string]string {
	settled := map[string]string{}
	for _, id := range ListChangeEventIDs(dir) {
		path := filepath.Join(dir, id+".json")
		ev, err := ReadChangeEvent(path)
		if err != nil || ev.EventID != id {
			continue
		}
		settled[id] = path
		if ev.ReservationID != "" {
			settled[ev.ReservationID] = path
		}
	}
	return settled
}

// lazyChangeSettlements reads changeSettlements(dir) on its first call
// only: the spool is read only when a reservation's command ended.
func lazyChangeSettlements(dir string) func(id string) (string, bool) {
	var settled map[string]string
	return func(id string) (string, bool) {
		if settled == nil {
			settled = changeSettlements(dir)
		}
		path, ok := settled[id]
		return path, ok
	}
}

// readReservation reads the event of reservation id from file. An emptied
// reservation (its command wrote its event or changed nothing) and one
// that does not validate are not ok.
func readReservation(file *os.File, id string) ([]byte, ChangeEvent, bool) {
	raw, err := io.ReadAll(io.LimitReader(file, maxChangeEventBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxChangeEventBytes {
		return nil, ChangeEvent{}, false
	}
	var ev ChangeEvent
	if json.Unmarshal(raw, &ev) != nil || ev.EventID != id || ev.Validate() != nil {
		return nil, ChangeEvent{}, false
	}
	return raw, ev, true
}

// EndedChangeReservations is for the gateway, which reads the change spool
// dir and cannot write it. It returns, oldest first, the event of every
// reservation whose command ended before it wrote its outcome and that no
// event the gateway can read and validate settles (changeSettlements):
// the change it held room for may have been made, so it is
// reported as failed (interrupted) at the gateway's next poll, even when
// no later command moves it into the spool. A reservation still held, an
// emptied one and one that does not validate are skipped.
// The writer that settles the reservation later keeps its id, so the
// gateway reports it once.
func EndedChangeReservations(dir string) []ChangeEvent {
	reserved := filepath.Join(dir, ChangeReservedDirName)
	if requireDirectory(dir) != nil || requireDirectory(reserved) != nil {
		return nil
	}
	entries, err := os.ReadDir(reserved)
	if err != nil {
		return nil
	}
	var out []ChangeEvent
	settled := lazyChangeSettlements(dir)
	for _, entry := range entries {
		id, ok := strings.CutSuffix(entry.Name(), ".json")
		if !ok || !ValidChangeEventID(id) || !entry.Type().IsRegular() {
			continue
		}
		if ev, ok := readEndedReservation(filepath.Join(reserved, entry.Name()), id, settled); ok {
			out = append(out, ev)
		}
	}
	return out
}

func readEndedReservation(path, id string, settled func(id string) (string, bool)) (ChangeEvent, bool) {
	file, err := openChangeFile(path, os.O_RDONLY)
	if err != nil {
		return ChangeEvent{}, false
	}
	defer file.Close()
	if locked, err := tryLockChangeFile(file); err != nil || !locked {
		return ChangeEvent{}, false
	}
	defer unlockChangeFile(file)
	// Its command writes the event that settles it into the spool before it
	// lets go of the reservation, so an event there that the gateway reads
	// is the outcome. One it cannot read or validate settles nothing, so the
	// reservation is reported.
	if _, ok := settled(id); ok {
		return ChangeEvent{}, false
	}
	_, ev, ok := readReservation(file, id)
	// A command that stopped inside Reserve may not have flushed its
	// reservation: it is reported only once it is on disk to stay.
	if !ok || flushEndedReservation(file) != nil || syncChangeDir(filepath.Dir(path)) != nil {
		return ChangeEvent{}, false
	}
	return ev, true
}

// changeReservationHeld reports whether the reservation at path exists and
// its command holds it. A reservation the gateway cannot open or lock is
// counted as held.
func changeReservationHeld(path string) bool {
	file, err := openChangeFile(path, os.O_RDONLY)
	if errors.Is(err, fs.ErrNotExist) {
		return false
	}
	if err != nil {
		return true
	}
	defer file.Close()
	locked, err := tryLockChangeFile(file)
	if err != nil || !locked {
		return true
	}
	unlockChangeFile(file)
	return false
}
