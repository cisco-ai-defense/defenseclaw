// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

const ownershipSchemaVersion = 1

// Flapping: this many rewrites of an owned file within the window means a
// second writer (an MDM template, config management) keeps replacing it.
const (
	flapThreshold = 3
	flapWindow    = 24 * time.Hour
	flapKeep      = 10
)

// ownershipRecord remembers what DefenseClaw changed in one vendor file so
// removal can restore the administrator's exact preimage.
type ownershipRecord struct {
	SchemaVersion   int      `json:"schema_version"`
	Connector       string   `json:"connector"`
	Path            string   `json:"path"`
	PreimageExisted bool     `json:"preimage_existed"`
	Preimage        []byte   `json:"preimage,omitempty"`
	PreimageSHA256  string   `json:"preimage_sha256"`
	PostimageSHA256 string   `json:"postimage_sha256"`
	CreatedDirs     []string `json:"created_dirs,omitempty"`
	Rewrites        []string `json:"rewrites,omitempty"`
	UpdatedAt       string   `json:"updated_at"`
}

var recordNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)

func recordPath(opts Options, connector string) (string, error) {
	if opts.StateDir == "" {
		return "", errors.New("enterprise policy: ownership state directory is required")
	}
	if !recordNamePattern.MatchString(connector) {
		return "", fmt.Errorf("enterprise policy: invalid connector name %q", connector)
	}
	return filepath.Join(opts.StateDir, connector+".json"), nil
}

func loadRecord(opts Options, connector string) (*ownershipRecord, error) {
	path, err := recordPath(opts, connector)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	file, err := openNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := readBounded(file, 2*policyFileLimit)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var record ownershipRecord
	if err := decoder.Decode(&record); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	if record.SchemaVersion != ownershipSchemaVersion || record.Connector != connector {
		return nil, fmt.Errorf("%s is not a %s ownership record", path, connector)
	}
	if record.PreimageExisted && sha256Hex(record.Preimage) != record.PreimageSHA256 {
		return nil, fmt.Errorf("%s preimage digest does not match its bytes", path)
	}
	return &record, nil
}

func saveRecord(opts Options, record *ownershipRecord) error {
	path, err := recordPath(opts, record.Connector)
	if err != nil {
		return err
	}
	if err := ensurePrivateDir(opts.StateDir); err != nil {
		return err
	}
	record.SchemaVersion = ownershipSchemaVersion
	record.UpdatedAt = opts.now().Format(time.RFC3339)
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(opts, path, append(data, '\n'), false)
}

func deleteRecord(opts Options, connector string) error {
	path, err := recordPath(opts, connector)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// stripFunc removes DefenseClaw-owned content from one vendor file. It
// returns the administrator's remaining bytes and whether any DefenseClaw
// content was found. With nothing owned it must return current unchanged,
// so a file DefenseClaw never touched is never re-encoded.
type stripFunc func(current []byte) (admin []byte, owned bool, err error)

// wholeFileStrip is the stripFunc of a file DefenseClaw owns entirely (its
// 90-defenseclaw.json drop-ins, the Cursor PowerShell adapter): a file that
// carries DefenseClaw's entries is DefenseClaw's, and any other content
// under that name belongs to someone else and is left alone.
func wholeFileStrip(isOwned func([]byte) bool) stripFunc {
	return func(current []byte) ([]byte, bool, error) {
		if isOwned(current) {
			return nil, true, nil
		}
		return current, false, nil
	}
}

// blank reports whether data holds no content worth restoring. An empty
// JSON drop-in is not valid JSON (Claude Code refuses to start with one),
// so blank administrator content means "no file".
func blank(data []byte) bool {
	return len(bytes.TrimSpace(data)) == 0
}

// capturePreimage records what the administrator, not DefenseClaw, keeps in
// path: the current bytes with DefenseClaw's content stripped. A file that
// held only DefenseClaw content (an admin-deployed `policy export`, a file
// left by a crash before the record was saved) has no preimage, so removal
// never puts DefenseClaw's hooks or lock back.
func (r *ownershipRecord) capturePreimage(current []byte, exists bool, strip stripFunc) error {
	r.PreimageExisted, r.Preimage, r.PreimageSHA256 = false, nil, ""
	if !exists {
		return nil
	}
	admin, _, err := strip(current)
	if err != nil {
		return err
	}
	if blank(admin) {
		return nil
	}
	r.PreimageExisted = true
	r.Preimage = append([]byte(nil), admin...)
	r.PreimageSHA256 = sha256Hex(admin)
	return nil
}

// noteRewrite records that the owned entries were found missing from a
// file DefenseClaw had written; it returns how many rewrites happened in
// the flap window.
func (r *ownershipRecord) noteRewrite(now time.Time) int {
	r.Rewrites = append(r.Rewrites, now.Format(time.RFC3339))
	if len(r.Rewrites) > flapKeep {
		r.Rewrites = r.Rewrites[len(r.Rewrites)-flapKeep:]
	}
	count := 0
	for _, stamp := range r.Rewrites {
		when, err := time.Parse(time.RFC3339, stamp)
		if err == nil && now.Sub(when) <= flapWindow {
			count++
		}
	}
	return count
}

// flapConflict reports a second writer that keeps replacing a file
// DefenseClaw owns. The Claude Code version floor drop-in never gets here: a
// floor file that changed is the administrator's, and DefenseClaw does not
// rewrite it.
func flapConflict(state *State, connector, path string, count int) {
	if count >= flapThreshold {
		state.conflict("another writer replaced %s %d times in 24h and removed DefenseClaw's hooks each time; if an MDM or configuration tool owns this file, set enterprise.machine_policy.connectors.%s.ownership: verify_only and deploy the output of `defenseclaw-gateway enterprise policy export --connector %s` through that tool", path, count, connector, connector)
	}
}

// publishWithRecord writes rendered when it differs from current and keeps
// the ownership record in sync. It returns whether the file changed.
// alsoCreated names directories the caller created for this file (a
// vendor directory that replaced a planted object), recorded like the ones
// the write creates so removal deletes them when empty.
//
// The preimage follows the administrator: whenever the file on disk is not
// what DefenseClaw last wrote (someone edited, replaced or deleted it), the
// administrator content of that version replaces the recorded preimage
// before DefenseClaw merges into it. Otherwise a reconcile would fold the
// edit into the postimage and removal would restore the stale install-time
// preimage, dropping the edit (or resurrecting deleted content).
func publishWithRecord(opts Options, connector, path string, current []byte, exists bool, rendered []byte, ownedWasPresent bool, strip stripFunc, state *State, alsoCreated ...string) (bool, error) {
	record, err := loadRecord(opts, connector)
	if err != nil {
		return false, err
	}
	switch {
	case record == nil || record.Path != path:
		record = &ownershipRecord{Connector: connector, Path: path}
		if err := record.capturePreimage(current, exists, strip); err != nil {
			return false, err
		}
	case !exists || sha256Hex(current) != record.PostimageSHA256:
		if record.PostimageSHA256 != "" && exists && !ownedWasPresent {
			flapConflict(state, connector, path, record.noteRewrite(opts.now()))
		}
		if err := record.capturePreimage(current, exists, strip); err != nil {
			return false, err
		}
	}
	record.CreatedDirs = appendUnique(record.CreatedDirs, alsoCreated...)
	changed := !exists || !bytes.Equal(current, rendered)
	if !changed {
		// Same bytes, but a mode or owner an agent may not be able to read
		// through (an administrator's chmod 0600): write it again, which
		// restores both.
		if problem := publishedFileProblem(opts, path); problem != "" {
			changed = true
			state.detail("restored %s to mode 0644 and administrator ownership (it had %s)", path, problem)
		}
	}
	if changed {
		created, err := writePolicyFile(opts, path, rendered)
		record.CreatedDirs = appendUnique(record.CreatedDirs, created...)
		if err != nil {
			return false, err
		}
	}
	record.PostimageSHA256 = sha256Hex(rendered)
	if err := saveRecord(opts, record); err != nil {
		return changed, err
	}
	return changed, nil
}

// ownershipRecordNames lists the ownership records connector's machine
// policy can hold.
func ownershipRecordNames(opts Options, connector string) []string {
	names := []string{connector}
	if connector == ConnectorCursor && opts.goos() == "windows" {
		names = append(names, cursorAdapterRecord)
	}
	if connector == ConnectorClaudeCode {
		names = append(names, claudeVersionFloorRecord)
	}
	return names
}

// verifyPublishedFiles reports, as drift, each policy file DefenseClaw
// published for connector (named by an ownership record, and still what
// DefenseClaw wrote) whose mode or owner changed since: agents may not be
// able to read it, and the next publish restores it. Only ownership: merge
// publishes, so only it is checked.
func verifyPublishedFiles(opts Options, connector string, state *State) {
	if opts.PolicyFor(connector).Ownership != config.MachinePolicyOwnershipMerge {
		return
	}
	for _, name := range ownershipRecordNames(opts, connector) {
		record, err := loadRecord(opts, name)
		if err != nil || record == nil {
			continue
		}
		current, exists, err := readPolicyFile(opts, record.Path)
		if err != nil || !exists || sha256Hex(current) != record.PostimageSHA256 {
			continue
		}
		if problem := publishedFileProblem(opts, record.Path); problem != "" {
			state.Drift = true
			state.conflict("%s has %s; DefenseClaw publishes it with mode 0644, owned by root, so every user's agent can read it; the next lifecycle run that applies changes (ensure, repair or reconcile) restores it", record.Path, problem)
		}
	}
	state.finish()
}

// restoreOrStrip removes DefenseClaw's content from path. When the file is
// exactly what DefenseClaw last wrote, the recorded administrator content
// is restored byte for byte (or the file removed when there was none);
// otherwise strip is applied to the current bytes so later administrator
// edits survive. A file without DefenseClaw content is never rewritten or
// deleted, and a file left with nothing but DefenseClaw content is removed,
// never truncated to an empty (unparsable) policy file.
//
// wholeFile marks a drop-in DefenseClaw owns entirely. Without an ownership
// record such a file was deployed by the administrator (for example the
// `policy export` output under verify_only), so it is left in place.
func restoreOrStrip(opts Options, connector, path string, strip stripFunc, wholeFile bool, state *State) error {
	record, err := loadRecord(opts, connector)
	if err != nil {
		return err
	}
	current, exists, err := readPolicyFile(opts, path)
	if err != nil {
		return err
	}
	switch {
	case !exists:
	case record == nil && wholeFile:
		state.detail("left %s in place: DefenseClaw has no record of writing it", path)
	case record != nil && record.Path == path && sha256Hex(current) == record.PostimageSHA256:
		var admin []byte
		if record.PreimageExisted {
			// Records written before preimages were stripped can hold
			// DefenseClaw's own entries; never restore those.
			if admin, _, err = strip(record.Preimage); err != nil {
				return err
			}
		}
		if blank(admin) {
			if err := removePolicyFile(opts, path); err != nil {
				return err
			}
			state.detail("removed %s (it held no administrator content besides DefenseClaw's)", path)
		} else {
			if _, err := writePolicyFile(opts, path, admin); err != nil {
				return err
			}
			state.detail("restored the administrator content of %s", path)
		}
		state.Changed = true
	default:
		admin, owned, err := strip(current)
		if err != nil {
			if record == nil {
				// No record says DefenseClaw ever wrote this file, and its
				// content cannot be parsed: it is its owner's to fix.
				state.detail("left %s unchanged: %v", path, err)
				break
			}
			return err
		}
		switch {
		case !owned:
			if record != nil {
				state.detail("%s no longer holds DefenseClaw entries; left it unchanged", path)
			}
		case blank(admin):
			if err := removePolicyFile(opts, path); err != nil {
				return err
			}
			state.Changed = true
			state.detail("removed %s (only DefenseClaw content remained)", path)
		default:
			if _, err := writePolicyFile(opts, path, admin); err != nil {
				return err
			}
			state.Changed = true
			state.detail("%s changed after DefenseClaw wrote it; removed only DefenseClaw entries", path)
		}
	}
	if record != nil {
		// Deepest first: a directory recorded later can be the parent of
		// one recorded earlier.
		dirs := append([]string(nil), record.CreatedDirs...)
		sort.SliceStable(dirs, func(i, j int) bool { return len(dirs[i]) > len(dirs[j]) })
		for _, dir := range dirs {
			if err := removeDirIfEmpty(opts, dir); err != nil {
				state.detail("left %s in place: %v", dir, err)
			}
		}
	}
	return deleteRecord(opts, connector)
}

func appendUnique(list []string, values ...string) []string {
	for _, value := range values {
		found := false
		for _, existing := range list {
			if existing == value {
				found = true
				break
			}
		}
		if !found {
			list = append(list, value)
		}
	}
	return list
}
