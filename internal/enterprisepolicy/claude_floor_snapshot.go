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
	"errors"
	"os"
	"slices"

	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
)

// claudeFloorSnapshot is a version floor plan made before the Claude Code
// managed policy lock is taken, with every input it was made from (GAP-1833).
// The plan is applied under the lock only while unchanged reports that each
// of those inputs is still the same file holding the same bytes (or still
// absent) and managed-settings.d still lists the same drop-ins. Every other
// pass reads everything again under the lock, so a writer that changes a
// source between the two steps never gets a plan made from what it replaced.
//
// The trust checks of readPolicyFile ran on the files the snapshot read; the
// check under the lock ties the plan to those same files by identity. Only a
// privileged account can change the protection of a file or folder that
// passed them. The higher-precedence source (HKLM Settings) is read before
// the lock: no DefenseClaw lock orders its writers, so reading it a moment
// earlier is the same as reading it under the lock.
type claudeFloorSnapshot struct {
	plan   claudeFloorPlan
	inputs []claudeFloorInput
	// dropDir is managed-settings.d; dropDirExists and dropIns are what its
	// listing held (the drop-ins that count, sorted).
	dropDir       string
	dropDirExists bool
	dropIns       []string
	// unstable: a file changed while the snapshot read it.
	unstable bool
}

// claudeFloorInput is one file a snapshot read: the bytes and the identity
// of the file they came from, or that path had no file.
type claudeFloorInput struct {
	path   string
	exists bool
	data   []byte
	info   os.FileInfo
	limit  int64
}

// snapshotClaudeVersionFloor reads and plans the floor without the lock. It
// returns nil when the plan cannot be made from a snapshot: an error (the
// pass under the lock reads again and reports it), or a drop-in to adopt
// (adopting saves the record, which only runs under the lock).
func snapshotClaudeVersionFloor(opts Options) *claudeFloorSnapshot {
	s := &claudeFloorSnapshot{}
	sources, err := readClaudeFileSourcesWith(opts, s.readPolicyFile, func(dir string, exists bool, names []string) {
		s.dropDir, s.dropDirExists, s.dropIns = dir, exists, names
	})
	if err != nil {
		return nil
	}
	path, err := ClaudeVersionFloorPath(opts)
	if err != nil {
		return nil
	}
	// The listing's read of the floor drop-in is the one the plan uses; the
	// pass under the lock read it three times.
	current, exists, read := s.input(platformPath(opts, path))
	if !read {
		if current, exists, err = s.readPolicyFile(opts, path); err != nil {
			return nil
		}
	}
	record, err := s.readRecord(opts, claudeVersionFloorRecord)
	if err != nil || s.unstable || claudeFloorAdoptable(opts, record, path, current, exists) {
		return nil
	}
	// As under the lock: an unreadable higher-precedence source can only
	// lead to a floor that source overrides anyway.
	higher, _ := claudeHigherSources(opts)
	s.plan = planClaudeVersionFloorFrom(opts, sources, higher, path, current, exists, record)
	return s
}

// readPolicyFile is readPolicyFile that keeps the file it read as an input.
// The file must be the same one before and after the read.
func (s *claudeFloorSnapshot) readPolicyFile(opts Options, path string) ([]byte, bool, error) {
	local := platformPath(opts, path)
	before, beforeErr := pathidentity.LstatPinned(local)
	data, exists, err := readPolicyFile(opts, path)
	if err != nil {
		return nil, false, err
	}
	in := claudeFloorInput{path: local, exists: exists, data: data, limit: policyFileLimit}
	after, afterErr := pathidentity.LstatPinned(local)
	switch {
	case !exists:
		s.unstable = s.unstable || !errors.Is(beforeErr, os.ErrNotExist) || !errors.Is(afterErr, os.ErrNotExist)
	case beforeErr != nil || afterErr != nil || !os.SameFile(before, after) || after.Size() != int64(len(data)):
		s.unstable = true
	default:
		in.info = after
	}
	s.inputs = append(s.inputs, in)
	return data, exists, nil
}

// readRecord loads the ownership record of connector and keeps its file as
// an input.
func (s *claudeFloorSnapshot) readRecord(opts Options, connector string) (*ownershipRecord, error) {
	path, err := recordPath(opts, connector)
	if err != nil {
		return nil, err
	}
	data, info, exists, err := readRecordFile(path)
	if err != nil {
		return nil, err
	}
	s.inputs = append(s.inputs, claudeFloorInput{path: path, exists: exists, data: data, info: info, limit: recordFileLimit})
	if !exists {
		return nil, nil
	}
	return decodeRecord(path, connector, data)
}

// input returns what the snapshot read at path, and whether it read it.
func (s *claudeFloorSnapshot) input(path string) ([]byte, bool, bool) {
	for _, in := range s.inputs {
		if in.path == path {
			return in.data, in.exists, true
		}
	}
	return nil, false, false
}

// unchanged reports, under the lock, that the snapshot can be applied: the
// drop-in listing and every input are what the snapshot read. A nil
// snapshot is never unchanged.
func (s *claudeFloorSnapshot) unchanged(opts Options) bool {
	if s == nil || s.unstable {
		return false
	}
	entries, err := os.ReadDir(s.dropDir)
	if (err != nil && !errors.Is(err, os.ErrNotExist)) || (err == nil) != s.dropDirExists {
		return false
	}
	names := []string{}
	for _, entry := range entries {
		if effectivePolicyDropIn(entry) {
			names = append(names, entry.Name())
		}
	}
	slices.Sort(names)
	if !slices.Equal(names, s.dropIns) {
		return false
	}
	for _, in := range s.inputs {
		if !in.unchanged() {
			return false
		}
	}
	return true
}

// unchanged reports that path is still the file the snapshot read, with the
// same bytes, or still has no file.
func (in claudeFloorInput) unchanged() bool {
	info, err := pathidentity.LstatPinned(in.path)
	if !in.exists {
		return errors.Is(err, os.ErrNotExist)
	}
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(in.info, info) {
		return false
	}
	file, err := openNoFollowOnce(in.path)
	if err != nil {
		return false
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(in.info, opened) {
		return false
	}
	data, err := readBounded(file, in.limit)
	return err == nil && bytes.Equal(data, in.data)
}
