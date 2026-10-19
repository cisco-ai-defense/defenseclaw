// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package workspace

import (
	"context"
	"errors"
	"maps"
	"os"
	"slices"
	"sync"
)

// HostStage is an owned, private sanitized project artifact on the trusted
// host. It contains no guest paths, runtime admission or launch authority.
// Its paths and summary are host-confidential and must not enter guest plans.
// Close must run after the owning adapter has finished reading the artifact.
type HostStage struct {
	mu       sync.Mutex
	record   CopyRecord
	identity string
	closed   bool
	close    func() error
	closeErr error
	// A refused Linux preparation can still own exact residue and handles.
	// It has cleanup authority only, never a borrowable sanitized artifact.
	cleanupOnly bool
	// Root acquisition and release reserve custody before doing native I/O.
	// A close request blocks new borrowers without waiting for that I/O.
	closeRequested bool
	duplicateRoot  func() (*os.File, error)
	rootLeases     map[*RootLease]struct{}
}

const maxHostStageRootLeases = 64

var (
	// ErrHostStageInUse means consumer custody must be released before cleanup.
	ErrHostStageInUse  = errors.New("workspace: host stage still has root consumer custody")
	errHostStageClosed = errors.New("workspace: host stage is closing or closed")
)

// RootLease owns one limited-access, non-inheritable directory handle. File is
// borrowed: callers must not close it or transfer it to an exclusive owner.
// A lease is custody only, not guest filesystem permission or runtime admission.
// The current AXIS NewAssets consumes exclusive handles and cannot consume this
// borrowed File directly. A future factory must make its own independent copy,
// retain this lease through native cleanup AND successful Assets closure, then
// close this lease before retrying HostStage.Close.
type RootLease struct {
	stage     *HostStage
	file      *os.File
	closeFile func() error
	pending   bool
	copying   int
	releasing bool
	released  bool
	admitErr  error
	closeErr  error
}

// AcquireRoot duplicates the already-held sanitized tree, never TreePath. No
// acquisition may begin after a close request. A nonnil lease owns cleanup even
// when err is nonnil (for example, close won during native validation); File
// refuses such a lease. A consumer must explicitly release it.
func (s *HostStage) AcquireRoot() (*RootLease, error) {
	if s == nil {
		return nil, errHostStageClosed
	}
	s.mu.Lock()
	if s.closed || s.closeRequested || s.cleanupOnly {
		s.mu.Unlock()
		return nil, errHostStageClosed
	}
	if s.duplicateRoot == nil {
		s.mu.Unlock()
		return nil, ErrUnsupportedPlatform
	}
	if len(s.rootLeases) >= maxHostStageRootLeases {
		s.mu.Unlock()
		return nil, ErrHostStageInUse
	}
	lease := &RootLease{stage: s, pending: true}
	if s.rootLeases == nil {
		s.rootLeases = make(map[*RootLease]struct{})
	}
	s.rootLeases[lease] = struct{}{}
	duplicate := s.duplicateRoot
	s.mu.Unlock()

	file, err := duplicate()
	s.mu.Lock()
	defer s.mu.Unlock()
	lease.pending = false
	if file == nil {
		delete(s.rootLeases, lease)
		if err == nil {
			err = errors.New("workspace: host stage root duplication returned no custody")
		}
		return nil, err
	}
	lease.file, lease.closeFile = file, file.Close
	if s.closeRequested || s.closed {
		err = errors.Join(err, errHostStageClosed)
	}
	lease.admitErr = err
	return lease, err
}

// File returns a borrowed handle to the exact sanitized tree. Limited handle
// access does not prevent relative child opens under the caller's token and
// must never be treated as guest read-only enforcement. No new borrow is issued
// after a close request; previously borrowed handles remain owned by the lease
// until its consumer finishes and explicitly closes it.
func (l *RootLease) File() (*os.File, error) {
	if l == nil || l.stage == nil {
		return nil, errHostStageClosed
	}
	l.stage.mu.Lock()
	defer l.stage.mu.Unlock()
	if l.pending || l.releasing {
		return nil, ErrHostStageInUse
	}
	if l.released || l.file == nil || l.stage.closeRequested {
		return nil, errHostStageClosed
	}
	if err := errors.Join(l.admitErr, l.closeErr); err != nil {
		return nil, err
	}
	return l.file, nil
}

// Duplicate returns an independently owned, limited-access, non-inheritable
// handle to the same sanitized root, without reopening a display pathname.
// The trusted caller must retain this lease until every returned file has
// definitely closed, including a nonnil file returned with an error. Such a
// file is cleanup custody only and must not be used after a refusal. The stage
// cannot prevent a host consumer from breaking this ownership contract.
func (l *RootLease) Duplicate() (*os.File, error) {
	if l == nil || l.stage == nil {
		return nil, errHostStageClosed
	}
	s := l.stage
	s.mu.Lock()
	if l.pending || l.releasing || l.released || l.file == nil || s.closeRequested {
		s.mu.Unlock()
		return nil, errHostStageClosed
	}
	if err := errors.Join(l.admitErr, l.closeErr); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	if l.copying >= maxHostStageRootLeases {
		s.mu.Unlock()
		return nil, ErrHostStageInUse
	}
	l.copying++
	duplicate := s.duplicateRoot
	s.mu.Unlock()
	file, err := duplicate()
	s.mu.Lock()
	defer s.mu.Unlock()
	l.copying--
	if file == nil && err == nil {
		err = errors.New("workspace: host stage root duplication returned no custody")
	}
	if s.closeRequested {
		err = errors.Join(err, errHostStageClosed)
	}
	return file, err
}

// Close releases only this lease, never the stage. A successful close permits a
// later explicit HostStage.Close retry. Uncertain native close is sticky: its
// slot and producer pins remain retained, even if the Go File appears closed.
func (l *RootLease) Close() error {
	if l == nil || l.stage == nil {
		return nil
	}
	s := l.stage
	s.mu.Lock()
	if l.pending || l.releasing || l.copying != 0 {
		s.mu.Unlock()
		return ErrHostStageInUse
	}
	if l.released || l.closeErr != nil {
		err := l.closeErr
		s.mu.Unlock()
		return err
	}
	l.releasing = true
	closeFile := l.closeFile
	s.mu.Unlock()
	var err error
	if closeFile == nil {
		err = errors.New("workspace: host stage root lease has no native closer")
	} else {
		err = closeFile()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	l.releasing = false
	if err != nil {
		l.closeErr = err
		return err
	}
	l.released = true
	l.file = nil
	delete(s.rootLeases, l)
	return nil
}

// HostStageSummary describes host staging only. It is not a persisted copy
// record: a qualified provider must separately bind the guest layout and
// workspace operations before importing this tree.
type HostStageSummary struct {
	Project, SourceIdentity string
	Kind                    CopyKind
	Head, Baseline          string
	Files                   int
	Bytes                   int64
	HeldBack, Unmasked      []string
	Warnings                []string
	Remotes, LineEndings    map[string]string
}

func (s *HostStage) Summary() HostStageSummary {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.record
	return HostStageSummary{
		Project: r.Project, SourceIdentity: s.identity, Kind: r.Kind,
		Head: r.Head, Baseline: r.Baseline, Files: r.Files, Bytes: r.Bytes,
		HeldBack: slices.Clone(r.HeldBack), Unmasked: slices.Clone(r.Unmasked),
		Warnings: slices.Clone(r.Warnings), Remotes: maps.Clone(r.Remotes), LineEndings: maps.Clone(r.LineEndings),
	}
}

// TreePath returns the sanitized host tree while its owner retains custody.
// It is never a guest workspace path or permission to mount the original tree.
func (s *HostStage) TreePath() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.closeRequested || s.cleanupOnly {
		return "", errHostStageClosed
	}
	return s.record.Stage, nil
}

// Close removes only this artifact's private owned root. A bounded cleanup
// refusal is returned to the owner, which must retain/report the residue.
func (s *HostStage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeRequested = true
	if len(s.rootLeases) != 0 {
		err := ErrHostStageInUse
		for lease := range s.rootLeases {
			err = errors.Join(err, lease.closeErr)
		}
		return err
	}
	if s.cleanupOnly && !s.closed {
		// The concrete partial owner distinguishes retryable bounded removal
		// from uncertain native closes, which it latches without retrying.
		s.closeErr = s.close()
		s.closed = s.closeErr == nil
		return s.closeErr
	}
	if !s.closed {
		s.closed = true
		s.closeErr = s.close()
	}
	return s.closeErr
}

// PrepareHostStage captures and sanitizes a host project without enabling any
// guest operations. The initial supported floor is Windows on a genuine local
// fixed NTFS mount, private current-user staging, no reparse points, named
// streams, hardlinks, case-sensitive directories or ambiguous Windows names.
// Linked/external git metadata is refused. Stage and live-mount support are
// unchanged; native Windows requires separate typed guest-operation tests.
// Linux adds a conservative local-root-mount floor: no symbolic/magic links,
// mount crossings, special files or hardlinks, already-private staging, and a
// verified procfs capability alias. It copies through retained descriptors;
// this is race-sampled capture, not an atomic snapshot across multiple files.
// MaxBytes also bounds the initial complete source capture, including git
// metadata and files that the later sanitizer would ignore or hold back.
// A nonnil result with an error owns cleanup-only residue: callers must retain
// it and call Close, and must not treat it as a prepared/borrowable stage.
func PrepareHostStage(ctx context.Context, opts StageOptions) (*HostStage, error) {
	if err := ValidateName(opts.Name); err != nil {
		return nil, err
	}
	if opts.RemoteRoot != "" {
		return nil, errors.New("workspace: host staging accepts no guest remote root")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return prepareHostStagePlatform(ctx, opts)
}
