// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package workspace

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// linuxHostStageOwner retains every allocated object before preparation can
// fail. Uncertain native closure is sticky; bounded removal refusal can retry.
// closeRoot is private pure-test injection, not a runtime/provider dependency.
type linuxHostStageOwner struct {
	access                               *linuxHostAccess
	source, parent, artifact, tree, lock *os.File
	roots                                [3]*os.Root
	name                                 string
	artifactID                           linuxHostIdentity
	created, deleted                     bool
	stickyErr                            error
	closeRoot                            func(*os.Root) error
}

func (o *linuxHostStageOwner) closeFile(file **os.File) error {
	if *file == nil {
		return nil
	}
	if err := (*file).Close(); err != nil {
		o.stickyErr = errors.Join(o.stickyErr, err)
		return o.stickyErr
	}
	*file = nil
	return nil
}

func (o *linuxHostStageOwner) closeRootAt(index int) error {
	root := o.roots[index]
	if root == nil {
		return nil
	}
	closeRoot := o.closeRoot
	if closeRoot == nil {
		closeRoot = (*os.Root).Close
	}
	if err := closeRoot(root); err != nil {
		o.stickyErr = errors.Join(o.stickyErr, err)
		return o.stickyErr
	}
	o.roots[index] = nil
	return nil
}

func (o *linuxHostStageOwner) close() error {
	if o.stickyErr != nil {
		return o.stickyErr
	}
	if o.access != nil {
		if err := o.access.closeRetained(); err != nil {
			o.stickyErr = err
			return err
		}
	}
	for index := range o.roots {
		if err := o.closeRootAt(index); err != nil {
			return err
		}
	}
	for _, file := range []**os.File{&o.tree, &o.lock, &o.source} {
		if err := o.closeFile(file); err != nil {
			return err
		}
	}
	if o.created && !o.deleted {
		if o.artifact == nil || o.artifactID.ino == 0 {
			o.stickyErr = errors.New("workspace: retain unverified Linux stage residue with held parent custody")
			return o.stickyErr
		}
		cleanupCtx, done := context.WithTimeout(context.Background(), 30*time.Second)
		defer done()
		budget := 4*hostStageMaxEntries + 10_000
		if err := o.access.remove(cleanupCtx, o.parent, o.name, o.artifactID, 0, &budget); err != nil {
			return err
		}
		o.deleted = true
	}
	for _, file := range []**os.File{&o.artifact, &o.parent} {
		if err := o.closeFile(file); err != nil {
			return err
		}
	}
	if o.access != nil {
		if err := o.access.close(); err != nil {
			o.stickyErr = err
			return err
		}
		o.access = nil
	}
	return nil
}

func (o *linuxHostStageOwner) refused(cause error) (*HostStage, error) {
	cleanupErr := o.close()
	if cleanupErr == nil {
		return nil, cause
	}
	return &HostStage{cleanupOnly: true, closeRequested: true, close: o.close}, errors.Join(cause, cleanupErr)
}

func prepareHostStagePlatform(ctx context.Context, opts StageOptions) (stage *HostStage, retErr error) {
	ctx, cancel := context.WithTimeout(ctx, hostStageDeadline)
	defer cancel()
	access, err := newLinuxHostAccess()
	if access == nil {
		return nil, err
	}
	owner := &linuxHostStageOwner{access: access}
	succeeded := false
	defer func() {
		if !succeeded {
			stage, retErr = owner.refused(retErr)
		}
	}()
	if err != nil {
		return nil, err
	}
	owner.source, err = access.absolute(opts.Project)
	if err != nil {
		return nil, fmt.Errorf("workspace: pin Linux source without links or mount crossings: %w", err)
	}
	sourceID, err := linuxHostInfo(owner.source, false)
	if err != nil {
		return nil, err
	}
	if err := validateLinuxHostStageSource(opts); err != nil {
		return nil, err
	}
	owner.parent, err = access.absolute(opts.DataDir)
	if err != nil {
		return nil, err
	}
	if _, err := linuxHostInfo(owner.parent, true); err != nil {
		return nil, err
	}
	owner.name = "host-stage-" + opts.Name + "-" + randomSuffix()
	if err := unix.Mkdirat(int(owner.parent.Fd()), owner.name, 0o700); err != nil {
		return nil, err
	}
	owner.created = true
	owner.artifact, err = linuxHostOpen(owner.parent, owner.name)
	if err != nil {
		return nil, fmt.Errorf("workspace: retain unverified empty Linux staging residue: %w", err)
	}
	artifactID, err := linuxHostInfo(owner.artifact, true)
	if err != nil || artifactID.mode&unix.S_IFMT != unix.S_IFDIR {
		return nil, errors.Join(errors.New("workspace: Linux artifact is not a held private directory"), err)
	}
	owner.artifactID = artifactID // publish cleanup identity only after directory admission
	owner.roots[0], err = access.heldRoot(owner.artifact, true)
	if err != nil {
		return nil, err
	}
	artifactRoot := owner.roots[0]
	owner.lock, err = artifactRoot.OpenFile("owner.lock", os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if closeErr := owner.closeRootAt(0); err != nil || closeErr != nil {
		return nil, errors.Join(err, closeErr)
	}
	if _, err := linuxHostInfo(owner.lock, true); err != nil {
		return nil, err
	}
	if err := unix.Flock(int(owner.lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, err
	}
	ids := make([]linuxHostIdentity, 3)
	for i, dir := range []string{"capture", "sanitized", "scratch"} {
		if err := unix.Mkdirat(int(owner.artifact.Fd()), dir, 0o700); err != nil {
			return nil, err
		}
		pin, err := linuxHostOpen(owner.artifact, dir)
		if err != nil {
			return nil, err
		}
		ids[i], err = linuxHostInfo(pin, true)
		if err == nil {
			owner.roots[i], err = access.heldRoot(pin, true)
		}
		// Child directory pins remain reachable on an uncertain close.
		if closeErr := access.closeFile(pin); closeErr != nil {
			owner.stickyErr = closeErr
			return nil, errors.Join(err, closeErr)
		}
		if err != nil {
			return nil, err
		}
	}
	capture, sanitized, scratch := owner.roots[0], owner.roots[1], owner.roots[2]
	limit := opts.MaxBytes
	if limit <= 0 {
		limit = DefaultCopyMaxBytes
	}
	entries := opts.MaxWalkEntries
	if entries <= 0 || entries > hostStageMaxEntries {
		entries = hostStageMaxEntries
	}
	budget := linuxHostCaptureBudget{limit: limit, remaining: entries}
	if err := access.capture(ctx, owner.source, sourceID, capture, "", 0, &budget); err != nil {
		return nil, err
	}
	if err := owner.closeFile(&owner.source); err != nil {
		return nil, err
	}
	settings := capturedGitSettings{frozen: true}
	if _, err := capture.Lstat(".git"); err == nil {
		settings, err = freezeLinuxHostStageSettings(ctx, access, opts)
		if err != nil {
			return nil, err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	record, err := stageCapturedSHA1(ctx, capture, sanitized, scratch, opts, stageSecretOptions(opts, opts.Project), settings)
	if err != nil {
		return nil, err
	}
	for _, index := range []int{0, 2} {
		if err := owner.closeRootAt(index); err != nil {
			return nil, err
		}
		dir := []string{"capture", "sanitized", "scratch"}[index]
		cleanupBudget := 2*hostStageMaxEntries + 1
		if err := access.remove(ctx, owner.artifact, dir, ids[index], 0, &cleanupBudget); err != nil {
			return nil, err
		}
	}
	output, err := linuxHostOpen(owner.artifact, "sanitized")
	if err != nil {
		return nil, err
	}
	owner.tree, err = linuxHostOpen(output, record.RepoName)
	if closeErr := access.closeFile(output); closeErr != nil {
		owner.stickyErr = closeErr
		return nil, errors.Join(err, closeErr)
	}
	if err != nil {
		return nil, err
	}
	treeID, err := linuxHostInfo(owner.tree, true)
	if err != nil || treeID.mode&unix.S_IFMT != unix.S_IFDIR {
		return nil, errors.Join(errors.New("workspace: Linux sanitized root is not a held private directory"), err)
	}
	record.Stage = filepath.Join(opts.DataDir, owner.name, "sanitized", record.RepoName)
	stage = &HostStage{record: record, identity: sourceID.label(), close: owner.close, duplicateRoot: func() (*os.File, error) { return duplicateLinuxHostRoot(owner.tree, treeID) }}
	succeeded = true
	return stage, nil
}

func validateLinuxHostStageSource(opts StageOptions) error {
	if opts.MaxBytes > DefaultCopyMaxBytes {
		return errors.New("workspace: Linux host capture exceeds its 500 MiB admission bound")
	}
	for _, name := range []string{opts.Project, opts.DataDir} {
		if err := linuxHostAbsolute(name); err != nil {
			return err
		}
	}
	if len(opts.Protected) > 256 || strings.Count(opts.Project, "/") < 2 {
		return errors.New("workspace: Linux host source or protected-path inventory exceeds its floor")
	}
	for _, name := range refusedExact {
		if opts.Project == name {
			return &SourceError{Path: opts.Project, Reason: "it is a shared top-level host directory"}
		}
	}
	for _, name := range refusedTrees {
		if within(opts.Project, name) {
			return &SourceError{Path: opts.Project, Reason: "it is inside a protected system tree"}
		}
	}
	home, err := resolveHome(opts.Home)
	if err != nil {
		return err
	}
	if home == "" || opts.Project == home || within(home, opts.Project) {
		return &SourceError{Path: opts.Project, Reason: "it is or contains the operator home"}
	}
	protected := append([]string{opts.DataDir}, opts.Protected...)
	for _, tree := range credentialTrees(home) {
		protected = append(protected, tree.path)
	}
	for _, name := range protected {
		if name == "" {
			continue
		}
		// The admitted source spelling is compared as metadata only. Never
		// reopen it through resolveExisting after its native no-link pin.
		for _, protected := range []string{name, resolveExisting(name)} {
			if within(opts.Project, protected) || within(protected, opts.Project) {
				return &SourceError{Path: opts.Project, Reason: "it overlaps protected credentials, harness or staging state"}
			}
		}
	}
	return nil
}

type linuxHostCaptureBudget struct {
	written, limit int64
	remaining      int
}

func (a *linuxHostAccess) capture(ctx context.Context, source *os.File, expected linuxHostIdentity, output *os.Root, rel string, depth int, budget *linuxHostCaptureBudget) (retErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if depth > hostStageMaxDepth {
		return errors.New("workspace: Linux source capture exceeds its depth bound")
	}
	before, err := linuxHostInfo(source, false)
	if err != nil || before != expected {
		return errors.Join(errors.New("workspace: Linux source changed between admission and capture"), err)
	}
	readable, err := a.readable(source, false)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, a.closeFile(readable)) }()
	if before.mode&unix.S_IFMT == unix.S_IFREG {
		if before.size > budget.limit-budget.written {
			return &TooLargeError{What: "the complete Linux source capture including git metadata", Size: budget.written + before.size, Limit: budget.limit}
		}
		file, err := output.OpenFile(rel, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		n, copyErr := io.Copy(file, io.LimitReader(capturedContextReader{ctx, readable}, before.size+1))
		var modeErr error
		if before.mode&0o111 != 0 {
			modeErr = file.Chmod(0o700) // only the newly created private capture
		}
		syncErr, closeErr := file.Sync(), a.closeFile(file)
		if copyErr != nil || modeErr != nil || syncErr != nil || closeErr != nil || n != before.size {
			return errors.Join(errors.New("workspace: Linux captured source read/size changed"), copyErr, modeErr, syncErr, closeErr)
		}
		budget.written += n
	} else {
		seen := make(map[string]bool)
		for {
			entries, readErr := readable.ReadDir(128)
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				return readErr
			}
			for _, entry := range entries {
				budget.remaining--
				name := entry.Name()
				if budget.remaining < 0 || capturedRelativePath(filepath.Join(rel, name)) != nil || seen[strings.ToUpper(name)] {
					return errors.New("workspace: Linux captured entry name/count refused")
				}
				seen[strings.ToUpper(name)] = true
				child, err := linuxHostOpen(readable, name)
				if err != nil {
					return err
				}
				info, err := linuxHostInfo(child, false)
				if err == nil && info.mode&unix.S_IFMT == unix.S_IFDIR {
					err = output.Mkdir(filepath.Join(rel, name), 0o700)
				}
				if err == nil {
					err = a.capture(ctx, child, info, output, filepath.Join(rel, name), depth+1, budget)
				}
				if err = errors.Join(err, a.closeFile(child)); err != nil {
					return err
				}
			}
			if errors.Is(readErr, io.EOF) {
				break
			}
		}
	}
	after, err := linuxHostInfo(source, false)
	if err != nil || before != after {
		return errors.Join(errors.New("workspace: Linux source metadata changed during bounded capture"), err)
	}
	return nil
}
