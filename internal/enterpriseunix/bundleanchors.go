// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// Trust anchor install for a root management agent (`enterprise bundle
// anchors install`, Linux and macOS; the MDM kit's dc_install_anchors runs it
// when the installed gateway has it). It writes the file the kit's fallback
// writer dc_put_anchors writes (<etc>/trust/bundle-anchors.json, root 0644 in
// a root 0755 folder), with three things that writer leaves out: the
// source is checked the way an installed anchor file is (LoadAnchors with
// the managed trust check on the file and every folder above it) and read
// once, the write happens under the lifecycle lock, so it cannot land in
// the middle of a bundle apply, and the installed file is checked again and
// put back when that check fails. Every install that changed the file,
// was refused or failed leaves a change event the gateway reports as a
// config.trust_anchors.changed audit event (recordAnchorsChange).

// Results of InstallBundleAnchors.
const (
	AnchorsInstalled = "installed" // no anchor file before: bundle mode turns on
	AnchorsReplaced  = "replaced"
	AnchorsUnchanged = "unchanged" // byte-identical and trusted: nothing written
)

const (
	codeAnchorRestoreFailed enterprisebundle.Code = "anchor_restore_failed"
	// maxInstalledAnchorsBytes bounds the read of the installed file kept
	// for the restore; a valid anchor file is far smaller.
	maxInstalledAnchorsBytes = 1 << 20
)

// AnchorsInstall is what an anchors install did. On a refusal only Path and
// SHA256 (of the file still installed, "" for none) are set.
type AnchorsInstall struct {
	Result string
	// Path is the installed anchor file as the layout names it (not rooted).
	Path           string
	SHA256         string
	PreviousSHA256 string // set when Result is replaced
	Anchors        *enterprisebundle.Anchors
	// SignerKeyID signed the confirmed bundle ("" for none): the caller warns
	// when the new anchors no longer trust it.
	SignerKeyID string
	// previousKeyIDs are the key ids of the replaced file; attempted is set
	// once the install started writing, so a refusal after it is a failure.
	previousKeyIDs []string
	attempted      bool
	// Unrecorded is set when the change event of this install could not be
	// written: the caller reports it as the warning change_unrecorded.
	Unrecorded error
	// ReleaseUnflushed is set when this install recorded nothing and its
	// change event reservation could not be removed durably: the caller
	// reports it as the warning change_release_unflushed.
	ReleaseUnflushed error
}

// InstallBundleAnchors installs the anchor file src as the device trust
// anchors. Refusals are *enterprisebundle.Error with codes not_root,
// anchor_missing, anchor_insecure, anchor_invalid, anchor_restore_failed,
// lifecycle_busy, state_invalid and disk_full; nothing is written for any of them but
// anchor_restore_failed.
func (e *Env) InstallBundleAnchors(ctx context.Context, src string) (*AnchorsInstall, error) {
	var reservation *enterprisestatus.ChangeReservation
	defer func() { _ = reservation.Release() }()
	out, err := e.installBundleAnchors(ctx, src, &reservation)
	if recordErr := e.recordAnchorsChange(reservation, out, err); recordErr != nil && out != nil {
		out.Unrecorded = recordErr
	}
	if releaseErr := reservation.Release(); releaseErr != nil && out != nil {
		out.ReleaseUnflushed = releaseErr
	}
	return out, err
}

// installBundleAnchors sets *reservation once it reserved room for the
// change event, before the file is written.
func (e *Env) installBundleAnchors(ctx context.Context, src string, reservation **enterprisestatus.ChangeReservation) (*AnchorsInstall, error) {
	dest := e.bundleAnchorsPath()
	out := &AnchorsInstall{Path: filepath.Join(e.Layout.ConfigDir, "trust", enterprisebundle.AnchorsName)}
	attempted := false
	refused := func(err error) (*AnchorsInstall, error) {
		// Only the file still installed is reported, never the refused one.
		out = &AnchorsInstall{Path: out.Path, attempted: attempted}
		if installed, readErr := readInstalledAnchors(dest); readErr == nil && installed != nil {
			out.SHA256 = sha256Bytes(installed)
		}
		return out, err
	}
	refuse := func(code enterprisebundle.Code, format string, args ...any) (*AnchorsInstall, error) {
		return refused(&enterprisebundle.Error{Code: code, Path: enterprisebundle.AnchorsName, Detail: fmt.Sprintf(format, args...)})
	}
	if e.Geteuid() != 0 {
		return out, &enterprisebundle.Error{Code: codeNotRoot, Detail: "run this command as root (sudo or the management agent)"}
	}
	trust := func(path string) error { return e.Trust(path, TrustAdminFile) }
	anchors, raw, err := enterprisebundle.ReadAnchorsFile(src, trust)
	if enterprisebundle.CodeOf(err) == enterprisebundle.CodeAnchorMissing {
		return refuse(enterprisebundle.CodeAnchorMissing, "%s does not exist", src)
	}
	if err != nil {
		return refused(err)
	}

	if err := e.ensureDir(e.P(e.Layout.LifecycleDir), 0o700, rootOwner()); err != nil {
		return refuse(anchorsWriteCode(err), "%v%s", err, stateWriteAction(err))
	}
	lock, err := e.acquireLock(ctx)
	if errors.Is(err, errLockBusy) {
		return refuse(enterprisebundle.CodeLifecycleBusy, "%v; %s", err, lockBusyNextStep(e.LockTimeout))
	}
	if err != nil {
		return refuse(enterprisebundle.CodeStateInvalid, "%v", err)
	}
	defer lock.release()

	previous, err := readInstalledAnchors(dest)
	if err != nil {
		return refuse(enterprisebundle.CodeAnchorInsecure, "the installed trust anchor file cannot be replaced: %v", err)
	}
	if st, err := e.bundleStore().LoadState(); err == nil && st.Current != nil {
		out.SignerKeyID = st.Current.SignerKeyID
	}
	out.Anchors, out.SHA256 = anchors, sha256Bytes(raw)
	// Identical bytes that fail the trust check (another owner, a loose
	// mode) are rewritten: every apply refuses an untrusted anchor file.
	if previous != nil && bytes.Equal(previous, raw) && trust(dest) == nil {
		out.Result = AnchorsUnchanged
		return out, nil
	}
	if err := e.ensureDir(filepath.Dir(dest), 0o755, rootOwner()); err != nil {
		return refuse(anchorsWriteCode(err), "prepare the trust anchor folder: %v%s", err, stateWriteAction(err))
	}
	// An install this device could not audit is not made: the spool must
	// hold room for its change event before the file is written, until the
	// event is written.
	reserved, err := e.ReserveChange(enterprisestatus.ChangeKindTrustAnchors, enterprisestatus.ChangeActionInstall, "")
	if err != nil {
		return refuse(anchorsWriteCode(err), "cannot record the trust anchor change: %v%s", err, stateWriteAction(err))
	}
	*reservation = reserved
	if previous != nil {
		if old, err := enterprisebundle.DecodeAnchors(previous); err == nil {
			for _, key := range old.Keys {
				out.previousKeyIDs = append(out.previousKeyIDs, key.KeyID)
			}
		}
	}
	attempted = true
	err = e.fault("anchors-write")
	if err == nil {
		err = e.writeFileAtomic(dest, raw, 0o644, rootOwner())
	}
	if err != nil {
		return refuse(anchorsWriteCode(err), "write the trust anchor file: %v%s", err, stateWriteAction(err))
	}
	if _, installed, err := enterprisebundle.ReadAnchorsFile(dest, trust); err != nil || !bytes.Equal(installed, raw) {
		problem := "the installed bytes differ from the checked file"
		var coded *enterprisebundle.Error
		if errors.As(err, &coded) {
			problem = coded.Detail
		} else if err != nil {
			problem = err.Error()
		}
		if err := e.restoreAnchors(dest, previous); err != nil {
			return refuse(codeAnchorRestoreFailed, "the installed trust anchor file failed its check (%s) and the previous file could not be put back: %v", problem, err)
		}
		return refuse(enterprisebundle.CodeAnchorInsecure, "the installed trust anchor file failed its check (%s); the previous file was put back", problem)
	}
	out.Result = AnchorsInstalled
	if previous != nil {
		out.Result, out.PreviousSHA256 = AnchorsReplaced, sha256Bytes(previous)
	}
	return out, nil
}

// anchorsWriteCode is the code of an anchor install whose own write failed:
// disk_full when the filesystem or quota is full, state_invalid otherwise
// (GAP-0609).
func anchorsWriteCode(err error) enterprisebundle.Code {
	if noSpace(err) {
		return enterprisebundle.CodeDiskFull
	}
	return enterprisebundle.CodeStateInvalid
}

// readInstalledAnchors returns the installed anchor file (nil when there is
// none). A path that is not a regular file is an error: it is never
// followed or replaced.
func readInstalledAnchors(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	raw, err := safefile.ReadRegularFileBounded(path, maxInstalledAnchorsBytes+1)
	if err != nil {
		return nil, err
	}
	if len(raw) > maxInstalledAnchorsBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxInstalledAnchorsBytes)
	}
	return raw, nil
}

// restoreAnchors puts previous back at path, or removes path when there was
// no file before (as the kit's dc_restore_anchors does).
func (e *Env) restoreAnchors(path string, previous []byte) error {
	if previous == nil {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	return e.writeFileAtomic(path, previous, 0o644, rootOwner())
}
