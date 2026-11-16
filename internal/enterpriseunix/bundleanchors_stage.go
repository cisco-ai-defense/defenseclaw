// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// Trust anchors and a bundle in one transaction (`enterprise bundle apply
// --trust-anchors F`, #1316), as Windows `ensure --trust-anchors F --bundle B`
// does. The lifecycle lock the apply holds covers both. The anchor file is
// checked and written first, because the bundle is verified against the
// installed file and a device without one is not in bundle mode yet. It stays
// only when the bundle is confirmed, or applied and waiting for the gateway to
// report its policy (the next run settles that receipt against the same
// anchors). A bundle that fails puts the previous file back, or removes the
// new one when there was none, so the caller never restores by hand. The
// change is recorded once, as an anchor install that was applied, or as one
// that failed and was put back (config.trust_anchors.changed).

const codeChangeUnrecorded = "change_unrecorded"

// bundleAnchorsStage is the anchor install of one bundle apply.
type bundleAnchorsStage struct {
	dest     string
	previous []byte // the installed file before the run; nil when there was none
	out      *AnchorsInstall
	// reservation is the room reserved for the change event; nil when the
	// run wrote nothing.
	reservation *enterprisestatus.ChangeReservation
}

// stageBundleAnchors checks the anchor file of l.opts.TrustAnchors, pins it to
// env.AnchorsDeviceGroup when one is set, and writes it as the device trust
// anchors. A refusal is an *enterprisebundle.Error; nothing is left written
// for one, except for anchor_restore_failed.
func (l *lifecycle) stageBundleAnchors() (*bundleAnchorsStage, error) {
	e := l.env
	stage := &bundleAnchorsStage{dest: e.bundleAnchorsPath()}
	stage.out = &AnchorsInstall{Path: filepath.Join(e.Layout.ConfigDir, "trust", enterprisebundle.AnchorsName)}
	fail := func(code enterprisebundle.Code, format string, args ...any) (*bundleAnchorsStage, error) {
		return stage, &enterprisebundle.Error{Code: code, Path: enterprisebundle.AnchorsName, Detail: fmt.Sprintf(format, args...)}
	}
	trust := func(path string) error { return e.Trust(path, TrustAdminFile) }
	anchors, raw, err := enterprisebundle.ReadAnchorsFile(l.opts.TrustAnchors, trust)
	if enterprisebundle.CodeOf(err) == enterprisebundle.CodeAnchorMissing {
		return fail(enterprisebundle.CodeAnchorMissing, "%s does not exist", l.opts.TrustAnchors)
	}
	if err != nil {
		return stage, err
	}
	if group := e.AnchorsDeviceGroup; group != "" {
		if anchors, raw, err = enterprisebundle.PinDeviceGroup(anchors, raw, group); err != nil {
			return stage, err
		}
	}
	previous, err := readInstalledAnchors(stage.dest)
	if err != nil {
		return fail(enterprisebundle.CodeAnchorInsecure, "the installed trust anchor file cannot be replaced: %v", err)
	}
	stage.previous = previous
	stage.out.Anchors, stage.out.SHA256 = anchors, sha256Bytes(raw)
	if previous != nil && bytes.Equal(previous, raw) && trust(stage.dest) == nil {
		stage.out.Result = AnchorsUnchanged
		return stage, nil
	}
	if err := e.ensureDir(filepath.Dir(stage.dest), 0o755, rootOwner()); err != nil {
		return fail(anchorsWriteCode(err), "prepare the trust anchor folder: %v%s", err, stateWriteAction(err))
	}
	// An install this device could not audit is not made.
	reserved, err := e.ReserveChange(enterprisestatus.ChangeKindTrustAnchors, enterprisestatus.ChangeActionInstall, "")
	if err != nil {
		return fail(anchorsWriteCode(err), "cannot record the trust anchor change: %v%s", err, stateWriteAction(err))
	}
	stage.reservation = reserved
	if previous != nil {
		if old, err := enterprisebundle.DecodeAnchors(previous); err == nil {
			for _, key := range old.Keys {
				stage.out.previousKeyIDs = append(stage.out.previousKeyIDs, key.KeyID)
			}
		}
	}
	stage.out.attempted = true
	err = e.fault("anchors-write")
	if err == nil {
		err = e.writeFileAtomic(stage.dest, raw, 0o644, rootOwner())
	}
	if err != nil {
		return fail(anchorsWriteCode(err), "write the trust anchor file: %v%s", err, stateWriteAction(err))
	}
	if _, installed, err := enterprisebundle.ReadAnchorsFile(stage.dest, trust); err != nil || !bytes.Equal(installed, raw) {
		problem := "the installed bytes differ from the checked file"
		var coded *enterprisebundle.Error
		if errors.As(err, &coded) {
			problem = coded.Detail
		} else if err != nil {
			problem = err.Error()
		}
		if err := e.restoreAnchors(stage.dest, previous); err != nil {
			return fail(codeAnchorRestoreFailed, "the installed trust anchor file failed its check (%s) and the previous file could not be put back: %v", problem, err)
		}
		stage.previous, stage.out.Result = nil, ""
		return fail(enterprisebundle.CodeAnchorInsecure, "the installed trust anchor file failed its check (%s); the previous file was put back", problem)
	}
	stage.out.Result = AnchorsInstalled
	if previous != nil {
		stage.out.Result, stage.out.PreviousSHA256 = AnchorsReplaced, sha256Bytes(previous)
	}
	return stage, nil
}

// settleBundleAnchors ends the anchor install of an apply once the bundle's
// receipt is in its final state: the file stays when the bundle was kept, and
// otherwise the previous file is put back. cause is why the install ended
// (nil when the file stays).
func (l *lifecycle) settleBundleAnchors(stage *bundleAnchorsStage, keep bool, cause error) {
	e, r := l.env, l.result
	if stage == nil {
		return
	}
	defer func() {
		if releaseErr := stage.reservation.Release(); releaseErr != nil {
			r.AddWarning("change_release_unflushed", "the room reserved for the audit change event of the trust anchor install could not be removed durably: "+releaseErr.Error())
		}
	}()
	out := stage.out
	switch {
	case out.Result == AnchorsUnchanged:
		return
	case keep && cause == nil && out.Result != "":
		if recordErr := e.recordAnchorsChange(stage.reservation, out, nil); recordErr != nil {
			r.AddWarning(codeChangeUnrecorded, "the audit change event of this run could not be written, so the gateway will not report it: "+recordErr.Error())
		}
		verb := "installed trust anchors in "
		if out.Result == AnchorsReplaced {
			verb = "replaced the trust anchors in "
		}
		r.Changes = append(r.Changes, verb+out.Path)
		r.Noop, r.NoopReason = false, ""
		return
	}
	// The bundle did not stay (or the install itself failed): the file the
	// run found is put back. A refusal before the write has nothing to undo.
	failure := cause
	if out.attempted && out.Result != "" {
		if err := e.restoreAnchors(stage.dest, stage.previous); err != nil {
			failure = &enterprisebundle.Error{Code: codeAnchorRestoreFailed, Path: enterprisebundle.AnchorsName,
				Detail: "the previous trust anchor file could not be put back: " + err.Error()}
			r.AddError(string(codeAnchorRestoreFailed), failure.Error())
		} else {
			r.AddWarning("anchors_put_back", "the bundle was not applied, so the previous trust anchors were put back")
		}
	}
	if failure == nil {
		failure = &enterprisebundle.Error{Code: enterprisebundle.CodeApplyFailed}
	}
	if recordErr := e.recordAnchorsChange(stage.reservation, out, failure); recordErr != nil {
		r.AddWarning(codeChangeUnrecorded, "the audit change event of this run could not be written, so the gateway will not report it: "+recordErr.Error())
	}
}
