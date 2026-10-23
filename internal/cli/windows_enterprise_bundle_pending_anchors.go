//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// These administrator-only files belong to one receipt, so another delivery
// cannot replace the anchors of an applied receipt waiting for the gateway.
func windowsReceiptAnchorPaths(layout managed.StandaloneLayout, id string) (stage, previous string, err error) {
	if !enterprisestatus.ValidReceiptID(id) {
		return "", "", fmt.Errorf("invalid bundle receipt id %q", id)
	}
	base := filepath.Join(layout.LifecycleDir, "bundle-anchors-"+id)
	return base + ".json", base + ".previous", nil
}

// The owner is written only after BeforeConfirm installs a receipt's anchors.
// It prevents an older applied receipt from undoing a later receipt's install.
func windowsReceiptAnchorOwnerPath(layout managed.StandaloneLayout) string {
	return filepath.Join(layout.LifecycleDir, "bundle-anchors-owner")
}

func readWindowsReceiptAnchorOwner(layout managed.StandaloneLayout) (string, error) {
	raw, err := safefile.ReadRegularFileBounded(windowsReceiptAnchorOwnerPath(layout), 64)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !enterprisestatus.ValidReceiptID(string(raw)) {
		return "", errors.New("invalid trust anchor owner receipt")
	}
	return string(raw), nil
}

func (run *windowsBundleRun) bindReceiptAnchors() error {
	if run.anchorStage == "" || run.prepared == nil || run.prepared.Receipt == nil {
		return nil
	}
	stage, previous, err := windowsReceiptAnchorPaths(run.layout, run.prepared.Receipt.ReceiptID)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(stage); err == nil {
		return fmt.Errorf("staged trust anchors already exist for receipt %s", run.prepared.Receipt.ReceiptID)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	// An empty previous file means that the host had no installed anchors.
	// Write it first: an applied receipt never exists without its rollback
	// snapshot and staged anchors both on disk.
	if err := writeWindowsBundleAdminFile(previous, run.anchorPrevious); err != nil {
		return err
	}
	if err := os.Rename(run.anchorStage, stage); err != nil {
		return err
	}
	if err := windowsBundlePublishPrivateFile(stage); err != nil {
		return err
	}
	run.anchorStage = stage
	run.driver.AnchorsPath = stage
	return nil
}

func readWindowsReceiptAnchors(layout managed.StandaloneLayout, id string) (stagePath string, staged, previous []byte, present bool, err error) {
	stagePath, previousPath, err := windowsReceiptAnchorPaths(layout, id)
	if err != nil {
		return "", nil, nil, false, err
	}
	if _, err := os.Lstat(stagePath); errors.Is(err, fs.ErrNotExist) {
		// The previous-anchor snapshot is written before the stage is moved
		// here. If it remains, this receipt was delivered with anchors and
		// cannot borrow a valid anchor file from an earlier bundle.
		if _, previousErr := os.Lstat(previousPath); previousErr == nil {
			return stagePath, nil, nil, false, fmt.Errorf("%w: staged trust anchors of receipt %s are missing", enterprisebundle.ErrConfirmationPrerequisiteMissing, id)
		} else if !errors.Is(previousErr, fs.ErrNotExist) {
			return stagePath, nil, nil, false, previousErr
		}
		return stagePath, nil, nil, false, nil
	} else if err != nil {
		return stagePath, nil, nil, false, err
	}
	_, staged, err = windowsBundleReadAnchors(stagePath, bundleAnchorTrust)
	if err != nil {
		return stagePath, nil, nil, false, err
	}
	previous, err = safefile.ReadRegularFileBounded(previousPath, windowsBundleMaxAnchors)
	if err != nil {
		return stagePath, nil, nil, false, fmt.Errorf("read previous trust anchors of receipt %s: %w", id, err)
	}
	return stagePath, staged, previous, true, nil
}

func commitWindowsReceiptAnchors(layout managed.StandaloneLayout, receipt *enterprisebundle.Receipt, reservation *enterprisestatus.ChangeReservation) (*anchorOnlyChange, error) {
	_, staged, previous, present, err := readWindowsReceiptAnchors(layout, receipt.ReceiptID)
	if err != nil {
		return nil, err
	}
	installedPath := newWindowsBundleDriver(layout).AnchorsPath
	if !present {
		// An old or damaged pending receipt may have lost its stage. It must
		// never become confirmed on a host with no trust anchors.
		if _, _, err := windowsBundleReadAnchors(installedPath, bundleAnchorTrust); err != nil {
			if errors.Is(err, fs.ErrNotExist) || enterprisebundle.CodeOf(err) == enterprisebundle.CodeAnchorMissing {
				return nil, fmt.Errorf("%w: cannot confirm bundle receipt %s without installed trust anchors: %v", enterprisebundle.ErrConfirmationPrerequisiteMissing, receipt.ReceiptID, err)
			}
			return nil, fmt.Errorf("cannot check installed trust anchors for bundle receipt %s: %w", receipt.ReceiptID, err)
		}
		return nil, nil
	}
	current, err := safefile.ReadRegularFileBounded(installedPath, windowsBundleMaxAnchors)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if !bytes.Equal(current, staged) {
		if !bytes.Equal(current, previous) {
			return nil, fmt.Errorf("installed trust anchors changed while bundle receipt %s was pending", receipt.ReceiptID)
		}
		stagePath, _, pathErr := windowsReceiptAnchorPaths(layout, receipt.ReceiptID)
		if pathErr != nil {
			return nil, pathErr
		}
		if _, replaced, err := installWindowsBundleAnchors(stagePath, installedPath); err != nil {
			if replaced {
				if restoreErr := restoreWindowsBundleAnchors(installedPath, len(previous) != 0, previous); restoreErr != nil {
					return nil, fmt.Errorf("commit trust anchors of bundle receipt %s: %w; restore previous trust anchors: %v", receipt.ReceiptID, err, restoreErr)
				}
			}
			return nil, fmt.Errorf("commit trust anchors of bundle receipt %s: %w", receipt.ReceiptID, err)
		}
		if err := writeWindowsBundleAdminFile(windowsReceiptAnchorOwnerPath(layout), []byte(receipt.ReceiptID)); err != nil {
			if restoreErr := restoreWindowsBundleAnchors(installedPath, len(previous) != 0, previous); restoreErr != nil {
				return nil, fmt.Errorf("record trust anchor owner of bundle receipt %s: %w; restore previous trust anchors: %v", receipt.ReceiptID, err, restoreErr)
			}
			return nil, fmt.Errorf("record trust anchor owner of bundle receipt %s: %w", receipt.ReceiptID, err)
		}
		change := &anchorOnlyChange{path: installedPath, existed: len(previous) != 0, previous: previous, installed: staged}
		if err := recordWindowsAnchorsChange(layout, reservation, change); err != nil {
			return nil, err
		}
		return change, nil
	}
	if _, _, err := windowsBundleReadAnchors(installedPath, bundleAnchorTrust); err != nil {
		return nil, fmt.Errorf("check installed trust anchors of bundle receipt %s: %w", receipt.ReceiptID, err)
	}
	return &anchorOnlyChange{path: installedPath, existed: len(previous) != 0, previous: previous, installed: staged}, nil
}

func restoreFailedWindowsReceiptAnchors(layout managed.StandaloneLayout, receipt *enterprisebundle.Receipt) error {
	if receipt.State != enterprisebundle.StateApplied {
		// Anchors are installed only just before an applied receipt is
		// confirmed. A staged receipt has no anchor change to undo.
		return nil
	}
	state, err := newWindowsBundleDriver(layout).Store.LoadState()
	if err != nil {
		return err
	}
	// A later confirmed generation owns its anchors even when the stale
	// receipt staged identical bytes (including a key rotation).
	if state.Current != nil && state.Current.ConfigGeneration > receipt.ConfigGeneration {
		return nil
	}
	owner, err := readWindowsReceiptAnchorOwner(layout)
	if err != nil {
		return err
	}
	if owner != "" && owner != receipt.ReceiptID {
		return nil
	}
	_, staged, previous, present, err := readWindowsReceiptAnchors(layout, receipt.ReceiptID)
	if errors.Is(err, enterprisebundle.ErrConfirmationPrerequisiteMissing) {
		return nil
	}
	if err != nil || !present {
		return err
	}
	path := newWindowsBundleDriver(layout).AnchorsPath
	current, err := safefile.ReadRegularFileBounded(path, windowsBundleMaxAnchors)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if bytes.Equal(current, staged) && !bytes.Equal(staged, previous) {
		if err := restoreWindowsBundleAnchors(path, len(previous) != 0, previous); err != nil {
			return err
		}
	}
	if owner == receipt.ReceiptID {
		return os.Remove(windowsReceiptAnchorOwnerPath(layout))
	}
	return nil
}

func cleanupWindowsReceiptAnchors(layout managed.StandaloneLayout, receipt *enterprisebundle.Receipt) error {
	stage, previous, err := windowsReceiptAnchorPaths(layout, receipt.ReceiptID)
	if err != nil {
		return err
	}
	for _, path := range []string{stage, previous} {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}
