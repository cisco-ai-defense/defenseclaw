// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package connector

import (
	"errors"
	"fmt"
	"os"
)

// atomicExchange swaps two names in one step; tests replace it to run a file
// system that has no exchange.
var atomicExchange = exchangeAtomicFiles

// errHeldConversionNeedsExchange is a rollback conversion that cannot replace
// a file without risking a save made in the instant of the replacement: the
// file system has no atomic exchange of two names. The file is left as it is.
var errHeldConversionNeedsExchange = errors.New("this file system cannot replace a file without risking a concurrent save; the file was left as it is")

// publishHeldConversion replaces writePath, which a rollback conversion found
// holding the bytes with hash found, with the staged tmpPath (the bytes data)
// by exchanging the two names, so the file displaced is the one in tmpPath
// afterwards and can be compared with found. A file that is not those bytes is
// a save made after the last check: the exchange is undone, the save is back
// under its name and the write is refused (errManagedTargetMoved), so a
// replacement never drops a save, whatever the timing. A file system without
// an exchange is refused too (errHeldConversionNeedsExchange): there is no
// plain replacement for a conversion, which is a check followed by a rename and
// always leaves an instant for a save to be lost in. tmpPath is gone on return,
// except when a save could not be put back and the error names it.
func publishHeldConversion(tmpPath, writePath, found string, data []byte, _ conversionPublish) error {
	err := atomicExchange(tmpPath, writePath)
	switch {
	case err == nil:
	case atomicExchangeUnsupported(err):
		os.Remove(tmpPath)
		return fmt.Errorf("replace %s: %w", writePath, errHeldConversionNeedsExchange)
	case errors.Is(err, os.ErrNotExist):
		// A conversion starts on a file it read, so a file that is gone was
		// removed or moved since; nothing is created in its place.
		os.Remove(tmpPath)
		return errManagedTargetMoved
	default:
		os.Remove(tmpPath)
		return &atomicPublishError{Path: writePath, Err: publishCause(err)}
	}
	if displacedMatches(tmpPath, found) {
		os.Remove(tmpPath)
		return nil
	}
	// Someone saved the file after the check. Put the save back.
	if err := atomicExchange(tmpPath, writePath); err != nil {
		return fmt.Errorf("%s was saved while DefenseClaw replaced it and could not be put back; the saved file is %s: %w", writePath, tmpPath, err)
	}
	if displacedMatches(tmpPath, managedFileSnapshotHash(data, true)) {
		os.Remove(tmpPath)
		return errManagedTargetMoved
	}
	// A second save landed in the instant of the undo. Keep the newest one in
	// place and the earlier one next to it, and say so.
	if err := atomicExchange(tmpPath, writePath); err != nil {
		return fmt.Errorf("%s was saved twice while DefenseClaw replaced it; the earlier save is %s and the file may be that one: %w", writePath, tmpPath, err)
	}
	return fmt.Errorf("%s was saved twice while DefenseClaw replaced it; the earlier save is kept in %s", writePath, tmpPath)
}

// displacedMatches reports whether the file at path is a regular file whose
// bytes have the managed snapshot hash want.
func displacedMatches(path, want string) bool {
	current, info, err := readManagedTarget(path)
	return err == nil && info != nil && managedFileSnapshotHash(current, true) == want
}
