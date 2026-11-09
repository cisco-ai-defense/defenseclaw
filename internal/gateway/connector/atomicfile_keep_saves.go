// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"fmt"
)

// displacedHold is an open handle on the file a name leads to. It shares
// deletion, so a rename over the name goes through and the handle goes on
// holding the file that was displaced.
type displacedHold interface {
	// ReadAll returns the bytes of the held file, wherever the name leads now.
	ReadAll() ([]byte, error)
	// StillNamed reports whether the name leads to the held file.
	StillNamed() (bool, error)
	Close() error
}

// keptSaves replaces a file by a rename and keeps every save made meanwhile.
// Windows has no exchange of two names, and a move aside exposes a missing
// name to a reader (GAP-2644, GAP-0546). So the file is held open before the
// rename and read again after it: the held handle is the displaced file, and
// its bytes show whether anyone saved between the conversion reading the file
// and the rename. A rename keeps the replacement crash-safe (the name leads to
// the complete old or the complete new file), leaves a hardlinked alias alone
// and publishes with the writer own private protection.
type keptSaves struct {
	// hold opens the file the name leads to now.
	hold func() (displacedHold, error)
	// publish renames the staged conversion over the name.
	publish func() error
	// putBack stages save and renames it over the name.
	putBack func(save []byte) error
	// keep stores save in a file of its own and returns its path.
	keep func(save []byte) (string, error)
}

// replace publishes data over writePath, which a conversion read as the bytes
// with hash found. A file that is not those bytes is left as it is
// (errManagedTargetMoved). A save made after the file was held is put back
// under the name and the write is refused; none is dropped. The one instant
// left is a save by renaming or deleting the file in the single call between
// the check that the held file still has the name and the rename.
func (k keptSaves) replace(writePath, found string, data []byte) error {
	want := managedFileSnapshotHash(data, true)
	displaced, err := k.swap(k.publish, found)
	if err != nil {
		return err
	}
	if managedFileSnapshotHash(displaced, true) == found {
		return nil
	}
	// Someone saved the file after the last check. Put the save back.
	undone, err := k.swap(func() error { return k.putBack(displaced) }, want)
	switch {
	case err == nil && managedFileSnapshotHash(undone, true) == want:
		return errManagedTargetMoved
	case err == nil:
		// A second save landed in the instant of the undo, and the undo
		// displaced it. The first save is under the name; keep the later one.
		return fmt.Errorf("%s was saved twice while DefenseClaw replaced it; %s", writePath, k.keepSave("the later save", undone))
	default:
		return fmt.Errorf("%s was saved while DefenseClaw replaced it and could not be put back (%v); %s", writePath, err, k.keepSave("the save", displaced))
	}
}

// swap holds the file at the name, checks it holds the bytes with hash want
// and is still the file the name leads to, runs publish and returns the bytes
// of the file that publish displaced.
func (k keptSaves) swap(publish func() error, want string) ([]byte, error) {
	hold, err := k.hold()
	if err != nil {
		return nil, err
	}
	defer hold.Close()
	before, err := hold.ReadAll()
	if err != nil {
		return nil, err
	}
	if managedFileSnapshotHash(before, true) != want {
		return nil, errManagedTargetMoved
	}
	named, err := hold.StillNamed()
	if err != nil {
		return nil, err
	}
	if !named {
		return nil, errManagedTargetMoved
	}
	if err := publish(); err != nil {
		return nil, err
	}
	after, err := hold.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("read the file that was replaced: %w", err)
	}
	return after, nil
}

// keepSave stores save in a file of its own and says where, so the sentence
// finishes an error message.
func (k keptSaves) keepSave(what string, save []byte) string {
	path, err := k.keep(save)
	if err != nil {
		return fmt.Sprintf("%s could not be kept (%v)", what, err)
	}
	return fmt.Sprintf("%s is kept in %s", what, path)
}
