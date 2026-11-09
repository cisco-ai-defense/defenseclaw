// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// heldConversionReadLimit bounds the bytes read from a file about to be
// replaced; a larger file cannot be the one the conversion read.
const heldConversionReadLimit = 64 << 20

// publishHeldConversion replaces writePath, which a rollback conversion found
// holding the bytes with hash found, with the staged tmpPath (the bytes data)
// by the writer own publisher, so the file keeps its crash safety, its private
// protection and its hardlinked aliases. The file is held open across the
// rename and the file displaced is compared with found (keptSaves), so a save
// made after the last check is put back and the write refused. tmpPath is
// gone on return.
func publishHeldConversion(tmpPath, writePath, found string, data []byte, pub conversionPublish) error {
	defer os.Remove(tmpPath)
	dir := filepath.Dir(writePath)
	return keptSaves{
		hold: func() (displacedHold, error) { return holdFile(writePath) },
		publish: func() error {
			if err := pub.publish(tmpPath, writePath, pub.stagedInfo, pub.perm); err != nil {
				return &atomicPublishError{Path: writePath, Err: publishCause(err)}
			}
			return nil
		},
		putBack: func(save []byte) error {
			staged, info, err := stageAtomicFile(dir, writePath, save, pub.perm)
			if err != nil {
				return err
			}
			defer os.Remove(staged)
			if err := pub.publish(staged, writePath, info, pub.perm); err != nil {
				return &atomicPublishError{Path: writePath, Err: publishCause(err)}
			}
			return nil
		},
		keep: func(save []byte) (string, error) { return keepSaveBeside(writePath, save) },
	}.replace(writePath, found, data)
}

// keepSaveBeside stores save in a new file next to path.
func keepSaveBeside(path string, save []byte) (string, error) {
	file, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".saved-*")
	if err != nil {
		return "", err
	}
	_, writeErr := file.Write(save)
	closeErr := file.Close()
	return file.Name(), errors.Join(writeErr, closeErr)
}

// fileHold is a displacedHold on an open file.
type fileHold struct {
	file *os.File
	path string
}

// holdFile opens the regular file at path for reading, sharing read, write
// and deletion, so an editor and the rename that replaces the file are not
// blocked. A file that is gone is errManagedTargetMoved: a conversion starts
// on a file it read, and nothing is created in its place.
func holdFile(path string) (displacedHold, error) {
	file, err := winpath.OpenReadShared(path)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return nil, errManagedTargetMoved
		}
		return nil, err
	}
	info, err := file.Stat()
	if err == nil && !info.Mode().IsRegular() {
		err = errManagedTargetMoved
	}
	if err != nil {
		file.Close()
		return nil, err
	}
	return &fileHold{file: file, path: path}, nil
}

func (h *fileHold) ReadAll() ([]byte, error) {
	data, err := io.ReadAll(io.NewSectionReader(h.file, 0, heldConversionReadLimit+1))
	if err != nil {
		return nil, err
	}
	if len(data) > heldConversionReadLimit {
		return nil, errManagedTargetMoved
	}
	return data, nil
}

func (h *fileHold) StillNamed() (bool, error) {
	held, err := h.file.Stat()
	if err != nil {
		return false, err
	}
	named, err := os.Lstat(h.path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return os.SameFile(held, named), nil
}

func (h *fileHold) Close() error { return h.file.Close() }
