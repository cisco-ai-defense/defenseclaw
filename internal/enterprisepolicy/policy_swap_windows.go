// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisepolicy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// policyFileReads keeps, per path, the metadata readPolicyFile read through
// the handle it read the bytes with, so that a later write compares the
// owner, access list and attributes too: an access-list-only change after
// the read is a newer save as well (GAP-0908).
var policyFileReads sync.Map // cleaned lower-case path -> policyFileRead

type policyFileRead struct {
	sha      string
	metadata safefile.FileMetadata
}

func policyFileReadKey(path string) string { return strings.ToLower(filepath.Clean(path)) }

func notePolicyFileRead(path string, file *os.File, data []byte) {
	metadata, err := safefile.ReadFileMetadata(file)
	if err != nil {
		policyFileReads.Delete(policyFileReadKey(path))
		return
	}
	policyFileReads.Store(policyFileReadKey(path), policyFileRead{sha: sha256Hex(data), metadata: metadata})
}

func forgetPolicyFileRead(path string) { policyFileReads.Delete(policyFileReadKey(path)) }

// policyFileExpectation is the compare-and-swap expectation of base: its
// bytes, and the metadata read with them when the recorded read is of these
// bytes.
func policyFileExpectation(path string, base policyFileBase) safefile.SwapExpectation {
	expected := safefile.SwapExpectation{Exists: base.exists, Data: base.data}
	if !base.exists {
		return expected
	}
	if value, ok := policyFileReads.Load(policyFileReadKey(path)); ok {
		if read := value.(policyFileRead); read.sha == sha256Hex(base.data) {
			metadata := read.metadata
			expected.Metadata = &metadata
		}
	}
	return expected
}

func policyFileSwapError(path string, err error) error {
	if errors.Is(err, safefile.ErrSwapRaced) {
		return errors.Join(policyFileChanged(path), err)
	}
	return err
}

// atomicWriteOver writes data beside path with DefenseClaw's public
// protection and moves it over path with safefile.CompareAndSwapFile, which
// holds the current file against writers while it compares and replaces it.
func atomicWriteOver(_ Options, path string, base policyFileBase, data []byte) error {
	return atomicWriteSDDLWith(path, data, publicFileSDDL, func(tmp string) error {
		policyFileSwapHook(path)
		_, err := safefile.CompareAndSwapFile(tmp, path, policyFileExpectation(path, base), policyFileLimit, nil)
		if err == nil {
			forgetPolicyFileRead(path)
		}
		return policyFileSwapError(path, err)
	})
}

func removePolicyFileIfUnchanged(_ Options, path string, base policyFileBase) error {
	policyFileSwapHook(path)
	if !base.exists {
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			return nil
		} else if err != nil {
			return err
		}
		return policyFileChanged(path)
	}
	_, err := safefile.RemoveFileIfUnchanged(path, policyFileExpectation(path, base), policyFileLimit, nil)
	if err == nil {
		forgetPolicyFileRead(path)
	}
	return policyFileSwapError(path, err)
}
