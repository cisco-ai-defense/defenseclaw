// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisepolicy

import (
	"bytes"
	"errors"
	"os"
)

// The Unix vendor policy files have no lock protocol with their other
// writers, so the comparison happens right before the rename or removal:
// a save that landed after DefenseClaw read the file is kept and the edit is
// rendered again from it.

func notePolicyFileRead(string, *os.File, []byte) {}

func forgetPolicyFileRead(string) {}

func policyFileStillBase(path string, base policyFileBase) error {
	policyFileSwapHook(path)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if base.exists {
			return policyFileChanged(path)
		}
		return nil
	}
	if err != nil {
		return err
	}
	if !base.exists || !info.Mode().IsRegular() {
		return policyFileChanged(path)
	}
	file, err := openNoFollow(path)
	if err != nil {
		return err
	}
	defer file.Close()
	data, err := readBounded(file, policyFileLimit)
	if err != nil {
		return err
	}
	if !bytes.Equal(data, base.data) {
		return policyFileChanged(path)
	}
	return nil
}

func atomicWriteOver(opts Options, path string, base policyFileBase, data []byte) error {
	return atomicWriteChecked(opts, path, data, true, func() error { return policyFileStillBase(path, base) })
}

func removePolicyFileIfUnchanged(_ Options, path string, base policyFileBase) error {
	if err := policyFileStillBase(path, base); err != nil {
		return err
	}
	if !base.exists {
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
