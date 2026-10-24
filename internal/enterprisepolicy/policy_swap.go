// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"errors"
	"fmt"
)

// errPolicyFileChanged reports a vendor policy file another writer (an
// administrator's editor, a management tool, the managed-hook writer) saved
// after DefenseClaw read it. The newer file is kept as it is; the caller
// renders its edit again from that file (reconcileTarget, removeTargetOwned).
var errPolicyFileChanged = errors.New("the policy file changed after DefenseClaw read it; the newer file was kept")

// policyFileAttempts bounds how often a reconcile or removal renders and
// writes again over a newer save before it reports the conflict.
const policyFileAttempts = 4

// policyFileBase is the file an edit was rendered from: absent, or present
// with exactly data (and, on Windows, the owner, access list and attributes
// readPolicyFile saw with it).
type policyFileBase struct {
	exists bool
	data   []byte
}

// policyFileSwapHook runs just before a policy file write or removal
// compares the file with its base; tests replace it to save in between.
var policyFileSwapHook = func(string) {}

func policyFileChanged(path string) error {
	return fmt.Errorf("%s: %w", path, errPolicyFileChanged)
}

// writePolicyFileOver is writePolicyFile for a file DefenseClaw shares with
// other writers: it publishes data only while path still holds base, content
// and metadata alike (GAP-0896, GAP-0908). Otherwise it returns
// errPolicyFileChanged and leaves the newer file in place.
func writePolicyFileOver(opts Options, path string, base policyFileBase, data []byte) ([]string, error) {
	return writePolicyFileWith(opts, path, func(path string) error {
		return atomicWriteOver(opts, path, base, data)
	})
}

// removePolicyFileOver is removePolicyFile for a shared file: it deletes path
// only while it still holds base, and returns errPolicyFileChanged otherwise.
func removePolicyFileOver(opts Options, path string, base policyFileBase) error {
	return removePolicyFileIfUnchanged(opts, platformPath(opts, path), base)
}

// reconcileTarget reconciles target, rendering again from the newer file
// when another writer saved a shared policy file between the read and the
// write, up to policyFileAttempts times.
func reconcileTarget(target Target, opts Options) (State, error) {
	for attempt := 1; ; attempt++ {
		state, err := target.Reconcile(opts)
		if err == nil || !errors.Is(err, errPolicyFileChanged) || attempt >= policyFileAttempts {
			return state, err
		}
	}
}

// removeTargetOwned is target.RemoveOwned with the same retry.
func removeTargetOwned(target Target, opts Options) (State, error) {
	for attempt := 1; ; attempt++ {
		state, err := target.RemoveOwned(opts)
		if err == nil || !errors.Is(err, errPolicyFileChanged) || attempt >= policyFileAttempts {
			return state, err
		}
	}
}

// replaceUntrustedPolicyFile reads the file at path as it is, without the
// trust rules, for a caller that replaces a file at DefenseClaw's own drop-in
// name that an unprivileged principal controls: the replacement is still a
// compare-and-swap of what was there, so a save made after this read is
// not lost.
func (s *State) replaceUntrustedPolicyFile(opts Options, path string) error {
	data, exists, err := readPolicyFileWith(opts, path, func(Options, string) error { return nil })
	if err != nil {
		return err
	}
	if s.replacing == nil {
		s.replacing = map[string]policyFileBase{}
	}
	s.replacing[platformPath(opts, path)] = policyFileBase{exists: exists, data: data}
	return nil
}

// policyFileBase is the base of a write of path rendered from current: the
// file as read, or the untrusted file replaceUntrustedPolicyFile read.
func (s *State) policyFileBase(opts Options, path string, exists bool, current []byte) policyFileBase {
	if base, ok := s.replacing[platformPath(opts, path)]; ok {
		return base
	}
	return policyFileBase{exists: exists, data: current}
}
