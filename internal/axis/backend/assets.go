// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package backend

import (
	"errors"
	"os"
	"slices"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeprocess"
	"github.com/defenseclaw/defenseclaw/internal/sandboxruntime"
)

// Assets contains already held host objects supplied by the trusted manager's
// artifact/staging producer. It grants no artifact or policy qualification.
// NewAssets transfers exclusive ownership on success: the producer must not
// close or reuse any transferred object. No source pathname is accepted or
// reopened; in particular Spec.HostWorkspace never selects a host object.
type Assets struct {
	mu       sync.Mutex
	identity sandboxruntime.SessionIdentity
	inputs   bridgeprocess.Inputs
	read     []string
	write    []string
	claimed  bool
	closed   bool
	closeErr error
	// A partial stage handoff owns only its newly created resources. It cannot
	// be bound or used for execution, even when its identity is otherwise valid.
	cleanupOnly  bool
	releaseStage func() error
	// Only PreparePolicyHostStageAssets installs this after deriving the real
	// capture inputs from the same opaque host policy. It acknowledges no
	// export, review, undo, native mount or complete policy capability.
	workspacePreparation *workspacePreparation
}

func NewAssets(identity sandboxruntime.SessionIdentity, inputs bridgeprocess.Inputs, read, write []string) (*Assets, error) {
	if identity.Validate() != nil || identity.Runtime.Runtime != sandboxruntime.Axis ||
		inputs.Peer == nil || inputs.Bubblewrap == nil || inputs.Payload == nil || inputs.CWD == nil ||
		inputs.Peer == inputs.Bubblewrap || inputs.Peer == inputs.Payload || inputs.Bubblewrap == inputs.Payload ||
		len(read) != len(inputs.Read) || len(write) != len(inputs.Write) || len(read)+len(write) > 256 {
		return nil, ErrAssets
	}
	seen := map[*os.File]bool{inputs.CWD: true}
	for _, file := range append(slices.Clone(inputs.Read), inputs.Write...) {
		if file == nil || seen[file] {
			return nil, ErrAssets
		}
		seen[file] = true
	}
	metadata := make(map[*os.File]os.FileInfo, len(seen))
	for file := range seen {
		info, err := file.Stat()
		if err != nil || !info.IsDir() {
			return nil, ErrAssets
		}
		metadata[file] = info
	}
	work := slices.Index(write, "/work")
	if work < 0 || !os.SameFile(metadata[inputs.CWD], metadata[inputs.Write[work]]) {
		return nil, ErrAssets
	}
	if err := guestGrants(read, write); err != nil {
		return nil, err
	}
	inputs.Read, inputs.Write = slices.Clone(inputs.Read), slices.Clone(inputs.Write)
	return &Assets{identity: identity, inputs: inputs, read: slices.Clone(read), write: slices.Clone(write)}, nil
}

// Close is for an unbound producer, or the backend after confirmed native
// cleanup. Once bound, the backend exclusively owns resource release.
func (a *Assets) Close() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.claimed {
		return ErrAssets
	}
	return a.closeLocked()
}

func (a *Assets) closeLocked() error {
	if !a.closed {
		a.closed = true
		var errs []error
		for _, image := range []*bridgeprocess.Image{a.inputs.Peer, a.inputs.Bubblewrap, a.inputs.Payload} {
			errs = append(errs, image.Close())
		}
		for _, file := range append(append([]*os.File{a.inputs.CWD}, a.inputs.Read...), a.inputs.Write...) {
			if file != nil {
				errs = append(errs, file.Close())
			}
		}
		a.closeErr = errors.Join(errs...)
	}
	// Uncertain exclusive-file/image closure is sticky and must never allow
	// recursive stage cleanup. Stage in-use refusal is different: it performs
	// no deletion, and can be retried after another consumer releases custody.
	if a.closeErr != nil {
		return a.closeErr
	}
	if a.releaseStage != nil {
		if err := a.releaseStage(); err != nil {
			return err
		}
		a.releaseStage = nil
	}
	return nil
}
