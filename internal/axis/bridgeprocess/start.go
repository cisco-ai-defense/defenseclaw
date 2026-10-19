// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package bridgeprocess supplies private native custody below bridgeowner.
// It has no production caller, artifact discovery or policy authority.
package bridgeprocess

import (
	"context"
	"errors"
	"os"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeowner"
	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeproto"
)

var (
	ErrUnavailable = errors.New("private AXIS native process boundary is unavailable")
	ErrAdmission   = errors.New("private AXIS native process inputs refused")
)

// Image is a host-created, immutable image, never a wire credential. The host
// must supply the expected digest from its independently admitted artifact
// registry. Matching arbitrary caller-provided bytes and a digest is not that
// admission. In particular, Bubblewrap needs reviewed static-musl provenance.
type Image struct {
	mu     sync.Mutex
	file   *os.File
	digest string
	// A Windows owned copy also retains its image view and held-root cleanup.
	// Linux images keep the existing file-only lifetime.
	cleanup func() error
}

func (i *Image) Close() error {
	if i == nil {
		return nil
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.cleanup != nil {
		// Close admission before potentially retryable native cleanup. A
		// cleanup-only image never regains execution or duplication authority.
		i.file, i.digest = nil, ""
		err := i.cleanup()
		if err == nil {
			i.cleanup = nil
		}
		return err
	}
	if i.file == nil {
		return nil
	}
	err := i.file.Close()
	i.file = nil
	return err
}

// SealImage copies one already-open artifact into an owned sealed image while
// checking the host's expected digest. It never searches PATH or opens a source
// name. The caller retains source ownership. No image is executed here.
func SealImage(ctx context.Context, source *os.File, expected string) (*Image, error) {
	return sealImage(ctx, source, expected)
}

// Inputs are already admitted host capabilities. Original handles stay owned
// by the caller; Start duplicates them before handing them to its one child.
// Labels, plan hashes and JSON never select a host object. Read/Write order
// exactly matches the corresponding preparation lists. No credential handle
// belongs in this table.
type Inputs struct {
	Peer, Bubblewrap, Payload *Image
	CWD                       *os.File
	Read, Write               []*os.File
}

// Session retains native cleanup independently of the protocol owner's one-use
// shutdown. Keep it after any cleanup failure. StopAndWait can retry exact
// native custody without trusting a frame or reopening a process by PID.
type Session struct {
	Protocol *bridgeowner.Owner
	native   bridgeowner.Custody
}

func (session *Session) StopAndWait(ctx context.Context) error {
	if session == nil || session.native == nil {
		return ErrAdmission
	}
	return session.native.StopAndWait(ctx)
}

func (session *Session) Close(ctx context.Context) error {
	if session == nil || session.Protocol == nil || session.native == nil {
		return ErrAdmission
	}
	return errors.Join(session.Protocol.Close(ctx), session.StopAndWait(ctx))
}

// Start creates only the trusted zero-argument peer, inside independent native
// process-tree custody. The caller must send Prepare, reserve its session and
// use the common LaunchGate before sending Launch. The returned owner starts
// no workload by itself. Customer activation remains unavailable.
// A nonnil Session owns cleanup even if err is nonnil; otherwise Start closes all
// resources it created. Neither the original images nor object handles transfer.
func Start(ctx context.Context, binding bridgeproto.Binding, plan bridgeproto.Preparation, inputs Inputs, limits bridgeowner.Limits) (*Session, error) {
	return start(ctx, binding, plan, inputs, limits)
}
