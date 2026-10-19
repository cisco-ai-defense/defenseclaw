// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"time"
)

type retainedSession interface {
	Close(context.Context) error
	StopAndWait(context.Context) error
}

// cleanupOwner keeps exact native custody reachable through final reporting.
// A retry can discharge custody, but cannot turn the original failure into a
// passed case. The separate outer PID namespace remains the last-resort owner.
type cleanupOwner struct {
	pending       []retainedSession
	heldResources []func() error
}

func (o *cleanupOwner) close(session retainedSession) error {
	o.pending = append(o.pending, session)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	err := session.Close(ctx)
	cancel()
	if err == nil {
		o.pending = o.pending[:len(o.pending)-1]
		return nil
	}
	return errors.Join(err, o.retry())
}

func (o *cleanupOwner) retry() error {
	var result error
	remaining := o.pending[:0]
	for _, session := range o.pending {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := session.StopAndWait(ctx)
		cancel()
		if err != nil {
			remaining = append(remaining, session)
			result = errors.Join(result, err)
		}
	}
	o.pending = remaining
	if len(o.pending) == 0 {
		held := o.heldResources[:0]
		for _, close := range o.heldResources {
			if err := close(); err != nil {
				held = append(held, close)
				result = errors.Join(result, err)
			}
		}
		o.heldResources = held
	}
	return result
}

// Only fixed version-fixture resources use this list. Native custody must be
// discharged before these source descriptors are released. A close uncertainty
// keeps the closure (and captured resource owner) reachable through reporting.
func (o *cleanupOwner) releaseResource(close func() error) error {
	if len(o.pending) == 0 {
		if err := close(); err == nil {
			return nil
		} else {
			o.heldResources = append(o.heldResources, close)
			return err
		}
	}
	o.heldResources = append(o.heldResources, close)
	return nil
}
