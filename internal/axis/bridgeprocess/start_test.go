// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package bridgeprocess

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeowner"
	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeproto"
)

type retryCustody struct{ calls atomic.Int32 }

func (custody *retryCustody) StopAndWait(context.Context) error {
	if custody.calls.Add(1) == 1 {
		return errors.New("fixed native cleanup failure")
	}
	return nil
}

func TestSessionRetainsNativeCleanupAfterProtocolCleanupFailure(t *testing.T) {
	var channels []bridgeowner.PrivatePipe
	for _, direction := range []bridgeowner.Direction{bridgeowner.ToPeer, bridgeowner.FromPeer, bridgeowner.FromPeer} {
		channel, err := bridgeowner.NewPrivatePipe(direction)
		if err != nil {
			t.Fatal(err)
		}
		channels = append(channels, channel)
		t.Cleanup(func() { _ = channel.Child.Close(); _ = channel.Parent.Close() })
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	binding := bridgeproto.Binding{SessionID: "fixed-cleanup", SessionDigest: digest, PolicyDigest: digest, RuntimeDigest: digest, HarnessDigest: digest, PreparationHash: digest}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	native := &retryCustody{}
	owner, err := bridgeowner.New(ctx, binding, bridgeowner.Pipes{Input: channels[0].Parent, Output: channels[1].Parent, Diagnostics: channels[2].Parent, Custody: native}, bridgeowner.Limits{WriteTimeout: time.Second, CleanupTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	session := &Session{Protocol: owner, native: native}
	if err := owner.Close(ctx); !errors.Is(err, bridgeowner.ErrCleanup) {
		t.Fatalf("lost first native failure: %v", err)
	}
	if native.calls.Load() != 1 {
		t.Fatal("protocol owner did not invoke custody exactly once")
	}
	if err := session.StopAndWait(ctx); err != nil || native.calls.Load() != 2 {
		t.Fatalf("independent native retry unavailable: calls=%d err=%v", native.calls.Load(), err)
	}
	// Native recovery never rewrites a failed protocol session as successful.
	if err := owner.Close(ctx); !errors.Is(err, bridgeowner.ErrCleanup) {
		t.Fatal("historical failed session was relabeled successful")
	}
}

func TestZeroSessionAndImageDoNotCreateResources(t *testing.T) {
	for _, session := range []*Session{nil, {}} {
		if !errors.Is(session.StopAndWait(context.Background()), ErrAdmission) || !errors.Is(session.Close(context.Background()), ErrAdmission) {
			t.Fatal("zero session accepted lifecycle authority")
		}
	}
	for _, image := range []*Image{nil, {}} {
		if err := image.Close(); err != nil {
			t.Fatal(err)
		}
		if err := image.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
