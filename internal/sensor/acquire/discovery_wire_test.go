// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acquire

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

// OpDiscovery is served only by a helper configured for it (the Cowork VM
// helper); every other helper answers as one that predates the op, and a
// second read while one runs is turned away. Neither counts against the
// helper's reachability.
func TestHelperServesDiscoveryOnlyWhenConfigured(t *testing.T) {
	ctx := context.Background()
	var body map[string]any
	plain := serveHelper(t, ServerConfig{})
	if err := plain.Discovery(ctx, &body); !errors.Is(err, ErrDiscoveryUnsupported) {
		t.Fatalf("an unconfigured helper: %v", err)
	}
	if !plain.WideCoverage() {
		t.Fatal("an unsupported discovery read marked the helper unreachable")
	}

	release := make(chan struct{})
	started := make(chan struct{})
	var once sync.Once
	served := serveHelper(t, ServerConfig{Discovery: func(context.Context) (any, error) {
		once.Do(func() { close(started) })
		<-release
		return map[string]any{"version": 1}, nil
	}})
	first := make(chan error, 1)
	go func() {
		var got map[string]any
		err := served.Discovery(ctx, &got)
		if err == nil && got["version"] != float64(1) {
			err = errors.New("unexpected body")
		}
		first <- err
	}()
	<-started
	if err := served.Discovery(ctx, &body); err == nil || !strings.Contains(err.Error(), errDiscoveryBusy) {
		t.Fatalf("a concurrent read: %v", err)
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatalf("the discovery read: %v", err)
	}
}
