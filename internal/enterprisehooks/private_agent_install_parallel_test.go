// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Two independent directory branches must advance together under the
// Windows held-handle walk. The channel rendezvous pins concurrency without
// relying on a sleep or a machine-specific directory count.
func TestPrivateWalkListsIndependentBranchesConcurrently(t *testing.T) {
	home := t.TempDir()
	for _, name := range []string{"left", "right"} {
		if err := os.MkdirAll(filepath.Join(home, name, "node_modules"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	entered := make(chan string, 2)
	proceed := make(chan struct{})
	go func() {
		select {
		case <-entered:
		case <-ctx.Done():
			return
		}
		select {
		case <-entered:
			close(proceed)
		case <-ctx.Done():
		}
	}()
	prefixes, complete := walkPrivateNPMPrefixes(ctx, home, privateInstallWalk{
		open: os.Open,
		openChild: func(parent *os.File, name string) (*os.File, error) {
			if name == "left" || name == "right" {
				entered <- name
				select {
				case <-proceed:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return os.Open(filepath.Join(parent.Name(), name))
		},
		unreachable: func(_ string, err error) bool { return errors.Is(err, os.ErrNotExist) },
	})
	if !complete {
		t.Fatal("independent directory branches did not finish inside the bounded scan")
	}
	if len(prefixes) != 2 || prefixes[0] != filepath.Join(home, "left") || prefixes[1] != filepath.Join(home, "right") {
		t.Fatalf("parallel prefixes = %q, want deterministic left and right", prefixes)
	}
}
