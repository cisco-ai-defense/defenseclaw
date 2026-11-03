// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/sys/windows"
)

// A volume that refuses POSIX renames must keep a complete policy at its
// published name throughout replacement. A neighbouring policy is a benign
// twin: it remains readable and byte-identical while the first is updated.
func TestClassicRenameFallbackKeepsPolicyPublished(t *testing.T) {
	dir := t.TempDir()
	policy := filepath.Join(dir, "managed-policy.json")
	neighbour := filepath.Join(dir, "unchanged-policy.json")
	if err := os.WriteFile(policy, []byte("version 00000000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(neighbour, []byte("unchanged\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(RefusePOSIXRenameForTest())
	var reads, missing, partial, neighbourChanged atomic.Int64
	stop := make(chan struct{})
	var readers sync.WaitGroup
	for range 2 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				body, err := readForSwapReaderTest(policy, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
				if errors.Is(err, os.ErrNotExist) {
					missing.Add(1)
				} else if err == nil {
					reads.Add(1)
					if len(body) != len("version 00000000\n") || string(body[:8]) != "version " ||
						body[len(body)-1] != '\n' {
						partial.Add(1)
					} else if _, err := strconv.Atoi(string(body[8:16])); err != nil {
						partial.Add(1)
					}
				}
				if body, err := os.ReadFile(neighbour); err != nil || string(body) != "unchanged\n" {
					neighbourChanged.Add(1)
				}
			}
		}()
	}
	var writeErr error
	for i := 1; i <= 300 && writeErr == nil; i++ {
		stage := filepath.Join(dir, fmt.Sprintf("stage-%d.tmp", i))
		if writeErr = os.WriteFile(stage, []byte(fmt.Sprintf("version %08d\n", i)), 0o600); writeErr == nil {
			writeErr = ReplaceFileAtomically(stage, policy)
		}
	}
	close(stop)
	readers.Wait()
	if writeErr != nil {
		t.Fatal(writeErr)
	}
	if reads.Load() == 0 || missing.Load() != 0 || partial.Load() != 0 || neighbourChanged.Load() != 0 {
		t.Fatalf("reads=%d missing=%d partial=%d unchanged_policy_changed=%d", reads.Load(), missing.Load(), partial.Load(), neighbourChanged.Load())
	}
	if body, err := os.ReadFile(policy); err != nil || string(body) != "version 00000300\n" {
		t.Fatalf("final policy %q: %v", body, err)
	}
}
