// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"errors"
	"fmt"
	"io/fs"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// stubReads replaces the vault's bounded read for one test and counts the
// sleeps between reads.
func stubReads(t *testing.T, read func(string, int64) ([]byte, error)) *int {
	t.Helper()
	prevRead, prevSleep := readBounded, stableReadSleep
	slept := 0
	readBounded = read
	stableReadSleep = func(time.Duration) { slept++ }
	t.Cleanup(func() { readBounded, stableReadSleep = prevRead, prevSleep })
	return &slept
}

func changed(path string) error {
	return fmt.Errorf("%w: %s", safefile.ErrFileChanged, path)
}

func TestVaultReadsAgainWhenAWriterReplacedTheVault(t *testing.T) {
	s := newStore(t)
	if _, err := s.Add(AddInput{Name: "API_KEY", Value: "value-one", Host: "api.example.com"}); err != nil {
		t.Fatal(err)
	}
	real := readBounded
	calls := 0
	slept := stubReads(t, func(path string, max int64) ([]byte, error) {
		if path == s.Path() {
			calls++
		}
		if path == s.Path() && calls <= 2 {
			return nil, changed(path)
		}
		return real(path, max)
	})
	entries, err := s.List()
	if err != nil || len(entries) != 1 || entries[0].Name != "API_KEY" {
		t.Fatalf("list after two replaced reads = %+v %v", entries, err)
	}
	if *slept != 2 {
		t.Fatalf("slept %d times, want 2", *slept)
	}
}

func TestVaultGivesUpOnAVaultThatKeepsChanging(t *testing.T) {
	s := newStore(t)
	calls := 0
	stubReads(t, func(path string, max int64) ([]byte, error) {
		calls++
		return nil, changed(path)
	})
	if _, err := s.List(); !errors.Is(err, safefile.ErrFileChanged) {
		t.Fatalf("list of a vault that keeps changing = %v, want ErrFileChanged", err)
	}
	if calls != len(stableReadDelays)+1 {
		t.Fatalf("read %d times, want %d", calls, len(stableReadDelays)+1)
	}
}

func TestVaultDoesNotRepeatOtherReadErrors(t *testing.T) {
	s := newStore(t)
	calls := 0
	slept := stubReads(t, func(path string, max int64) ([]byte, error) {
		calls++
		return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrPermission}
	})
	if _, err := s.List(); err == nil {
		t.Fatal("list of an unreadable vault succeeded")
	}
	if calls != 1 || *slept != 0 {
		t.Fatalf("read %d times and slept %d, want 1 and 0", calls, *slept)
	}
}

// Readers that take no lock (List, Resolve) see a whole vault while other
// stores write it.
func TestVaultReadsDuringConcurrentWritesSucceed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("this checks readers against the POSIX rename; Windows readers during a swap are not covered here")
	}
	dir := newStore(t).dir
	if _, err := Open(dir).Add(AddInput{Name: "BASE", Value: "value-base", Host: "api.example.com"}); err != nil {
		t.Fatal(err)
	}
	const writers, adds = 4, 10
	var wg sync.WaitGroup
	done := make(chan struct{})
	errs := make(chan error, writers+4)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < adds; i++ {
				if _, err := Open(dir).Add(AddInput{Name: fmt.Sprintf("W%d_%d", w, i), Value: fmt.Sprintf("value-w%d-%d", w, i), Host: "api.example.com"}); err != nil {
					errs <- err
					return
				}
			}
		}(w)
	}
	var readers sync.WaitGroup
	for r := 0; r < 4; r++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				if _, err := Open(dir).List(); err != nil {
					errs <- fmt.Errorf("list during writes: %w", err)
					return
				}
				if _, _, err := Open(dir).Resolve("BASE"); err != nil {
					errs <- fmt.Errorf("resolve during writes: %w", err)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(done)
	readers.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	entries, err := Open(dir).List()
	if err != nil || len(entries) != 1+writers*adds {
		t.Fatalf("after the writes: %d entries, %v; want %d", len(entries), err, 1+writers*adds)
	}
}
