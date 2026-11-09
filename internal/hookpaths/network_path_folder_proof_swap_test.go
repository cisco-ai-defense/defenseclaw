// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// proofReader is one place that reads names with the folders of its scope
// proved once: the evaluation memo (lstat and stat), the hook client reads
// and the proofs themselves.
type proofReader struct {
	name string
	read func(name string) error
}

func proofReaders() []proofReader {
	memoL, memoS := NewTargetMemo(), NewTargetMemo()
	memoL.beginScan()
	memoS.beginScan()
	var bare folderProofs
	var bareStat folderProofs
	reads := &scanReads{}
	return []proofReader{
		{"memo lstat", func(n string) error { _, err := memoL.lstat(n); return err }},
		{"memo stat", func(n string) error { _, err := memoS.stat(n); return err }},
		{"hook client stat", func(n string) error { _, err := reads.stat(n); return err }},
		{"proofs lstat", func(n string) error { _, err := bare.lstat(n); return err }},
		{"proofs stat", func(n string) error { _, err := bareStat.stat(n); return err }},
	}
}

func readsBelow(t *testing.T, read proofReader, dir string, n int) {
	t.Helper()
	for i := range n {
		if err := read.read(filepath.Join(dir, fmt.Sprintf("f%d", i))); errors.Is(err, errNetworkShareUnanswered) {
			t.Fatalf("%s: ordinary name %d is read as a share: %v", read.name, i, err)
		}
	}
}

// A folder a scope proved plain can become a link to a share that does not
// answer in the same scope, or a folder above it can; a different name read
// below it is asked, once, by every reader of a scope.
func TestProvedFolderThatBecomesALinkInTheScopeIsAsked(t *testing.T) {
	for _, swap := range []string{"folder", "ancestor"} {
		for _, reader := range proofReaders() {
			t.Run(swap+"/"+reader.name, func(t *testing.T) {
				fx := newWalkReuseFixture(t)
				end := HookCall()
				defer end()
				readsBelow(t, reader, fx.slot, 50)
				old, target := fx.slot, fx.share
				if swap == "ancestor" {
					old, target = fx.project, filepath.Join(fx.share, "project")
				}
				if err := os.Rename(old, old+"-old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, old); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
				if err := reader.read(filepath.Join(fx.slot, "skills")); !errors.Is(err, errNetworkShareUnanswered) {
					t.Fatalf("read below the swapped %s = %v, want the share error", swap, err)
				}
				if got := fx.probes(); got != 1 {
					t.Fatalf("%d probes, want one", got)
				}
			})
		}
	}
}

// The benign twin: a proved folder replaced by another plain folder is read
// on with no probe and proved again, so the call does not turn an ordinary
// change into a block or into walk reads for each name.
func TestProvedFolderReplacedByAnotherFolderStaysReadable(t *testing.T) {
	for _, reader := range proofReaders() {
		t.Run(reader.name, func(t *testing.T) {
			fx := newWalkReuseFixture(t)
			end := HookCall()
			defer end()
			readsBelow(t, reader, fx.slot, 50)
			if err := os.Rename(fx.slot, fx.slot+"-old"); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(fx.slot, 0o700); err != nil {
				t.Fatal(err)
			}
			reads := countWalkReads(t)
			readsBelow(t, reader, fx.slot, 500)
			if got := fx.probes(); got != 0 {
				t.Fatalf("%d probes for a plain folder, want none", got)
			}
			if *reads > 20 {
				t.Fatalf("500 names below the replaced folder made %d walk reads, want at most 20", *reads)
			}
		})
	}
}

// The read of a proved folder that the system holds (a folder above it
// became a link to a share that does not answer) is bounded by the answer
// wait and reported unanswered, and the proof is dropped.
func TestProvedFolderReadThatDoesNotReturnIsBounded(t *testing.T) {
	for _, reader := range proofReaders() {
		t.Run(reader.name, func(t *testing.T) {
			fx := newWalkReuseFixture(t)
			end := HookCall()
			defer end()
			readsBelow(t, reader, fx.slot, 10)
			release := make(chan struct{})
			defer close(release)
			old := folderLstat
			folderLstat = func(name string) (os.FileInfo, error) {
				if name == fx.slot {
					<-release
				}
				return os.Lstat(name)
			}
			t.Cleanup(func() { folderLstat = old })
			start := time.Now()
			if err := reader.read(filepath.Join(fx.slot, "held")); !errors.Is(err, errNetworkShareUnanswered) {
				t.Fatalf("held read = %v, want the share error", err)
			}
			if took := time.Since(start); took > 5*time.Second {
				t.Fatalf("held read took %v, want about the answer wait", took)
			}
		})
	}
}

// Trusting a proof costs one read of the folder alone for a name: thousands
// of names below one folder make about as many folder reads and no more walk
// reads than the folders need. The count is the cost on Windows, which is one
// component read where the walk reads every component of the name.
func TestProvedFolderIsTrustedOnOneFolderReadAName(t *testing.T) {
	fx := newWalkReuseFixture(t)
	end := HookCall()
	defer end()
	var folderReads atomic.Int64
	old := folderLstat
	folderLstat = func(name string) (os.FileInfo, error) {
		folderReads.Add(1)
		return os.Lstat(name)
	}
	t.Cleanup(func() { folderLstat = old })
	walks := countWalkReads(t)
	const names = 1000
	for _, reader := range proofReaders() {
		folderReads.Store(0)
		*walks = 0
		readsBelow(t, reader, fx.slot, names)
		if got := folderReads.Load(); got > names+20 {
			t.Errorf("%s: %d names made %d folder reads, want at most %d", reader.name, names, got, names+20)
		}
		if *walks > 20 {
			t.Errorf("%s: %d names made %d walk reads, want at most 20", reader.name, names, *walks)
		}
	}
}

// What stat follows proves no folder: a name that is a link to a folder is
// not one, and a name below it is read with the walk.
func TestProofsDoNotTakeALinkFollowedByStatForAFolder(t *testing.T) {
	fx := newWalkReuseFixture(t)
	end := HookCall()
	defer end()
	link := filepath.Join(fx.project, "viashare")
	if err := os.Symlink(fx.share, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	var proofs folderProofs
	if _, err := proofs.stat(link); !errors.Is(err, errNetworkShareUnanswered) {
		t.Fatalf("stat of a link to a share = %v, want the share error", err)
	}
	if _, err := proofs.lstat(filepath.Join(link, "skills")); !errors.Is(err, errNetworkShareUnanswered) {
		t.Fatalf("read below a link to a share = %v, want the share error", err)
	}
	proofs.mu.Lock()
	_, proved := proofs.plain[link]
	proofs.mu.Unlock()
	if proved {
		t.Fatal("a link followed by stat is kept as a plain folder")
	}
}
