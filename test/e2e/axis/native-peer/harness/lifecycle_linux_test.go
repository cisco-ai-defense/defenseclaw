// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

// These are inert host filesystem fixtures with a Go writer goroutine only.
// They never invoke a peer, image, payload, namespace or child entry point.
func lifecycleTreeFixture(t *testing.T) (*treeObservation, []*os.File, string) {
	t.Helper()
	root := t.TempDir()
	work, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = work.Close() })
	observation := &treeObservation{work: work}
	t.Cleanup(func() { _ = observation.close() })
	var writers []*os.File
	for _, name := range treeNames {
		if err := os.WriteFile(filepath.Join(root, name+".ready"), []byte(sentinel), 0600); err != nil {
			t.Fatal(err)
		}
		file, err := os.OpenFile(filepath.Join(root, name+".heartbeat"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		writers = append(writers, file)
		t.Cleanup(func() { _ = file.Close() })
		if _, err := file.WriteAt([]byte("1"), 0); err != nil {
			t.Fatal(err)
		}
	}
	return observation, writers, root
}

func TestLifecycleTreeRequiresProgressThenFiniteStability(t *testing.T) {
	observation, writers, _ := lifecycleTreeFixture(t)
	stop, done := make(chan struct{}), make(chan error, 1)
	finish := sync.OnceFunc(func() { close(stop) })
	joined := false
	defer func() {
		finish()
		if !joined {
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("inert heartbeat writer cleanup deadline exceeded")
			}
		}
	}()
	go func() {
		ticker := time.NewTicker(40 * time.Millisecond)
		defer ticker.Stop()
		for count := 2; ; count++ {
			select {
			case <-stop:
				done <- nil
				return
			case <-ticker.C:
			}
			for _, file := range writers {
				if _, err := file.WriteAt([]byte(strconv.Itoa(count)), 0); err != nil {
					done <- err
					return
				}
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := observation.beforeCancel(ctx); err != nil {
		t.Fatal(err)
	}
	if err := observation.stableBeforeDestroy(ctx); err == nil {
		t.Fatal("continuing synthetic writer was reported stable")
	}
	finish()
	select {
	case err := <-done:
		joined = true
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("inert heartbeat writer did not stop")
	}
	if err := observation.stableBeforeDestroy(ctx); err != nil {
		t.Fatalf("bounded stopped-writer observation failed: %v", err)
	}
	if observation.evidence.StableSamples != 6 {
		t.Fatal("failed earlier sampling was reused as successful stability proof")
	}
	for i := range 3 {
		if observation.evidence.Before[i] == 0 || observation.evidence.Progressed[i] <= observation.evidence.Before[i] || observation.evidence.Terminal[i] < observation.evidence.Progressed[i] {
			t.Fatal("fixed before/progress/terminal counts were not retained")
		}
	}
}

func TestLifecycleTreeRejectsNoProgressLinksAndOversizedFiles(t *testing.T) {
	for _, bad := range []string{"no-progress", "linked-ready", "oversized-heartbeat"} {
		t.Run(bad, func(t *testing.T) {
			observation, _, root := lifecycleTreeFixture(t)
			switch bad {
			case "linked-ready":
				path := filepath.Join(root, treeNames[0]+".ready")
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(treeNames[1]+".ready", path); err != nil {
					t.Fatal(err)
				}
			case "oversized-heartbeat":
				if err := os.WriteFile(filepath.Join(root, treeNames[0]+".heartbeat"), []byte("12345678901234567"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
			defer cancel()
			if err := observation.beforeCancel(ctx); err == nil {
				t.Fatal("unqualified tree file observation accepted")
			}
		})
	}
	if heartbeatProgress(nil, nil) {
		t.Fatal("missing heartbeats proved progress")
	}
}
