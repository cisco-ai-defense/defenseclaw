// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Adding a watch while nobody reads the loop's events must not hang: on
// Windows fsnotify serves Add on the goroutine that delivers events, and the
// guardian adds watches from inside a reconcile. 200 writes overflow the
// watcher's own 50-event Windows buffer.
func TestEnterpriseHookWatchPumpKeepsAddFromBlocking(t *testing.T) {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatal(err)
	}
	defer fsw.Close()
	pump := newEnterpriseHookWatchPump(fsw.Events, fsw.Errors, 2)
	watched, next := t.TempDir(), t.TempDir()
	if err := fsw.Add(watched); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 200; i++ {
		if err := os.WriteFile(filepath.Join(watched, "f"+strconv.Itoa(i)), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-pump.Overflow:
	case <-time.After(10 * time.Second):
		t.Fatal("a full queue must signal Overflow")
	}
	added := make(chan error, 1)
	go func() { added <- fsw.Add(next) }()
	select {
	case err := <-added:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Add hung while the loop was not reading events")
	}
}
