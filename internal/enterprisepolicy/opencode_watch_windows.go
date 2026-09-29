// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisepolicy

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

// OpenCode's runtime opens every module with FILE_WRITE_ATTRIBUTES, so the
// managed plugin grants Users that right (openCodePluginFileSDDL), and with
// it any standard account can mark the plugin read-only or set a reparse
// point on it that no reader can follow: every account's OpenCode then runs
// without DefenseClaw until the guardian's next pass. The guardian therefore
// also watches the plugin's folder and runs the pass's heal
// (InstallOpenCodeManagedPlugin) right after a change. The right stays until
// an OpenCode release no longer asks for it when it imports a module.

// Watch tuning and the armed notification; tests replace them.
var (
	openCodeWatchDebounce = 250 * time.Millisecond
	openCodeWatchRearm    = 30 * time.Second
	openCodeHealWindow    = time.Minute
	openCodeHealBudget    = 12
	openCodeHealThrottle  = 5 * time.Second
	openCodeWatchArmed    = func() {}
)

const openCodeWatchFilter = windows.FILE_NOTIFY_CHANGE_FILE_NAME |
	windows.FILE_NOTIFY_CHANGE_DIR_NAME |
	windows.FILE_NOTIFY_CHANGE_ATTRIBUTES |
	windows.FILE_NOTIFY_CHANGE_SIZE |
	windows.FILE_NOTIFY_CHANGE_LAST_WRITE |
	windows.FILE_NOTIFY_CHANGE_SECURITY

// WatchOpenCodeManagedPlugin restores the managed OpenCode plugin after
// every burst of attribute, name, security or content changes in its
// folder until ctx ends. Bursts are debounced, and past openCodeHealBudget
// rewrites per openCodeHealWindow at most one runs per openCodeHealThrottle,
// so a loop of changes can neither keep the guardian busy nor keep the
// plugin unreadable until the pass, which stays the backstop. A failed
// watch is re-armed.
// lock serializes the heal with the guardian's other writers of the plugin;
// logf records each restored change and each failure.
func WatchOpenCodeManagedPlugin(ctx context.Context, opts Options, lock sync.Locker, logf func(string, ...any)) {
	if opts.goos() != "windows" || strings.TrimSpace(opts.OpenCodePluginPath) == "" {
		return
	}
	file := opts.openCodeArtifactFile()
	changes := make(chan struct{}, 1)
	go func() {
		dir := filepath.Dir(file)
		reported := false
		for ctx.Err() == nil {
			err := watchDirectoryChanges(ctx, dir, changes)
			if ctx.Err() != nil {
				return
			}
			if !reported {
				logf("managed OpenCode plugin watch on %s stopped: %v; retrying every %s, and every pass still restores the plugin", dir, err, openCodeWatchRearm)
				reported = true
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(openCodeWatchRearm):
			}
		}
	}()
	windowStart := time.Now()
	heals := 0
	limited := false
	var lastHeal time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-changes:
		}
		if time.Since(windowStart) >= openCodeHealWindow {
			windowStart, heals, limited = time.Now(), 0, false
		}
		// Let a burst settle; the heal's own rewrite also lands here. Past the
		// budget the heal slows down instead of stopping: dropping changes
		// would let an account spend the budget and then keep the plugin
		// unreadable until the next pass.
		wait := openCodeWatchDebounce
		if heals >= openCodeHealBudget {
			if !limited {
				logf("the managed OpenCode plugin keeps changing; restoring it at most every %s", openCodeHealThrottle)
				limited = true
			}
			if throttle := time.Until(lastHeal.Add(openCodeHealThrottle)); throttle > wait {
				wait = throttle
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		select {
		case <-changes:
		default:
		}
		// A missing plugin is left to the pass: no account can delete it,
		// and only teardown removes it.
		name, err := windows.UTF16PtrFromString(file)
		if err != nil {
			continue
		}
		if _, err := windows.GetFileAttributes(name); err != nil {
			continue
		}
		lock.Lock()
		changed, err := InstallOpenCodeManagedPlugin(opts)
		lock.Unlock()
		if changed || err != nil {
			heals++
			lastHeal = time.Now()
		}
		switch {
		case err != nil:
			logf("tamper: the managed OpenCode plugin %s changed and restoring it failed: %v", file, err)
		case changed:
			logf("tamper: the managed OpenCode plugin %s changed (attributes, reparse point or content); restored it", file)
		}
	}
}

// watchDirectoryChanges signals notify after each change in dir that
// matches openCodeWatchFilter, until ctx ends or the watch fails.
func watchDirectoryChanges(ctx context.Context, dir string, notify chan<- struct{}) error {
	name, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(name, windows.FILE_LIST_DIRECTORY,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_OVERLAPPED, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	done, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(done)
	cancelled, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(cancelled)
	stop := context.AfterFunc(ctx, func() { _ = windows.SetEvent(cancelled) })
	defer stop()
	// The kernel writes the change records and the completion status after
	// ReadDirectoryChanges returns, so they must not live on this goroutine's
	// stack, which can move. Keep them pinned on the heap; every return below
	// follows the read's completion. Only the notification matters; the
	// change records are not read.
	read := &struct {
		overlapped windows.Overlapped
		buffer     [4096]byte
	}{}
	var pinner runtime.Pinner
	pinner.Pin(read)
	defer pinner.Unpin()
	for {
		if err := windows.ResetEvent(done); err != nil {
			return err
		}
		read.overlapped = windows.Overlapped{HEvent: done}
		if err := windows.ReadDirectoryChanges(handle, &read.buffer[0], uint32(len(read.buffer)), false,
			openCodeWatchFilter, nil, &read.overlapped, 0); err != nil {
			return fmt.Errorf("watch %s: %w", dir, err)
		}
		openCodeWatchArmed()
		event, err := windows.WaitForMultipleObjects([]windows.Handle{done, cancelled}, false, windows.INFINITE)
		var transferred uint32
		if err != nil || event != windows.WAIT_OBJECT_0 {
			_ = windows.CancelIoEx(handle, &read.overlapped)
			_ = windows.GetOverlappedResult(handle, &read.overlapped, &transferred, true)
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("watch %s: wait: %v", dir, err)
		}
		if err := windows.GetOverlappedResult(handle, &read.overlapped, &transferred, false); err != nil {
			return fmt.Errorf("watch %s: %w", dir, err)
		}
		select {
		case notify <- struct{}{}:
		default:
		}
	}
}
