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

import "github.com/fsnotify/fsnotify"

// enterpriseHookWatchEventBuffer bounds the fsnotify events queued for the
// guardian's watch loop while a reconcile runs.
const enterpriseHookWatchEventBuffer = 1024

// enterpriseHookWatchPump keeps an fsnotify watcher's channels drained.
//
// On Windows, fsnotify serves Add and Remove on the goroutine that delivers
// events, and that goroutine waits until someone reads each event. The watch
// loop calls Add and Remove from inside a reconcile, whose own writes raise
// events in the watched folders, so the first reconcile that had to watch a
// new folder (a new target) hung the guardian for good: no more reconciles,
// stale state and authorization, while the service still showed Running.
// The pump reads the watcher at all times. When its queue is full it drops
// the event and signals Overflow, and the loop reconciles anyway.
type enterpriseHookWatchPump struct {
	Events   chan fsnotify.Event
	Errors   chan error
	Overflow chan struct{}
}

func newEnterpriseHookWatchPump(events <-chan fsnotify.Event, errs <-chan error, size int) *enterpriseHookWatchPump {
	pump := &enterpriseHookWatchPump{
		Events:   make(chan fsnotify.Event, size),
		Errors:   make(chan error, size),
		Overflow: make(chan struct{}, 1),
	}
	go func() {
		defer close(pump.Events)
		for event := range events {
			select {
			case pump.Events <- event:
			default:
				pump.overflow()
			}
		}
	}()
	go func() {
		defer close(pump.Errors)
		for err := range errs {
			select {
			case pump.Errors <- err:
			default:
				pump.overflow()
			}
		}
	}()
	return pump
}

func (p *enterpriseHookWatchPump) overflow() {
	select {
	case p.Overflow <- struct{}{}:
	default:
	}
}
