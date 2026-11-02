// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package ipc

import (
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// peerProcessKey identifies one process image: the pid, its start time, and
// its command name. A reused pid has a different start time, and an exec in
// the same process changes the command name, so neither reuses a cached
// identity.
type peerProcessKey struct {
	pid       int32
	startSec  int64
	startUsec int64
	comm      string
}

// peerProcessIdentity reads the process start time and command name for pid.
// Overridable in tests.
var peerProcessIdentity = func(pid int32) (peerProcessKey, bool) {
	info, err := unix.SysctlKinfoProc("kern.proc.pid", int(pid))
	if err != nil || info == nil || info.Proc.P_pid != pid {
		return peerProcessKey{}, false
	}
	comm := make([]byte, 0, len(info.Proc.P_comm))
	for _, c := range info.Proc.P_comm {
		if c == 0 {
			break
		}
		comm = append(comm, byte(c))
	}
	start := info.Proc.P_starttime
	return peerProcessKey{
		pid:       pid,
		startSec:  int64(start.Sec),
		startUsec: int64(start.Usec),
		comm:      string(comm),
	}, true
}

type peerCodesignIdentity struct {
	teamID, signingID, bundleID, exePath string
	at                                   time.Time
}

const (
	peerCodesignCacheTTL  = 10 * time.Minute
	peerCodesignCacheSize = 256
)

// peerCodesignCache keeps the codesign identity of each connecting process
// image, so a GUI that reconnects does not pay a codesign exec (and its
// timeout risk) on every connection. Only identities that carry a signing
// field are cached; the allowlist decision itself is made on every connection
// and is unchanged.
type peerCodesignCache struct {
	mu      sync.Mutex
	now     func() time.Time
	entries map[peerProcessKey]peerCodesignIdentity
	// timeoutLogged is set while lookups keep timing out, so the degraded line
	// is logged once per streak.
	timeoutLogged bool
}

var peerCodesignIdentities = &peerCodesignCache{now: time.Now}

func (c *peerCodesignCache) get(key peerProcessKey) (peerCodesignIdentity, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok || c.now().Sub(entry.at) > peerCodesignCacheTTL {
		return peerCodesignIdentity{}, false
	}
	return entry, true
}

func (c *peerCodesignCache) put(key peerProcessKey, identity peerCodesignIdentity) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil || len(c.entries) >= peerCodesignCacheSize {
		c.entries = map[peerProcessKey]peerCodesignIdentity{}
	}
	identity.at = c.now()
	c.entries[key] = identity
}

// noteTimeout records the outcome of a lookup and reports whether a degraded
// line is due (the first timeout after a success).
func (c *peerCodesignCache) noteTimeout(timedOut bool) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !timedOut {
		c.timeoutLogged = false
		return false
	}
	if c.timeoutLogged {
		return false
	}
	c.timeoutLogged = true
	return true
}

// readCodesignForPIDCached returns the codesign identity of pid, from the
// cache when the same process image was looked up recently. A lookup that
// times out is retried once; if it times out again the identity stays empty
// (the peer is refused, as before) and defenseclaw_degraded is logged once per
// streak.
func readCodesignForPIDCached(pid int32) (teamID, signingID, bundleID, exePath string, err error) {
	return peerCodesignIdentities.read(pid)
}

func (c *peerCodesignCache) read(pid int32) (teamID, signingID, bundleID, exePath string, err error) {
	key, keyed := peerProcessIdentity(pid)
	if keyed {
		if cached, ok := c.get(key); ok {
			return cached.teamID, cached.signingID, cached.bundleID, cached.exePath, nil
		}
	}
	output, timedOut := codesignOutputWithRetry(pid)
	if c.noteTimeout(timedOut) {
		managed.EmitResilienceEvent(managed.MarkerDegraded, map[string]string{
			"component": "ipc",
			"reason":    "codesign_timeout",
		})
	}
	teamID, signingID, bundleID, exePath = parseCodesignIdentity(output)
	if timedOut || !keyed || (teamID == "" && signingID == "") {
		return teamID, signingID, bundleID, exePath, nil
	}
	// Cache only when the process is still the image that was inspected.
	if after, ok := peerProcessIdentity(pid); ok && after == key {
		c.put(key, peerCodesignIdentity{teamID: teamID, signingID: signingID, bundleID: bundleID, exePath: exePath})
	}
	return teamID, signingID, bundleID, exePath, nil
}
