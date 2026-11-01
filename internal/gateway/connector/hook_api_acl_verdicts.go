// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"errors"
	"sync"
	"time"
)

// errHookAPIACLUnfinished is the verdict of an inspection that did not return.
var errHookAPIACLUnfinished = errors.New("the ACL inspection did not finish")

// hookAPIACLVerdicts remembers the directories whose ACL inspection found no
// write-capable entry, keyed by the directory's identity: device, inode,
// mode, owner and status-change time. An ACL change, a chmod, a chown and a
// replaced directory all change that identity, so the next check inspects
// the directory again; a clean verdict is also kept for at most
// hookAPIACLCleanFor. A verdict that refuses, and an inspection that failed,
// are never kept.
//
// Every hook request reads the hook API token and checks the ACL of each
// directory above it. On macOS the inspection is one /bin/ls process per
// directory (five for a token under the home), and process starts are
// serialized in the gateway: in a 32-way burst of Claude Code hook calls the
// requests queued behind about 160 of them before the handler ran, and the
// hooks denied benign calls as a gateway that did not answer (rel-1-0-6
// GAP-0129). Concurrent checks of one directory share one inspection.
type hookAPIACLVerdicts struct {
	mu      sync.Mutex
	clean   map[string]hookAPIACLClean
	running map[string]*hookAPIACLRun
	// now is the clock; tests replace it.
	now func() time.Time
}

type hookAPIACLClean struct {
	identity string
	at       time.Time
}

type hookAPIACLRun struct {
	identity string
	done     chan struct{}
	err      error
}

const (
	// hookAPIACLCleanFor bounds how long a clean verdict is reused.
	hookAPIACLCleanFor = 10 * time.Second
	// hookAPIACLVerdictLimit bounds the directories remembered.
	hookAPIACLVerdictLimit = 256
)

func (v *hookAPIACLVerdicts) clock() time.Time {
	if v.now != nil {
		return v.now()
	}
	return time.Now()
}

// check returns the ACL verdict of path, whose identity is identity ("" when
// it could not be read: then the directory is inspected and nothing is
// kept). inspect runs the inspection.
func (v *hookAPIACLVerdicts) check(path, identity string, inspect func() error) error {
	if identity == "" {
		return inspect()
	}
	v.mu.Lock()
	started := v.clock()
	if clean, ok := v.clean[path]; ok && clean.identity == identity && started.Sub(clean.at) < hookAPIACLCleanFor {
		v.mu.Unlock()
		return nil
	}
	if run := v.running[path]; run != nil && run.identity == identity {
		v.mu.Unlock()
		<-run.done
		return run.err
	}
	run := &hookAPIACLRun{identity: identity, done: make(chan struct{})}
	if v.running == nil {
		v.running = make(map[string]*hookAPIACLRun)
	}
	v.running[path] = run
	v.mu.Unlock()
	run.err = errHookAPIACLUnfinished
	defer func() {
		v.mu.Lock()
		if v.running[path] == run {
			delete(v.running, path)
		}
		if run.err != nil {
			delete(v.clean, path)
		} else {
			if v.clean == nil || len(v.clean) >= hookAPIACLVerdictLimit {
				v.clean = make(map[string]hookAPIACLClean)
			}
			// The verdict holds from when the inspection started: a change
			// during it has a later status-change time and is inspected again.
			v.clean[path] = hookAPIACLClean{identity: identity, at: started}
		}
		v.mu.Unlock()
		close(run.done)
	}()
	run.err = inspect()
	return run.err
}
