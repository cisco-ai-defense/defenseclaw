// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// answerWatchdogLogPrepareLead is how long before its answer deadline a tool
// call that is still waiting opens its hook-failure log
// (preparedFailureLog). The watchdog that answers at the deadline then only
// appends its line to the open file inside answerWatchdogLogWait. Before,
// it looked up the folder and opened the file shared by every hook of the
// account after its answer, and on a saturated host (par 128 on 16 vCPU)
// that took longer than the wait: the process ended and the denied call had
// no record (rel-1-0-6 GAP-0407). A call answered before the lead opens
// nothing.
var answerWatchdogLogPrepareLead = time.Second

// openHookFailureLog opens the hook-failure log; tests replace it to stall
// the open.
var openHookFailureLog = os.OpenFile

// preparedFailureLog is the hook-failure log of one tool call, opened ahead
// of its answer deadline. Every copy of the call's Options shares it
// (Options.failureLog), and the first failure line of the call takes it.
type preparedFailureLog struct {
	once        sync.Once
	done        chan struct{}
	markerReady chan struct{}
	// open and record are openHookFailureLog and managedHookDecisionRecorder
	// as the call found them: its lines can be written by a goroutine that
	// outlives it (the watchdog's log line past answerWatchdogLogWait, the
	// open ahead of the deadline), and a test that replaced either after the
	// call raced that read (rel-1-0-6 GAP-0680).
	open   func(string, int, os.FileMode) (*os.File, error)
	record func(source, marker, line string)

	mu            sync.Mutex
	home          string
	file          *os.File
	marker        *os.File
	markerEnabled bool
	markerTaken   bool
	forceMarker   bool
	fallbackFrame []byte
	taken         bool
	closed        bool
	// restartReason is the bounded proof's result for a per-user no-answer.
	restartReason string
}

func (p *preparedFailureLog) setRestartReason(reason string) {
	if p == nil || reason == "" {
		return
	}
	p.mu.Lock()
	p.restartReason = reason
	p.mu.Unlock()
}

func (p *preparedFailureLog) getRestartReason() string {
	if p == nil {
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.restartReason
}

func newPreparedFailureLog() *preparedFailureLog {
	return &preparedFailureLog{done: make(chan struct{}), markerReady: make(chan struct{}), open: openHookFailureLog, record: managedHookDecisionRecorder}
}

// opener is the call's openHookFailureLog.
func (p *preparedFailureLog) opener() func(string, int, os.FileMode) (*os.File, error) {
	if p == nil || p.open == nil {
		return openHookFailureLog
	}
	return p.open
}

// recorder is the call's managedHookDecisionRecorder.
func (p *preparedFailureLog) recorder() func(source, marker, line string) {
	if p == nil || p.record == nil {
		return managedHookDecisionRecorder
	}
	return p.record
}

// prepare opens the per-user marker before the ordinary failure log. The
// marker can be used if opening or writing the ordinary log is delayed.
// A managed call does not create either folder or file here.
func (p *preparedFailureLog) prepare(home func() string) {
	if p == nil || home == nil {
		return
	}
	p.once.Do(func() {
		go func() {
			defer close(p.done)
			h := home()
			if h == "" {
				close(p.markerReady)
				return
			}
			if p.markerEnabled {
				if info, err := os.Stat(h); err == nil && info.IsDir() {
					_ = os.Mkdir(filepath.Join(h, "logs"), 0o700)
				}
				marker, err := p.opener()(filepath.Join(h, "logs", "hook-failures.dropped"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
				if err == nil {
					p.mu.Lock()
					if p.closed {
						_ = marker.Close()
					} else {
						p.home, p.marker = h, marker
					}
					p.mu.Unlock()
				}
			}
			close(p.markerReady)
			f, err := p.opener()(filepath.Join(h, "logs", "hook-failures.jsonl"), os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				return
			}
			p.mu.Lock()
			defer p.mu.Unlock()
			if p.closed {
				_ = f.Close()
				return
			}
			p.home, p.file = h, f
		}()
	})
}

// take hands the ready ordinary log to the first failure line of the call.
// An open still in progress leaves the caller free to use the marker.
func (p *preparedFailureLog) take(home string) *os.File {
	if p == nil || home == "" {
		return nil
	}
	select {
	case <-p.done:
	default:
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.taken || p.closed || p.file == nil || p.home != home {
		return nil
	}
	p.taken = true
	return p.file
}

func (p *preparedFailureLog) forceFallback() {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.forceMarker = true
	p.mu.Unlock()
}

func (p *preparedFailureLog) wantsFallback() bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.forceMarker
}

func (p *preparedFailureLog) takeMarker(home string) *os.File {
	if p == nil || home == "" || !p.markerEnabled {
		return nil
	}
	select {
	case <-p.markerReady:
	default:
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.markerTaken || p.marker == nil || p.home != home {
		return nil
	}
	p.markerTaken = true
	return p.marker
}

func (p *preparedFailureLog) setFallbackFrame(frame []byte) {
	if p == nil {
		return
	}
	p.mu.Lock()
	if !bytes.Contains(p.fallbackFrame, []byte(`"outcome":"fail_closed"`)) ||
		bytes.Contains(frame, []byte(`"outcome":"fail_closed"`)) {
		p.fallbackFrame = append(p.fallbackFrame[:0], frame...)
	}
	p.mu.Unlock()
}

func (p *preparedFailureLog) promoteFallbackClosed() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !bytes.HasPrefix(p.fallbackFrame, []byte("DCID")) {
		return
	}
	var entry hookFailureEntry
	if json.Unmarshal(p.fallbackFrame[4:], &entry) != nil {
		return
	}
	entry.Outcome, entry.FailMode = "fail_closed", "closed"
	if line, err := json.Marshal(entry); err == nil {
		p.fallbackFrame = append(append([]byte("DCID"), line...), '\n')
	}
}

func (p *preparedFailureLog) appendFallback() bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.marker == nil || len(p.fallbackFrame) == 0 {
		return false
	}
	n, err := p.marker.Write(p.fallbackFrame)
	return err == nil && n == len(p.fallbackFrame)
}

// close closes the log unless a failure line took it.
func (p *preparedFailureLog) close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	if !p.taken && p.file != nil {
		_ = p.file.Close()
	}
	if !p.markerTaken && p.marker != nil {
		_ = p.marker.Close()
	}
}

// failureLogHomeOf is the directory the failure lines of the call go to: the
// invoking user's diagnostic directory of a managed call (FailureLogHome,
// the one lookup of the watchdog), the per-user home otherwise.
func failureLogHomeOf(opts Options) func() string {
	if opts.ManagedEnterprise {
		return opts.FailureLogHome
	}
	home := opts.Home
	if home == "" {
		return nil
	}
	return func() string { return home }
}
