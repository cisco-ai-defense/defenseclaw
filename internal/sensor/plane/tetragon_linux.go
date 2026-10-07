// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package plane

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

// The managed Linux sensor helper's Plane C: a customer-run Tetragon for the
// process half, with the native halves kept live inside the same stream.
//
//   - While Tetragon answers, its exec and exit events are the process half
//     and cn_proc does not run (two process sources would duplicate every
//     exec). When the Tetragon stream ends, cn_proc starts at once, the
//     coverage says so, and the source keeps redialling Tetragon; when it is
//     back, cn_proc stops again. The subscriber (the gateway) sees one
//     uninterrupted stream and a coverage update, never a reconnect.
//   - fanotify keeps the file half until DefenseClaw's own observe policy has
//     been enabled and delivering file events with no throttle, rate-limit
//     drop or known loss for handoffWindow. Any loss signal, the stream
//     ending or the policy leaving the enabled state starts it again. While
//     both run, a fanotify event is held for duplicateWindow and dropped when
//     Tetragon reported the same (pid, path): the Tetragon event carries the
//     exec id, the policy and its outcome.
//
// Everything this source forwards has been redacted with
// redaction.CommandLine, because the stream leaves a root process for the
// gateway's service account and carries every user's command lines.

// Tuning, variables so tests can shorten them.
var (
	handoffWindow   = 10 * time.Minute
	handoffInterval = 30 * time.Second
	duplicateWindow = time.Second
	superviseTick   = 200 * time.Millisecond
	redialInitial   = 2 * time.Second
	redialMax       = time.Minute
	dialTimeout     = 15 * time.Second
	// switchBackWindow is how long after Tetragon returns an exec it
	// reports for a pid cn_proc just delivered is taken as the same exec.
	switchBackWindow = 2 * time.Second
)

// maxCmdlineBytes bounds a forwarded command line, as the sandbox process
// tree does.
const maxCmdlineBytes = 1024

// maxHeld bounds the fanotify events waiting for a duplicate check. Past it
// the oldest is released at once: late is better than lost.
const maxHeld = 4096

// nativeHalf is one running half of the native backend (cn_proc or fanotify).
type nativeHalf interface {
	Events() <-chan Event
	Close() error
}

// halfSource is a linuxSource running one half only.
type halfSource struct {
	*linuxSource
	cancel context.CancelFunc
}

func (h halfSource) Close() error {
	h.cancel()
	return h.linuxSource.Close()
}

// startProcessHalf and startFileHalf start the native halves; tests replace
// them, because cn_proc needs CAP_NET_ADMIN and fanotify CAP_SYS_ADMIN.
var (
	startProcessHalf = func(ctx context.Context) (nativeHalf, error) {
		ctx, cancel := context.WithCancel(ctx)
		half := &linuxSource{buffer: NewBuffer()}
		if err := half.startProcessConnector(); err != nil {
			cancel()
			return nil, err
		}
		half.wg.Add(1)
		go func() { defer half.wg.Done(); half.readProcessConnector(ctx) }()
		return halfSource{linuxSource: half, cancel: cancel}, nil
	}
	startFileHalf = func(ctx context.Context, homes []string) (nativeHalf, error) {
		ctx, cancel := context.WithCancel(ctx)
		half := &linuxSource{buffer: NewBuffer(), credentialRoots: credentialRoots(homes)}
		if err := half.startFanotify(); err != nil {
			cancel()
			return nil, err
		}
		half.wg.Add(1)
		go func() { defer half.wg.Done(); half.readFanotify(ctx) }()
		return halfSource{linuxSource: half, cancel: cancel}, nil
	}
)

// NewTetragonSource returns the managed Linux helper's Plane C source. It is
// never used by a per-user gateway: only the helper, which reads its mode
// from the lifecycle's root-owned drop-in, builds one.
func NewTetragonSource(homeDirs []string, options TetragonOptions) Source {
	return &tetragonSource{
		homes:   homeDirs,
		options: options,
		buffer:  NewBuffer(),
		changes: make(chan struct{}, 1),
		now:     time.Now,
	}
}

type tetragonSource struct {
	homes   []string
	options TetragonOptions
	buffer  *Buffer
	changes chan struct{}
	now     func() time.Time

	mu      sync.Mutex
	closed  bool
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	feed    KernelFeed
	backend Backend
	// fallback is why the native process half runs ("" while Tetragon does).
	fallback string
	proc     nativeHalf
	procErr  error
	files    nativeHalf
	filesErr error
	handed   bool // fanotify stopped after the hand-off

	// Loss: rate-limit drops in the stream, and growth of Tetragon's own
	// loss counters since each session opened (lastLost is the counter at
	// the last read).
	dropped   int64
	knownLost int64
	lastLost  int64

	// Hand-off evidence.
	lossAt        time.Time // last throttle, rate-limit drop or known loss
	throttled     bool
	fileSince     time.Time // first Tetragon file event since lossAt
	observeSince  time.Time // observe policy enabled since
	switchedAt    time.Time // Tetragon took over the process half
	recentNative  map[int]time.Time
	dedupeMu      sync.Mutex
	tetragonFiles map[fileKey]time.Time
	held          []heldEvent
}

type fileKey struct {
	pid  int
	path string
}

type heldEvent struct {
	event Event
	until time.Time
}

func (s *tetragonSource) Events() <-chan Event             { return s.buffer.Events() }
func (s *tetragonSource) CoverageChanges() <-chan struct{} { return s.changes }

func (s *tetragonSource) Start(ctx context.Context) error {
	if s.options.Dial == nil {
		return errors.New("plane: the Tetragon source has no dialer")
	}
	ctx, cancel := context.WithCancel(ctx)
	s.mu.Lock()
	s.cancel = cancel
	s.backend = Backend{Kind: BackendNative, Mode: s.options.Mode}
	s.recentNative = map[int]time.Time{}
	s.tetragonFiles = map[fileKey]time.Time{}
	s.mu.Unlock()

	dialErr := s.dial(ctx)
	if dialErr != nil {
		s.startFallback(ctx, reasonOf(dialErr))
	}
	if len(s.homes) > 0 {
		s.startFiles(ctx)
	} else {
		s.mu.Lock()
		s.filesErr = errors.New("no enrolled home to watch")
		s.mu.Unlock()
	}

	s.mu.Lock()
	dead := s.feed == nil && s.proc == nil && s.files == nil
	procErr, filesErr := s.procErr, s.filesErr
	s.mu.Unlock()
	if dead {
		cancel()
		return fmt.Errorf("plane: linux plane C unavailable: tetragon: %v; cn_proc: %v; fanotify: %v",
			dialErr, procErr, filesErr)
	}

	s.wg.Add(1)
	go func() { defer s.wg.Done(); s.supervise(ctx) }()
	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()
	return nil
}

// reasonOf is the coverage reason for a dial error: its text, which the
// dialer starts with a reason code.
func reasonOf(err error) string {
	if err == nil {
		return ""
	}
	text := err.Error()
	if !strings.HasPrefix(text, "tetragon_") {
		text = "tetragon_unavailable: " + text
	}
	return text
}

// dial opens a Tetragon session and makes it the process half.
func (s *tetragonSource) dial(ctx context.Context) error {
	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	feed, err := s.options.Dial(dialCtx)
	cancel()
	if err != nil {
		return err
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = feed.Close()
		return errors.New("source closed")
	}
	s.feed = feed
	s.backend = feed.Backend()
	s.backend.Kind, s.backend.Mode = BackendTetragon, s.options.Mode
	s.fallback = ""
	s.switchedAt = s.now()
	s.lastLost = s.backend.EventsLost
	proc := s.proc
	s.proc, s.procErr = nil, nil
	s.mu.Unlock()
	if proc != nil {
		// Tetragon is delivering again: the native process half stops, or
		// every exec would arrive twice.
		go func() { _ = proc.Close() }()
	}
	s.wg.Add(1)
	go func() { defer s.wg.Done(); s.readFeed(ctx, feed) }()
	s.changed()
	return nil
}

// startFallback starts cn_proc because Tetragon is not delivering.
func (s *tetragonSource) startFallback(ctx context.Context, reason string) {
	s.mu.Lock()
	s.fallback = reason
	s.backend.Kind = BackendNative
	s.backend.FallbackReason = reason
	running := s.proc != nil
	s.mu.Unlock()
	if running {
		return
	}
	proc, err := startProcessHalf(ctx)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		if proc != nil {
			_ = proc.Close()
		}
		return
	}
	s.proc, s.procErr = proc, err
	s.mu.Unlock()
	if proc != nil {
		s.wg.Add(1)
		go func() { defer s.wg.Done(); s.forwardNative(proc, SourceCNProc) }()
	}
	s.changed()
}

// startFiles starts fanotify (at start, and again after any loss signal).
func (s *tetragonSource) startFiles(ctx context.Context) {
	files, err := startFileHalf(ctx, s.homes)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		if files != nil {
			_ = files.Close()
		}
		return
	}
	s.files, s.filesErr, s.handed = files, err, false
	s.mu.Unlock()
	if files != nil {
		s.wg.Add(1)
		go func() { defer s.wg.Done(); s.forwardNative(files, SourceFanotify) }()
	}
	s.changed()
}

// readFeed forwards one Tetragon session until it ends.
func (s *tetragonSource) readFeed(ctx context.Context, feed KernelFeed) {
	for {
		batch, err := feed.Recv()
		if err != nil {
			s.feedEnded(ctx, feed, err)
			return
		}
		s.handleBatch(batch)
	}
}

func (s *tetragonSource) handleBatch(batch KernelBatch) {
	now := s.now()
	if batch.ThrottleStart || batch.ThrottleStop || batch.Dropped > 0 {
		s.mu.Lock()
		if batch.ThrottleStart {
			s.throttled = true
		}
		if batch.ThrottleStop {
			s.throttled = false
		}
		if batch.ThrottleStart || batch.Dropped > 0 {
			s.lossAt, s.fileSince = now, time.Time{}
		}
		s.dropped += batch.Dropped
		s.mu.Unlock()
	}
	for _, event := range batch.Events {
		if event.Kind == KindExec && s.duplicateOfNative(event.PID, now) {
			continue
		}
		if event.Kind == KindFileRead || event.Kind == KindFileWrite {
			s.noteTetragonFile(event, now)
		}
		s.buffer.Push(event)
	}
}

// duplicateOfNative reports whether an exec Tetragon reports just after it
// took over is one cn_proc already delivered.
func (s *tetragonSource) duplicateOfNative(pid int, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.recentNative) == 0 || now.Sub(s.switchedAt) > switchBackWindow {
		return false
	}
	at, ok := s.recentNative[pid]
	return ok && now.Sub(at) <= switchBackWindow
}

func (s *tetragonSource) noteTetragonFile(event Event, now time.Time) {
	if own := s.options.OwnObservePolicy; own != nil && own(event.Policy) {
		s.mu.Lock()
		if s.fileSince.IsZero() {
			s.fileSince = now
		}
		s.mu.Unlock()
	}
	s.dedupeMu.Lock()
	s.tetragonFiles[fileKey{event.PID, event.Path}] = now
	s.dedupeMu.Unlock()
}

// feedEnded falls back to the native process half and starts redialling.
func (s *tetragonSource) feedEnded(ctx context.Context, feed KernelFeed, err error) {
	_ = feed.Close()
	s.mu.Lock()
	if s.closed || s.feed != feed {
		s.mu.Unlock()
		return
	}
	s.feed = nil
	s.lossAt, s.fileSince, s.observeSince, s.throttled = s.now(), time.Time{}, time.Time{}, false
	handed := s.handed
	s.mu.Unlock()
	s.startFallback(ctx, reasonOf(fmt.Errorf("tetragon_unavailable: the event stream ended: %w", err)))
	if handed {
		s.startFiles(ctx)
	}
}

// forwardNative forwards one native half, enriched the way the Tetragon
// events are: source, executable, and a redacted command line.
func (s *tetragonSource) forwardNative(half nativeHalf, source EventSource) {
	for event := range half.Events() {
		event.Source = source
		if event.Exe == "" && event.PID > 0 {
			event.Exe = procExe(event.PID)
		}
		if event.Cmdline != "" {
			event.Cmdline = redaction.CommandLine(strings.Fields(event.Cmdline), maxCmdlineBytes)
		}
		now := s.now()
		if source == SourceCNProc && event.Kind == KindExec {
			s.mu.Lock()
			s.recentNative[event.PID] = now
			if len(s.recentNative) > 4096 {
				for pid, at := range s.recentNative {
					if now.Sub(at) > switchBackWindow {
						delete(s.recentNative, pid)
					}
				}
			}
			s.mu.Unlock()
		}
		if source == SourceFanotify && s.holdingFiles() {
			s.hold(event, now)
			continue
		}
		s.buffer.Push(event)
	}
}

// procExe is the resolved executable of a live process, or "".
func procExe(pid int) string {
	link, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(link, " (deleted)")
}

// holdingFiles reports whether fanotify events may have a Tetragon twin:
// only while DefenseClaw's observe policy is enabled.
func (s *tetragonSource) holdingFiles() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.feed != nil && !s.observeSince.IsZero()
}

func (s *tetragonSource) hold(event Event, now time.Time) {
	s.dedupeMu.Lock()
	var release []Event
	if len(s.held) >= maxHeld {
		release = append(release, s.held[0].event)
		s.held = s.held[1:]
	}
	s.held = append(s.held, heldEvent{event: event, until: now.Add(duplicateWindow)})
	s.dedupeMu.Unlock()
	for _, e := range release {
		s.buffer.Push(e)
	}
}

// flushHeld releases held fanotify events whose wait is over, dropping the
// ones Tetragon reported too.
func (s *tetragonSource) flushHeld(now time.Time, all bool) {
	s.dedupeMu.Lock()
	var release []Event
	keep := s.held[:0]
	for _, h := range s.held {
		if !all && now.Before(h.until) {
			keep = append(keep, h)
			continue
		}
		at, twin := s.tetragonFiles[fileKey{h.event.PID, h.event.Path}]
		if twin && absDuration(at.Sub(h.event.At)) <= duplicateWindow+superviseTick {
			continue
		}
		release = append(release, h.event)
	}
	s.held = keep
	for key, at := range s.tetragonFiles {
		if now.Sub(at) > 2*duplicateWindow+superviseTick {
			delete(s.tetragonFiles, key)
		}
	}
	s.dedupeMu.Unlock()
	for _, e := range release {
		s.buffer.Push(e)
	}
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// supervise redials Tetragon, runs the fanotify hand-off and releases held
// events.
func (s *tetragonSource) supervise(ctx context.Context) {
	ticker := time.NewTicker(superviseTick)
	defer ticker.Stop()
	retry := redialInitial
	nextDial := s.now().Add(retry)
	nextHandoff := s.now().Add(handoffInterval)
	for {
		select {
		case <-ctx.Done():
			s.flushHeld(s.now(), true)
			return
		case <-ticker.C:
		}
		now := s.now()
		s.flushHeld(now, false)

		s.mu.Lock()
		down := s.feed == nil && !s.closed
		s.mu.Unlock()
		if down && !now.Before(nextDial) {
			if err := s.dial(ctx); err != nil {
				s.mu.Lock()
				changed := s.fallback != reasonOf(err)
				if changed {
					s.fallback, s.backend.FallbackReason = reasonOf(err), reasonOf(err)
				}
				s.mu.Unlock()
				if changed {
					s.changed()
				}
				retry = min(retry*2, redialMax)
			} else {
				retry = redialInitial
			}
			nextDial = s.now().Add(retry)
		}
		if !now.Before(nextHandoff) {
			s.evaluateHandoff(ctx, now)
			nextHandoff = now.Add(handoffInterval)
		}
	}
}

// evaluateHandoff refreshes the backend description and moves the file half
// between fanotify and the observe policy (section 7.9).
func (s *tetragonSource) evaluateHandoff(ctx context.Context, now time.Time) {
	s.mu.Lock()
	feed := s.feed
	s.mu.Unlock()
	if feed == nil {
		return
	}
	current := feed.Backend()

	s.mu.Lock()
	previous := s.backend
	s.backend.Version, s.backend.Socket, s.backend.LossKnown = current.Version, current.Socket, current.LossKnown
	s.backend.Policies = current.Policies
	if current.EventsLost > s.lastLost {
		// Known loss from Tetragon's own counters is a loss signal too.
		s.knownLost += current.EventsLost - s.lastLost
		s.lossAt, s.fileSince = now, time.Time{}
	}
	s.lastLost = current.EventsLost
	enabled := false
	if s.options.OwnObservePolicy != nil {
		for _, policy := range current.Policies {
			if s.options.OwnObservePolicy(policy.Name) && policy.State == "enabled" {
				enabled = true
				break
			}
		}
	}
	switch {
	case enabled && s.observeSince.IsZero():
		s.observeSince = now
	case !enabled:
		s.observeSince = time.Time{}
	}
	since := latest(s.fileSince, s.observeSince)
	healthy := enabled && !s.throttled && !s.fileSince.IsZero() && !s.lossAt.After(s.fileSince) &&
		now.Sub(since) >= handoffWindow
	handOff := healthy && s.files != nil && !s.handed
	takeBack := s.handed && !healthy && (!enabled || s.throttled || s.lossAt.After(since))
	files := s.files
	if handOff {
		s.files, s.handed = nil, true
	}
	policiesChanged := !samePolicies(previous.Policies, current.Policies)
	s.mu.Unlock()

	switch {
	case handOff:
		go func() { _ = files.Close() }()
		s.changed()
	case takeBack:
		s.startFiles(ctx)
	case policiesChanged:
		s.changed()
	}
}

func latest(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func samePolicies(a, b []BackendPolicy) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// changed tells the subscriber to read the coverage again. The send is
// made under the lock Close takes to close the channel.
func (s *tetragonSource) changed() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	select {
	case s.changes <- struct{}{}:
	default:
	}
}

// Coverage names both halves and the backend.
func (s *tetragonSource) Coverage() Coverage {
	s.mu.Lock()
	defer s.mu.Unlock()
	backend := s.backend
	backend.Policies = append([]BackendPolicy(nil), s.backend.Policies...)
	backend.EventsLost = s.dropped + s.knownLost
	coverage := Coverage{Backend: &backend}

	var process, files string
	switch {
	case s.feed != nil:
		process = "Tetragon " + firstNonEmpty(backend.Version, "(version unknown)") + " (gRPC)"
		coverage.Kinds = append(coverage.Kinds, KindExec, KindExit, KindPrivilege)
		if s.options.Mode == "observe" || s.options.Mode == "enforce" {
			coverage.Kinds = append(coverage.Kinds, KindConnect)
		}
	case s.proc != nil:
		process = "netlink process connector (cn_proc), Tetragon unavailable"
		coverage.Kinds = append(coverage.Kinds, KindExec, KindExit, KindPrivilege)
	default:
		coverage.MissingKinds = append(coverage.MissingKinds, KindExec, KindExit, KindPrivilege)
		coverage.Limitations = append(coverage.Limitations,
			"process events need Tetragon or the netlink connector: "+s.fallback+"; cn_proc: "+errText(s.procErr))
	}
	switch {
	case s.files != nil:
		files = "fanotify"
		coverage.Kinds = append(coverage.Kinds, KindFileRead, KindFileWrite)
	case s.handed && s.feed != nil:
		files = "file opens from the DefenseClaw observe policy"
		coverage.Kinds = append(coverage.Kinds, KindFileRead, KindFileWrite)
	default:
		coverage.MissingKinds = append(coverage.MissingKinds, KindFileRead, KindFileWrite)
		coverage.Limitations = append(coverage.Limitations,
			"file events need fanotify, which needs CAP_SYS_ADMIN: "+errText(s.filesErr))
	}
	coverage.Mechanism = strings.Join(nonEmpty(process, files), " + ")
	return coverage
}

func errText(err error) string {
	if err == nil {
		return "not started"
	}
	return err.Error()
}

func nonEmpty(values ...string) []string {
	out := values[:0]
	for _, v := range values {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// Close stops everything and closes the delivery channel.
func (s *tetragonSource) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	cancel, feed, proc, files := s.cancel, s.feed, s.proc, s.files
	s.feed, s.proc, s.files = nil, nil, nil
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if feed != nil {
		_ = feed.Close()
	}
	if proc != nil {
		_ = proc.Close()
	}
	if files != nil {
		_ = files.Close()
	}
	s.wg.Wait()
	s.flushHeld(s.now(), true)
	s.buffer.Close()
	s.mu.Lock()
	close(s.changes)
	s.mu.Unlock()
	return nil
}
