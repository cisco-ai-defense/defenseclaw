// Copyright 2026 Cisco Systems, Inc. and its affiliates
// Copyright (c) 2026 Mike Storm. All rights reserved.
//
// Derived from ShadowClaw -- Universal Shadow AI Detector, by Mike Storm,
// Distinguished Engineer, CCIE Security 13847. Reimplemented in Go and
// absorbed into the DefenseClaw gateway; see NOTICE for the modifications.
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

//go:build windows

package plane

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modWevtapi            = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtQuery          = modWevtapi.NewProc("EvtQuery")
	procEvtSubscribe      = modWevtapi.NewProc("EvtSubscribe")
	procEvtCreateBookmark = modWevtapi.NewProc("EvtCreateBookmark")
	procEvtNext           = modWevtapi.NewProc("EvtNext")
	procEvtRender         = modWevtapi.NewProc("EvtRender")
	procEvtClose          = modWevtapi.NewProc("EvtClose")
)

// EvtQuery and EvtSubscribe flags and render types.
const (
	evtQueryChannelPath             = 0x1
	evtQueryReverseDirection        = 0x200
	evtSubscribeStartAtOldestRecord = 2
	evtSubscribeStartAfterBookmark  = 3
	evtRenderEventXML               = 1
	// pollInterval is how often the channel is drained. The Security log is
	// a pull API with no usable blocking read from Go, so this trades latency
	// for not spinning a core. A kill chain is measured in minutes.
	pollInterval = 2 * time.Second
	// nextTimeoutMS bounds one EvtNext. A timeout is not the end of the
	// data; the reader retries until its poll budget runs out.
	nextTimeoutMS = 250
	// probeWindowMS is how far back the coverage probe looks for evidence
	// that process auditing is on at all. Wider than a poll because a quiet
	// host may not have created a process in the last few seconds.
	probeWindowMS = 24 * 60 * 60 * 1000
)

// windowsSource is Plane C on Windows, over the Security event log.
//
// The Security channel is the documented route to process creation with a
// command line, account creation, and privilege assignment, and it is a pure
// wevtapi consumer rather than an ETW session with a callback from a
// kernel-owned thread.
//
// It has one hard prerequisite the caller cannot supply by elevating:
// Advanced Audit Policy must enable the relevant subcategories, and process
// command lines additionally need the "Include command line in process
// creation events" policy. Those are two different missing things and are
// reported as two different reasons.
type windowsSource struct {
	buffer   *Buffer
	coverage Coverage
	reader   *securityReader
	mu       sync.Mutex
	closed   bool
	stop     chan struct{}
	wg       sync.WaitGroup
}

// NewSource returns the Windows Plane C source. homeDirs is accepted for
// parity with the other backends; the Security log is machine-wide and needs
// no path marking.
func NewSource(_ []string) Source {
	return &windowsSource{buffer: NewBuffer(), stop: make(chan struct{})}
}

func (s *windowsSource) Events() <-chan Event { return s.buffer.Events() }

// Coverage is the coverage found at Start plus whatever the reader reports
// right now: a reader that fell behind or had to reopen a stream is reduced
// coverage while it lasts, and says so (GAP-1473).
func (s *windowsSource) Coverage() Coverage {
	coverage := s.coverage
	if s.reader == nil {
		return coverage
	}
	if live := s.reader.limitations(); len(live) > 0 {
		coverage.Limitations = append(append([]string(nil), coverage.Limitations...), live...)
	}
	return coverage
}

func (s *windowsSource) Start(ctx context.Context) error {
	// Everything already on disk is history: both streams start after the
	// newest record, so a chain that completed last week is not reported as
	// though it were happening now. Opening them also proves the channel is
	// readable before the plane claims to be up; an unelevated token fails
	// here rather than silently delivering nothing.
	newest, err := newestSecurityRecordID()
	if err == nil {
		reader := newSecurityReader(subscribeSecurity, s.buffer, newest)
		if err = reader.openAll(); err == nil {
			s.reader = reader
		}
	}
	if err != nil {
		return fmt.Errorf("plane: Security event log unreadable: %w "+
			"(the gateway needs an elevated token to read the Security channel)", err)
	}

	hasProcessEvents, hasCommandLines := probeAuditCoverage()
	coverage := Coverage{
		Mechanism: "Windows Security event log (wevtapi)",
		Kinds:     []Kind{KindExec, KindExit, KindIdentity, KindPrivilege},
	}
	if !hasProcessEvents {
		coverage.MissingKinds = append(coverage.MissingKinds, KindExec, KindExit)
		coverage.Limitations = append(coverage.Limitations,
			"no process-creation events are present; enable Advanced Audit Policy > "+
				"Detailed Tracking > Audit Process Creation")
	}
	if hasProcessEvents && !hasCommandLines {
		coverage.Limitations = append(coverage.Limitations,
			"process events carry no command line; enable Administrative Templates > System > "+
				"Audit Process Creation > Include command line in process creation events. "+
				"Lineage still works; argument-vector tactics do not")
	}
	// File-object access needs a SACL on each watched file, which is almost
	// never configured. Say so rather than implying the coverage exists.
	//
	// Both file kinds, not just writes. Event 4663 becomes a read or a write
	// depending on the access mask, but the same per-object SACL gates both
	// and Start does not probe for it -- so claiming reads are covered while
	// writes are missing describes a state this source cannot verify it is
	// in. Coverage has to say what it can currently deliver, and without a
	// SACL that is neither.
	coverage.MissingKinds = append(coverage.MissingKinds, KindFileRead, KindFileWrite)
	coverage.Limitations = append(coverage.Limitations,
		"file events require a SACL on each audited object; without one, neither credential "+
			"reads nor persistence writes are observable through the Security channel")
	s.coverage = coverage

	s.wg.Add(1)
	go func() { defer s.wg.Done(); s.drain(ctx) }()
	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()
	return nil
}

func (s *windowsSource) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close(s.stop)
	s.mu.Unlock()
	s.wg.Wait()
	if s.reader != nil {
		s.reader.close()
	}
	s.buffer.Close()
	return nil
}

func (s *windowsSource) drain(ctx context.Context) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stop:
			return
		case <-ticker.C:
		}
		s.reader.pollOnce()
	}
}

// wevtStream is a pull subscription to the Security channel.
//
// A subscription, not a query: an EvtQuery result is a snapshot, so a query
// per poll has to be bounded by time, and the log service evaluates a time
// bound by walking the channel from its oldest record (GAP-1473). A
// subscription keeps its own position and filters records as they are
// written, so a read costs the records it returns and nothing else.
type wevtStream struct {
	handle windows.Handle
	// signal is required by a pull subscription. The reader polls on its
	// own ticker and never waits on it.
	signal windows.Handle
}

// subscribeSecurity opens filter on the Security channel after record id
// after, through a bookmark built from that id.
func subscribeSecurity(filter string, after uint64) (securityStream, error) {
	channel, err := windows.UTF16PtrFromString("Security")
	if err != nil {
		return nil, err
	}
	query, err := windows.UTF16PtrFromString(filter)
	if err != nil {
		return nil, err
	}
	flags := uintptr(evtSubscribeStartAtOldestRecord)
	var bookmark uintptr
	if after > 0 {
		text, err := windows.UTF16PtrFromString(fmt.Sprintf(
			`<BookmarkList><Bookmark Channel="Security" RecordId="%d" IsCurrent="true"/></BookmarkList>`, after))
		if err != nil {
			return nil, err
		}
		handle, _, callErr := procEvtCreateBookmark.Call(uintptr(unsafe.Pointer(text)))
		if handle == 0 {
			return nil, fmt.Errorf("EvtCreateBookmark: %w", callErr)
		}
		defer procEvtClose.Call(handle)
		bookmark, flags = handle, evtSubscribeStartAfterBookmark
	}
	signal, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, err
	}
	handle, _, callErr := procEvtSubscribe.Call(
		0, uintptr(signal),
		uintptr(unsafe.Pointer(channel)), uintptr(unsafe.Pointer(query)),
		bookmark, 0, 0, flags,
	)
	if handle == 0 {
		_ = windows.CloseHandle(signal)
		return nil, fmt.Errorf("EvtSubscribe: %w", callErr)
	}
	return &wevtStream{handle: windows.Handle(handle), signal: signal}, nil
}

// Next reads the subscription. Once a pull subscription has reported that it
// caught up, EvtNext answers ERROR_INVALID_OPERATION until a new matching
// record is written, and then delivers it on the same handle (measured on
// Windows Server 2025). That answer means "nothing new", not a broken stream.
func (w *wevtStream) Next(max int) ([]string, error) {
	events, err := nextEvents(w.handle, max, nextTimeoutMS)
	if errors.Is(err, windows.ERROR_INVALID_OPERATION) {
		return nil, errStreamDrained
	}
	return events, err
}

func (w *wevtStream) Close() {
	procEvtClose.Call(uintptr(w.handle))
	_ = windows.CloseHandle(w.signal)
}

// newestSecurityRecordID is the id of the last record in the Security
// channel, or zero for an empty one. Reverse direction makes it one read.
func newestSecurityRecordID() (uint64, error) {
	handle, err := openSecurityQuery("*", evtQueryReverseDirection)
	if err != nil {
		return 0, err
	}
	defer procEvtClose.Call(uintptr(handle))
	events, err := nextEvents(handle, 1, 1000)
	if errors.Is(err, errStreamDrained) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	for _, raw := range events {
		if record, err := decodeSecurityXML(raw); err == nil {
			return record.RecordID, nil
		}
	}
	return 0, errors.New("the newest Security record could not be read")
}

func openSecurityQuery(query string, direction uintptr) (windows.Handle, error) {
	channel, err := windows.UTF16PtrFromString("Security")
	if err != nil {
		return 0, err
	}
	text, err := windows.UTF16PtrFromString(query)
	if err != nil {
		return 0, err
	}
	handle, _, callErr := procEvtQuery.Call(
		0,
		uintptr(unsafe.Pointer(channel)),
		uintptr(unsafe.Pointer(text)),
		evtQueryChannelPath|direction,
	)
	if handle == 0 {
		return 0, callErr
	}
	return windows.Handle(handle), nil
}

// probeAuditCoverage reports whether process-creation events exist at all, and
// whether they carry a command line.
//
// It reads the existing log rather than waiting for a live event, because a
// host with audit policy off would otherwise report "coverage unknown"
// forever, which is the answer least useful to an operator. Newest first: the
// newest records reflect the audit policy in force now, and a forward read
// would walk the whole channel from its oldest record first.
func probeAuditCoverage() (hasProcessEvents, hasCommandLines bool) {
	handle, err := openSecurityQuery(fmt.Sprintf(
		"*[System[EventID=%d and TimeCreated[timediff(@SystemTime) <= %d]]]",
		eventProcessCreated, probeWindowMS), evtQueryReverseDirection)
	if err != nil {
		return false, false
	}
	defer procEvtClose.Call(uintptr(handle))

	events, _ := nextEvents(handle, 16, 1000)
	for _, raw := range events {
		record, err := decodeSecurityXML(raw)
		if err != nil || record.EventID != eventProcessCreated {
			continue
		}
		hasProcessEvents = true
		if strings.TrimSpace(record.data("CommandLine")) != "" {
			return true, true
		}
	}
	return hasProcessEvents, false
}

// nextEvents pulls up to count rendered event XML documents. It maps the two
// EvtNext failures that are not breakage -- caught up and timed out -- to the
// reader errors that say so; anything else is returned as is.
func nextEvents(handle windows.Handle, count int, timeoutMS int) ([]string, error) {
	handles := make([]windows.Handle, count)
	var returned uint32
	ret, _, callErr := procEvtNext.Call(
		uintptr(handle), uintptr(count),
		uintptr(unsafe.Pointer(&handles[0])),
		uintptr(timeoutMS), 0,
		uintptr(unsafe.Pointer(&returned)),
	)
	if ret == 0 {
		switch {
		case errors.Is(callErr, windows.ERROR_NO_MORE_ITEMS):
			return nil, errStreamDrained
		case errors.Is(callErr, windows.ERROR_TIMEOUT):
			return nil, errStreamTimeout
		}
		return nil, fmt.Errorf("EvtNext: %w", callErr)
	}
	rendered := make([]string, 0, returned)
	for index := 0; index < int(returned); index++ {
		if text, err := renderEvent(handles[index]); err == nil {
			rendered = append(rendered, text)
		}
		procEvtClose.Call(uintptr(handles[index]))
	}
	return rendered, nil
}

func renderEvent(event windows.Handle) (string, error) {
	var used, properties uint32
	// First call sizes the buffer.
	procEvtRender.Call(0, uintptr(event), evtRenderEventXML, 0, 0,
		uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&properties)))
	if used == 0 {
		return "", fmt.Errorf("plane: EvtRender reported a zero-length event")
	}
	buffer := make([]uint16, (used/2)+1)
	ret, _, callErr := procEvtRender.Call(
		0, uintptr(event), evtRenderEventXML, uintptr(used),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&properties)),
	)
	if ret == 0 {
		return "", callErr
	}
	return windows.UTF16ToString(buffer), nil
}
