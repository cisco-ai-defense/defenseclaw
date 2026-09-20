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
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Security-log event ids this source consumes. Each maps to exactly one tactic
// class the classifier can act on.
const (
	eventProcessCreated = 4688 // A new process has been created
	eventProcessExited  = 4689 // A process has exited
	eventObjectAccessed = 4663 // An attempt was made to access an object
	eventAccountCreated = 4720 // A user account was created
	eventMemberAdded    = 4732 // A member was added to a security-enabled local group
	eventSpecialPrivs   = 4672 // Special privileges assigned to new logon
	eventPrivilegedUse  = 4673 // A privileged service was called
)

// eventIDPredicate selects only the ids above. Filtering in the query rather
// than after the fact matters: the Security channel on a domain-joined host is
// thousands of events a second, almost none of them these.
var eventIDPredicate = fmt.Sprintf(
	"EventID=%d or EventID=%d or EventID=%d or EventID=%d or EventID=%d or EventID=%d or EventID=%d",
	eventProcessCreated, eventProcessExited, eventObjectAccessed,
	eventAccountCreated, eventMemberAdded, eventSpecialPrivs, eventPrivilegedUse,
)

// securityQuery builds the XPath for matching events written in the last
// windowMS milliseconds.
//
// Two things force this shape. An EvtQuery handle is a snapshot of the result
// set at the moment it was created -- EvtNext on it never yields an event
// written afterwards -- so each poll must open a fresh query. And the query
// must be bounded by time rather than by "everything, then filter", because
// the Security channel on a real host holds hundreds of thousands of records
// and rendering all of them once per poll would make the sensor the most
// expensive process on the machine.
//
// timediff is the documented Event Log XPath function for exactly this.
func securityQuery(windowMS int64) string {
	return fmt.Sprintf("*[System[(%s) and TimeCreated[timediff(@SystemTime) <= %d]]]",
		eventIDPredicate, windowMS)
}

var (
	modWevtapi    = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtQuery  = modWevtapi.NewProc("EvtQuery")
	procEvtNext   = modWevtapi.NewProc("EvtNext")
	procEvtRender = modWevtapi.NewProc("EvtRender")
	procEvtClose  = modWevtapi.NewProc("EvtClose")
)

// EvtQuery flags and render types.
const (
	evtQueryChannelPath = 0x1
	evtQueryForwardDir  = 0x100
	evtRenderEventXML   = 1
)

// pollInterval is how often the channel is drained. The Security log is a
// pull API with no usable blocking read from Go, so this trades latency for
// not spinning a core. A kill chain is measured in minutes, not milliseconds.
const (
	pollInterval = 2 * time.Second
	// pollWindow deliberately exceeds pollInterval so an event written between
	// two polls falls inside the next one.
	pollWindow = 30 * time.Second
	// probeWindow is how far back the coverage probe looks for evidence that
	// process auditing is on at all. Wider than a poll because a quiet host
	// may not have created a process in the last few seconds, and reporting
	// "coverage unknown" because of that is the answer least useful to an
	// operator.
	probeWindow = 24 * time.Hour
	// maxSeenRecords bounds the dedup set.
	maxSeenRecords = 16384
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
	mu       sync.Mutex
	closed   bool
	stop     chan struct{}
	wg       sync.WaitGroup
	// seen holds the record ids already delivered, so the overlapping poll
	// window does not deliver an event twice.
	seen map[uint64]struct{}
}

// NewSource returns the Windows Plane C source. homeDirs is accepted for
// parity with the other backends; the Security log is machine-wide and needs
// no path marking.
func NewSource(_ []string) Source {
	return &windowsSource{buffer: NewBuffer(), stop: make(chan struct{})}
}

func (s *windowsSource) Events() <-chan Event { return s.buffer.Events() }
func (s *windowsSource) Coverage() Coverage   { return s.coverage }

func (s *windowsSource) Start(ctx context.Context) error {
	// Prove the channel is readable before claiming the plane is up. An
	// unelevated token fails here rather than silently delivering nothing.
	handle, err := openSecurityQuery(int64(pollWindow / time.Millisecond))
	if err != nil {
		return fmt.Errorf("plane: Security event log unreadable: %w "+
			"(the gateway needs an elevated token to read the Security channel)", err)
	}
	procEvtClose.Call(uintptr(handle))

	// Everything already on disk is history. Marking it seen means the first
	// poll delivers only what happens from now on, so a chain that completed
	// last week is not reported as though it were happening now.
	s.markExistingSeen()

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

// markExistingSeen records the record ids already in the poll window, so the
// first real poll does not replay them as if they had just happened.
func (s *windowsSource) markExistingSeen() {
	handle, err := openSecurityQuery(int64(pollWindow / time.Millisecond))
	if err != nil {
		return
	}
	defer procEvtClose.Call(uintptr(handle))
	for {
		events, ok := nextEvents(handle, 64, 200)
		if !ok || len(events) == 0 {
			return
		}
		for _, raw := range events {
			if record, err := decodeSecurityXML(raw); err == nil {
				s.markSeen(record.RecordID)
			}
		}
	}
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
	s.buffer.Close()
	return nil
}

func openSecurityQuery(windowMS int64) (windows.Handle, error) {
	channel, err := windows.UTF16PtrFromString("Security")
	if err != nil {
		return 0, err
	}
	query, err := windows.UTF16PtrFromString(securityQuery(windowMS))
	if err != nil {
		return 0, err
	}
	handle, _, callErr := procEvtQuery.Call(
		0,
		uintptr(unsafe.Pointer(channel)),
		uintptr(unsafe.Pointer(query)),
		uintptr(evtQueryChannelPath|evtQueryForwardDir),
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
// forever, which is the answer least useful to an operator.
func probeAuditCoverage() (hasProcessEvents, hasCommandLines bool) {
	// A wider window than a poll: a quiet host may not have created a process
	// in the last few seconds, and reporting "coverage unknown" because of
	// that would be the answer least useful to an operator.
	handle, err := openSecurityQuery(int64(probeWindow / time.Millisecond))
	if err != nil {
		return false, false
	}
	defer procEvtClose.Call(uintptr(handle))

	// Bounded: a large Security channel must not turn startup into a full-log
	// scan. A host that audits process creation at all will show one well
	// inside this many records.
	const maxProbeRecords = 512
	scanned := 0
	for scanned < maxProbeRecords {
		events, ok := nextEvents(handle, 64, 200)
		if !ok || len(events) == 0 {
			break
		}
		for _, raw := range events {
			scanned++
			record, err := decodeSecurityXML(raw)
			if err != nil || record.EventID != eventProcessCreated {
				continue
			}
			hasProcessEvents = true
			if strings.TrimSpace(record.data("CommandLine")) != "" {
				return true, true
			}
		}
	}
	return hasProcessEvents, hasCommandLines
}

// nextEvents pulls up to count rendered event XML documents.
func nextEvents(handle windows.Handle, count int, timeoutMS int) ([]string, bool) {
	handles := make([]windows.Handle, count)
	var returned uint32
	ret, _, _ := procEvtNext.Call(
		uintptr(handle), uintptr(count),
		uintptr(unsafe.Pointer(&handles[0])),
		uintptr(timeoutMS), 0,
		uintptr(unsafe.Pointer(&returned)),
	)
	if ret == 0 {
		return nil, false
	}
	rendered := make([]string, 0, returned)
	for index := 0; index < int(returned); index++ {
		if text, err := renderEvent(handles[index]); err == nil {
			rendered = append(rendered, text)
		}
		procEvtClose.Call(uintptr(handles[index]))
	}
	return rendered, true
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
		s.pollOnce()
	}
}

// pollOnce reads the current window and delivers what has not been seen.
//
// The window deliberately overlaps the poll interval so an event written
// between two polls is never missed; the seen set is what stops the overlap
// from delivering it twice.
func (s *windowsSource) pollOnce() {
	handle, err := openSecurityQuery(int64(pollWindow / time.Millisecond))
	if err != nil {
		return
	}
	defer procEvtClose.Call(uintptr(handle))

	for {
		events, ok := nextEvents(handle, 32, 100)
		if !ok || len(events) == 0 {
			return
		}
		for _, raw := range events {
			record, err := decodeSecurityXML(raw)
			if err != nil || !s.markSeen(record.RecordID) {
				continue
			}
			if event, ok := translateSecurityRecord(record); ok {
				s.buffer.Push(event)
			}
		}
	}
}

// markSeen records a record id and reports whether it is new.
//
// Bounded: the set is cleared wholesale once it outgrows the window it could
// possibly need, which is cheaper than an LRU and cannot leak. A cleared set
// can at worst re-deliver one window's events, and the session dedup upstream
// absorbs that.
func (s *windowsSource) markSeen(recordID uint64) bool {
	if recordID == 0 {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seen == nil {
		s.seen = make(map[uint64]struct{}, 1024)
	}
	if _, ok := s.seen[recordID]; ok {
		return false
	}
	if len(s.seen) >= maxSeenRecords {
		s.seen = make(map[uint64]struct{}, 1024)
	}
	s.seen[recordID] = struct{}{}
	return true
}

// securityRecord is the subset of the Security-channel XML this source reads.
type securityRecord struct {
	EventID  int    `xml:"System>EventID"`
	RecordID uint64 `xml:"System>EventRecordID"`
	Data     []struct {
		Name  string `xml:"Name,attr"`
		Value string `xml:",chardata"`
	} `xml:"EventData>Data"`
	Created struct {
		SystemTime string `xml:"SystemTime,attr"`
	} `xml:"System>TimeCreated"`
}

func (r securityRecord) data(name string) string {
	for _, entry := range r.Data {
		if strings.EqualFold(entry.Name, name) {
			return entry.Value
		}
	}
	return ""
}

func decodeSecurityXML(raw string) (securityRecord, error) {
	var record securityRecord
	if err := xml.Unmarshal([]byte(raw), &record); err != nil {
		return securityRecord{}, err
	}
	return record, nil
}

func translateSecurityRecord(record securityRecord) (Event, bool) {
	at := parseSystemTime(record.Created.SystemTime)

	switch record.EventID {
	case eventProcessCreated:
		pid := parseHexOrDecimal(record.data("NewProcessId"))
		if pid <= 0 {
			return Event{}, false
		}
		return Event{
			Kind: KindExec, PID: pid,
			PPID:           parseHexOrDecimal(record.data("ProcessId")),
			ResponsiblePID: parseHexOrDecimal(record.data("ProcessId")),
			Name:           baseName(record.data("NewProcessName")),
			Cmdline:        record.data("CommandLine"),
			User:           record.data("SubjectUserName"),
			At:             at,
		}, true

	case eventProcessExited:
		pid := parseHexOrDecimal(record.data("ProcessId"))
		if pid <= 0 {
			return Event{}, false
		}
		return Event{Kind: KindExit, PID: pid, Name: baseName(record.data("ProcessName")), At: at}, true

	case eventObjectAccessed:
		path := record.data("ObjectName")
		if path == "" {
			return Event{}, false
		}
		kind := KindFileRead
		if strings.Contains(strings.ToLower(record.data("AccessList")), "writedata") {
			kind = KindFileWrite
		}
		return Event{
			Kind: kind, PID: parseHexOrDecimal(record.data("ProcessId")),
			Name: baseName(record.data("ProcessName")), Path: path,
			User: record.data("SubjectUserName"), At: at,
		}, true

	case eventAccountCreated:
		return Event{
			Kind: KindIdentity, PID: parseHexOrDecimal(record.data("ProcessId")),
			Detail: "local account created: " + record.data("TargetUserName"),
			User:   record.data("SubjectUserName"), At: at,
		}, true

	case eventMemberAdded:
		return Event{
			Kind: KindIdentity, PID: parseHexOrDecimal(record.data("ProcessId")),
			Detail: "added to group " + record.data("TargetUserName"),
			User:   record.data("SubjectUserName"), At: at,
		}, true

	case eventSpecialPrivs, eventPrivilegedUse:
		privileges := record.data("PrivilegeList")
		if strings.TrimSpace(privileges) == "" {
			return Event{}, false
		}
		return Event{
			Kind: KindPrivilege, PID: parseHexOrDecimal(record.data("ProcessId")),
			Name:   baseName(record.data("ProcessName")),
			Detail: "privileges assigned: " + strings.Join(strings.Fields(privileges), ","),
			User:   record.data("SubjectUserName"), At: at,
		}, true
	}
	return Event{}, false
}

// parseHexOrDecimal decodes a Security-log pid, which is written as 0x1a4 in
// most records and as a bare decimal in a few.
func parseHexOrDecimal(value string) int {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
		parsed, err := strconv.ParseInt(value[2:], 16, 64)
		if err != nil {
			return 0
		}
		return int(parsed)
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}
	return parsed
}

func parseSystemTime(value string) time.Time {
	if value == "" {
		return time.Now()
	}
	if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return parsed
	}
	return time.Now()
}

func baseName(path string) string {
	if index := strings.LastIndexAny(path, `\/`); index >= 0 {
		return path[index+1:]
	}
	return path
}
