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

package plane

// The Windows Security-log reader, kept free of wevtapi so the poll logic and
// the record decoding run, and are tested, on every OS. windows.go supplies
// the real streams.

import (
	"encoding/xml"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/tactics"
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

// The ids are read through two streams (GAP-1473). Process creation, exit and
// privilege records arrive in floods: a scheduled task looping a short
// command writes hundreds a second. File and account records are the rare,
// decisive ones -- the persistence write the host plane exists to catch. In
// one stream, ordered by record id, a flood of the first kind would make the
// second wait behind it; in two, the rare stream is drained in full on every
// poll and only the flood is capped.
var (
	signalFilter  = idFilter(eventObjectAccessed, eventAccountCreated, eventMemberAdded)
	lineageFilter = idFilter(eventProcessCreated, eventProcessExited, eventSpecialPrivs, eventPrivilegedUse)
)

func idFilter(ids ...int) string {
	terms := make([]string, len(ids))
	for index, id := range ids {
		terms[index] = fmt.Sprintf("EventID=%d", id)
	}
	return "*[System[(" + strings.Join(terms, " or ") + ")]]"
}

const (
	// pollBudget bounds one poll, so a flood can never make polls overlap.
	pollBudget = 1500 * time.Millisecond
	// lineageCap bounds the process records rendered per poll -- a sustained
	// 1,000 process starts a second. Records past it are not skipped: the
	// cursor stops at the last one read and the next poll continues there.
	lineageCap = 2000
	// readBatch is how many records one read asks for.
	readBatch = 64
	// signalHoldPolls bounds how many polls a file or account record waits
	// for the process records ahead of it (about 30 s at the 2 s poll
	// interval), and maxHeldSignals how many wait at once (GAP-1487).
	signalHoldPolls = 15
	maxHeldSignals  = eventBuffer
)

// securityStream is one cursor over a filtered view of the Security channel,
// positioned after a record id. It never rescans: each read continues where
// the previous one stopped.
type securityStream interface {
	// Next returns up to max rendered records. It returns errStreamDrained
	// once it has caught up with the log, errStreamTimeout when the log did
	// not answer in time (the stream is still usable), and any other error
	// when the stream is broken and has to be reopened.
	Next(max int) ([]string, error)
	Close()
}

var (
	errStreamDrained = errors.New("plane: Security log stream caught up")
	errStreamTimeout = errors.New("plane: Security log read timed out")
)

// openSecurityStream opens filter positioned after record id after; zero
// means the start of the log.
type openSecurityStream func(filter string, after uint64) (securityStream, error)

// securityCursor is one stream and the last record id read from it.
type securityCursor struct {
	filter string
	capped bool
	after  uint64
	stream securityStream
}

// securityReader polls the two Security-log streams into a Buffer and keeps
// the health a degraded snapshot reports.
//
// The cursor is what fixes GAP-1473. The earlier reader opened a new query
// for "the last 30 seconds" on every poll; the log service evaluates that by
// walking the channel from its oldest record, and once a process flood had
// put about 150,000 records in front of the window every read timed out, the
// timeout was taken for "no more events" and the plane went silent for as
// long as those records stayed in the log.
type securityReader struct {
	open    openSecurityStream
	buffer  *Buffer
	now     func() time.Time
	cursors [2]*securityCursor
	// held is the signal records waiting for the process stream to reach
	// them (GAP-1487). Only the polling goroutine touches it.
	held []heldSignal

	mu sync.Mutex
	// behind is set while the last poll stopped before reaching the end of a
	// stream (the cap or the budget ran out), and readErr while the last poll
	// had to reopen one. Both clear on the next poll that reaches the end of
	// both streams without dropping anything.
	behind      bool
	readErr     string
	timeouts    int64
	failures    int64
	heldBack    int64
	dropped     int64
	lastDropped int64
	// released counts signal records delivered before the process records
	// ahead of them were read, because they had waited signalHoldPolls polls
	// or too many were waiting.
	released int64
}

// heldSignal is a signal record and the polls it has waited.
type heldSignal struct {
	record securityRecord
	polls  int
}

func newSecurityReader(open openSecurityStream, buffer *Buffer, after uint64) *securityReader {
	return &securityReader{
		open: open, buffer: buffer, now: time.Now,
		cursors: [2]*securityCursor{
			{filter: signalFilter, after: after},
			{filter: lineageFilter, capped: true, after: after},
		},
	}
}

// openAll opens both streams; Start uses it to prove the channel readable.
func (r *securityReader) openAll() error {
	for _, cursor := range r.cursors {
		stream, err := r.open(cursor.filter, cursor.after)
		if err != nil {
			r.close()
			return err
		}
		cursor.stream = stream
	}
	return nil
}

func (r *securityReader) close() {
	for _, cursor := range r.cursors {
		if cursor.stream != nil {
			cursor.stream.Close()
			cursor.stream = nil
		}
	}
}

// pollOnce reads what both streams have gained since the previous poll and
// delivers it in record order, so a process start still reaches the lineage
// tracker before the file write it made, also when the process stream
// stopped short of that start in this poll (holdSignals).
func (r *securityReader) pollOnce() {
	start := r.now()
	deadline := start.Add(pollBudget)
	var (
		records, signals []securityRecord
		behind, lineage  bool
		lineageAfter     uint64
		failure          string
	)
	var timeouts, failures int64
	for _, cursor := range r.cursors {
		got, stopped, timedOut, err := r.read(cursor, deadline)
		if cursor.capped {
			records = append(records, got...)
			lineage, lineageAfter = stopped || err != nil, cursor.after
		} else {
			signals = got
		}
		behind = behind || stopped
		timeouts += timedOut
		if err != nil {
			failures++
			failure = err.Error()
		}
	}
	ready, released := r.holdSignals(signals, lineage, lineageAfter)
	records = append(records, ready...)
	sort.Slice(records, func(i, j int) bool { return records[i].RecordID < records[j].RecordID })
	for _, record := range records {
		if event, ok := translateSecurityRecord(record); ok {
			r.buffer.Push(event)
		}
	}

	dropped := r.buffer.Dropped()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.timeouts += timeouts
	r.failures += failures
	r.released += released
	if behind {
		r.heldBack++
	}
	newDrops := dropped - r.lastDropped
	r.lastDropped = dropped
	r.dropped = dropped
	r.behind = behind || newDrops > 0
	r.readErr = failure
}

// holdSignals returns the signal records to deliver in this poll and keeps
// the others. The signal stream is drained in full while the process stream
// stops at lineageCap, so while that stream is behind (lineageBehind), a
// signal past its last record (lineageAfter) may have been made by a process whose creation
// is still unread, and the host plane attributes a signal only through that
// creation: delivered now, it would fail the lineage gate for good
// (GAP-1487). Such a signal waits until the process stream passes it or
// catches up, at most signalHoldPolls polls and maxHeldSignals records; then
// it goes on as before, and released counts it.
func (r *securityReader) holdSignals(
	fresh []securityRecord, lineageBehind bool, lineageAfter uint64,
) (ready []securityRecord, released int64) {
	pending := r.held
	r.held = nil
	for _, record := range fresh {
		pending = append(pending, heldSignal{record: record})
	}
	for _, signal := range pending {
		waiting := lineageBehind && signal.record.RecordID > lineageAfter
		if waiting && signal.polls < signalHoldPolls && len(r.held) < maxHeldSignals {
			signal.polls++
			r.held = append(r.held, signal)
			continue
		}
		if waiting {
			released++
		}
		ready = append(ready, signal.record)
	}
	return ready, released
}

// read drains one cursor until the stream catches up, the cap or the budget
// runs out (stopped), or the stream breaks (err; it is reopened at the
// cursor next poll). A timeout is neither: the log is slow, not empty, so
// the read goes on until the budget says otherwise.
func (r *securityReader) read(cursor *securityCursor, deadline time.Time) (
	records []securityRecord, stopped bool, timeouts int64, err error,
) {
	if cursor.stream == nil {
		stream, openErr := r.open(cursor.filter, cursor.after)
		if openErr != nil {
			return nil, false, 0, fmt.Errorf("reopen: %w", openErr)
		}
		cursor.stream = stream
	}
	rendered := 0
	for {
		want := readBatch
		if cursor.capped {
			if rendered >= lineageCap {
				return records, true, timeouts, nil
			}
			want = min(want, lineageCap-rendered)
		}
		// The first read always happens: a budget spent on the other stream
		// must not starve this one entirely.
		if rendered > 0 && !r.now().Before(deadline) {
			return records, true, timeouts, nil
		}
		raws, nextErr := cursor.stream.Next(want)
		rendered += len(raws)
		for _, raw := range raws {
			record, decodeErr := decodeSecurityXML(raw)
			if decodeErr != nil || record.RecordID <= cursor.after {
				continue
			}
			cursor.after = record.RecordID
			records = append(records, record)
		}
		switch {
		case nextErr == nil && len(raws) == 0, errors.Is(nextErr, errStreamDrained):
			return records, false, timeouts, nil
		case nextErr == nil:
		case errors.Is(nextErr, errStreamTimeout):
			timeouts++
			if !r.now().Before(deadline) {
				return records, true, timeouts, nil
			}
		default:
			cursor.stream.Close()
			cursor.stream = nil
			return records, false, timeouts, nextErr
		}
	}
}

// limitations is what Coverage adds while the reader is not keeping up, in
// the operator-facing form the snapshot lists as degraded_reasons.
func (r *securityReader) limitations() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	if r.behind {
		out = append(out, fmt.Sprintf(
			"Security event log reader is behind (a process-event flood or a full event queue): "+
				"%d polls stopped before the end of the log, %d read timeouts, %d events dropped, "+
				"%d file or account events delivered before the process events ahead of them; "+
				"it continues from the last record read and clears once it catches up",
			r.heldBack, r.timeouts, r.dropped, r.released))
	}
	if r.readErr != "" {
		out = append(out, fmt.Sprintf(
			"Security event log read failed (%s); %d failures so far, reopening at the last record read",
			r.readErr, r.failures))
	}
	return out
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

// nullSID is what a 4688 names as its target account when the new process
// runs under its creator's token.
const nullSID = "S-1-0-0"

// account is the DOMAIN\name and SID of the account a record names under
// prefix ("Subject" or "Target"), both empty when it names none.
func (r securityRecord) account(prefix string) (user, sid string) {
	sid = strings.TrimSpace(r.data(prefix + "UserSid"))
	if sid == "" || sid == "-" || strings.EqualFold(sid, nullSID) {
		return "", ""
	}
	user = strings.TrimSpace(r.data(prefix + "UserName"))
	if domain := strings.TrimSpace(r.data(prefix + "DomainName")); domain != "" && domain != "-" && user != "" {
		user = domain + `\` + user
	}
	return user, sid
}

// createdAccount is the account a 4688's new process runs as: the target
// account when the creator started it under another token, the creator's
// otherwise.
func createdAccount(record securityRecord) (user, sid string) {
	if user, sid = record.account("Target"); sid != "" {
		return user, sid
	}
	return record.account("Subject")
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
		user, sid := createdAccount(record)
		return Event{
			Kind: KindExec, PID: pid,
			PPID:           parseHexOrDecimal(record.data("ProcessId")),
			ResponsiblePID: parseHexOrDecimal(record.data("ProcessId")),
			Name:           baseName(record.data("NewProcessName")),
			Cmdline:        record.data("CommandLine"),
			User:           user,
			UserSID:        sid,
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
		kind := classifyObjectAccess(record.data("ObjectType"), record.data("AccessMask"), record.data("AccessList"), path)
		user, sid := record.account("Subject")
		return Event{
			Kind: kind, PID: parseHexOrDecimal(record.data("ProcessId")),
			Name: baseName(record.data("ProcessName")), Path: path,
			User: user, UserSID: sid, At: at,
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

// Write rights in a 4663 AccessMask, from the Microsoft "4663(S) An attempt
// was made to access an object" access-rights table. A file or directory
// event is a write when it used any right that can change content, metadata,
// the directory listing or the security descriptor; these are exactly the
// rights Microsoft recommends monitoring as write actions.
const (
	accessWriteData       = 0x2     // WriteData / AddFile (registry: Set key value)
	accessAppendData      = 0x4     // AppendData / AddSubdirectory (registry: Create sub-key)
	accessWriteEA         = 0x10    // WriteEA (registry: Notify, a read)
	accessKeyCreateLink   = 0x20    // registry: Create link (files: Execute/Traverse, a read)
	accessDeleteChild     = 0x40    // DeleteChild
	accessWriteAttributes = 0x100   // WriteAttributes
	accessDelete          = 0x10000 // DELETE
	accessWriteDAC        = 0x40000 // WRITE_DAC
	accessWriteOwner      = 0x80000 // WRITE_OWNER

	accessStandardWrites = accessDelete | accessWriteDAC | accessWriteOwner
	fileWriteMask        = accessWriteData | accessAppendData | accessWriteEA | accessDeleteChild |
		accessWriteAttributes | accessStandardWrites
	keyWriteMask = accessWriteData | accessAppendData | accessKeyCreateLink | accessStandardWrites
)

// objectAccessRights maps every AccessList entry the plane understands to
// whether it is a write. EvtRenderEventXml never resolves these, so the list
// arrives as %%NNNN message ids; the names are the resolved English forms,
// kept for a record rendered with its message strings.
var objectAccessRights = map[string]bool{
	// Files and directories.
	"4416": false, "readdata": false, "listdirectory": false,
	"4417": true, "writedata": true, "addfile": true,
	"4418": true, "appenddata": true, "addsubdirectory": true, "createpipeinstance": true,
	"4419": false, "readea": false,
	"4420": true, "writeea": true,
	"4421": false, "execute/traverse": false, "execute": false, "traverse": false,
	"4422": true, "deletechild": true,
	"4423": false, "readattributes": false,
	"4424": true, "writeattributes": true,
	// Standard rights, any object type.
	"1537": true, "delete": true,
	"1538": false, "read_control": false,
	"1539": true, "write_dac": true,
	"1540": true, "write_owner": true,
	"1541": false, "synchronize": false,
	"1542": false, "access_sys_sec": false,
	// Registry keys: query value, set value, create sub-key, enumerate
	// sub-keys, notify, create link.
	"4432": false, "4433": true, "4434": true, "4435": false, "4436": false, "4437": true,
}

// classifyObjectAccess decides whether a 4663 record is a write.
//
// The numeric AccessMask is authoritative when present, because it does not
// depend on how the record was rendered. Without one, the AccessList entries
// decide. An entry the table does not recognise, with no write beside it, is
// treated as a write on an agent configuration path, so an unexpected
// rendering cannot hide a change to the files the persistence finding exists
// for; elsewhere it stays a read.
func classifyObjectAccess(objectType, accessMask, accessList, path string) Kind {
	if mask, ok := parseAccessMask(accessMask); ok {
		writes := uint64(fileWriteMask)
		if strings.EqualFold(strings.TrimSpace(objectType), "Key") {
			writes = keyWriteMask
		}
		if mask&writes != 0 {
			return KindFileWrite
		}
		return KindFileRead
	}
	unknown := false
	for _, token := range strings.Fields(accessList) {
		write, known := objectAccessRights[strings.ToLower(strings.TrimPrefix(token, "%%"))]
		if write {
			return KindFileWrite
		}
		if !known {
			unknown = true
		}
	}
	if unknown && isAgentConfigPath(path) {
		return KindFileWrite
	}
	return KindFileRead
}

// parseAccessMask reads a Security-log AccessMask: 0x-prefixed hex in every
// record seen so far, bare decimal otherwise. Zero carries no rights and is
// treated as absent.
func parseAccessMask(value string) (uint64, bool) {
	value = strings.TrimSpace(value)
	base := 10
	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
		value, base = value[2:], 16
	}
	mask, err := strconv.ParseUint(value, base, 32)
	if err != nil || mask == 0 {
		return 0, false
	}
	return mask, true
}

// isAgentConfigPath reports whether path is in a .claude folder or matches
// one of the agent configuration indicators that raise
// agent_config_persistence.
func isAgentConfigPath(path string) bool {
	normalised := strings.ToLower(strings.ReplaceAll(path, `\`, "/"))
	if strings.Contains(normalised, "/.claude/") || strings.HasSuffix(normalised, "/.claude") {
		return true
	}
	for _, fragment := range tactics.IndicatorsFor("windows").AgentConfigPaths {
		if strings.Contains(normalised, strings.ToLower(strings.ReplaceAll(fragment, `\`, "/"))) {
			return true
		}
	}
	return false
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
