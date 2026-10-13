// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package plane

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"
)

// fakeSecurityLog is an in-memory Security channel behind the two streams.
type fakeSecurityLog struct {
	signal, lineage []fakeSecurityRecord
	// faults maps a lineage read number (1-based) to the error it returns.
	faults       map[int]error
	lineageReads int
	opens        int
}

type fakeSecurityRecord struct {
	id  uint64
	xml string
}

func (l *fakeSecurityLog) open(filter string, after uint64) (securityStream, error) {
	l.opens++
	stream := &fakeSecurityStream{log: l, after: after, records: l.signal}
	if filter == lineageFilter {
		stream.records, stream.lineage = l.lineage, true
	}
	return stream, nil
}

type fakeSecurityStream struct {
	log     *fakeSecurityLog
	records []fakeSecurityRecord
	lineage bool
	after   uint64
}

func (s *fakeSecurityStream) Next(max int) ([]string, error) {
	if s.lineage {
		s.log.lineageReads++
		if err, ok := s.log.faults[s.log.lineageReads]; ok {
			return nil, err
		}
	}
	start := sort.Search(len(s.records), func(i int) bool { return s.records[i].id > s.after })
	if start == len(s.records) {
		return nil, errStreamDrained
	}
	end := min(start+max, len(s.records))
	out := make([]string, 0, end-start)
	for _, record := range s.records[start:end] {
		out = append(out, record.xml)
	}
	s.after = s.records[end-1].id
	return out, nil
}

func (*fakeSecurityStream) Close() {}

// TestSecurityReaderSurvivesAProcessFlood is GAP-1473: a scheduled task
// looping a short command put tens of thousands of 4688 records in the
// Security log, every per-poll query timed out, the timeout was read as "no
// more events", and the persistence writes an agent made afterwards were
// never delivered. The writes must arrive once they have waited the bounded
// signalHoldPolls polls for the process records ahead of them (GAP-1487), a
// timeout must not end a poll, a broken stream must reopen where it stopped,
// and the lag must be reported while it lasts and cleared once the reader
// catches up.
func TestSecurityReaderSurvivesAProcessFlood(t *testing.T) {
	const flood, writes = 80000, 10
	log := &fakeSecurityLog{faults: map[int]error{
		200: errStreamTimeout,
		500: errors.New("EvtNext: The handle is invalid."),
	}}
	for id := uint64(1); id <= flood; id++ {
		log.lineage = append(log.lineage, fakeSecurityRecord{id: id, xml: fmt.Sprintf(
			`<Event><System><EventID>4688</EventID><EventRecordID>%d</EventRecordID></System><EventData>`+
				`<Data Name="NewProcessId">0x%x</Data><Data Name="ProcessId">0x4</Data>`+
				`<Data Name="NewProcessName">C:\Windows\System32\cmd.exe</Data></EventData></Event>`, id, id+1000)})
	}
	for id := uint64(flood + 1); id <= flood+writes; id++ {
		log.signal = append(log.signal, fakeSecurityRecord{id: id, xml: fmt.Sprintf(
			`<Event><System><EventID>4663</EventID><EventRecordID>%d</EventRecordID></System><EventData>`+
				`<Data Name="ObjectName">C:\Users\alice\.claude\settings.json.tmp</Data>`+
				`<Data Name="AccessMask">0x2</Data><Data Name="ProcessId">0x1a4</Data>`+
				`<Data Name="ProcessName">C:\Users\alice\.local\bin\claude.exe</Data></EventData></Event>`, id)})
	}

	buffer := NewBuffer()
	reader := newSecurityReader(log.open, buffer, 0)
	fixed := time.Unix(1_800_000_000, 0)
	reader.now = func() time.Time { return fixed }
	if err := reader.openAll(); err != nil {
		t.Fatal(err)
	}

	execs := make(map[int]int, flood)
	written := 0
	drainBuffer := func() (polledExecs int) {
		for {
			select {
			case event := <-buffer.Events():
				switch event.Kind {
				case KindExec:
					execs[event.PID]++
					polledExecs++
				case KindFileWrite:
					written++
				}
			default:
				return polledExecs
			}
		}
	}

	sawTimeoutPoll, sawFailure := false, false
	for poll := 1; poll <= 100; poll++ {
		before := log.lineageReads
		reader.pollOnce()
		polled := drainBuffer()
		limits := strings.Join(reader.limitations(), "; ")
		if poll == 1 && !strings.Contains(limits, "behind") {
			t.Fatalf("a capped poll reported no lag: %q", limits)
		}
		if poll == 1+signalHoldPolls && written != writes {
			t.Fatalf("poll %d delivered %d of %d settings.json writes behind a %d-record flood",
				poll, written, writes, flood)
		}
		if before < 200 && log.lineageReads >= 200 {
			sawTimeoutPoll = true
			if polled != lineageCap {
				t.Fatalf("the poll with a read timeout delivered %d process records, want the full %d",
					polled, lineageCap)
			}
		}
		if before < 500 && log.lineageReads >= 500 {
			sawFailure = true
			if !strings.Contains(limits, "read failed") {
				t.Fatalf("a broken stream was not reported: %q", limits)
			}
		}
		if limits == "" {
			break
		}
	}
	if !sawTimeoutPoll || !sawFailure {
		t.Fatalf("faults not exercised: timeout=%v failure=%v", sawTimeoutPoll, sawFailure)
	}
	if limits := reader.limitations(); len(limits) != 0 {
		t.Fatalf("the reader caught up but still reports %q", limits)
	}
	if len(execs) != flood {
		t.Fatalf("delivered %d distinct process records, want %d", len(execs), flood)
	}
	for pid, count := range execs {
		if count != 1 {
			t.Fatalf("pid %d delivered %d times", pid, count)
		}
	}
	if written != writes || buffer.Dropped() != 0 || log.opens != 3 {
		t.Fatalf("writes=%d dropped=%d opens=%d, want %d, 0 and 3 (one reopen)",
			written, buffer.Dropped(), log.opens, writes)
	}
}

// TestSecurityReaderHoldsAWriteForItsProcessCreation is GAP-1487: the file
// stream is drained in full while the process stream stops at lineageCap, so
// a write whose process was created past the cap reached the host plane
// before that creation, failed the lineage gate and was never retried. The
// write must wait for the poll that delivers its creation.
func TestSecurityReaderHoldsAWriteForItsProcessCreation(t *testing.T) {
	const flood, writer = lineageCap + 500, 0x9999
	log := &fakeSecurityLog{}
	for id := uint64(1); id <= flood; id++ {
		pid := id + 1000
		if id == flood {
			pid = writer
		}
		log.lineage = append(log.lineage, fakeSecurityRecord{id: id, xml: fmt.Sprintf(
			`<Event><System><EventID>4688</EventID><EventRecordID>%d</EventRecordID></System><EventData>`+
				`<Data Name="NewProcessId">0x%x</Data><Data Name="ProcessId">0x4</Data>`+
				`<Data Name="NewProcessName">C:\Windows\System32\cmd.exe</Data></EventData></Event>`, id, pid)})
	}
	log.signal = []fakeSecurityRecord{{id: flood + 1, xml: fmt.Sprintf(
		`<Event><System><EventID>4663</EventID><EventRecordID>%d</EventRecordID></System><EventData>`+
			`<Data Name="ObjectName">C:\Users\alice\.claude\settings.json</Data>`+
			`<Data Name="AccessMask">0x2</Data><Data Name="ProcessId">0x%x</Data>`+
			`<Data Name="ProcessName">C:\Windows\System32\cmd.exe</Data></EventData></Event>`, flood+1, writer)}}

	buffer := NewBuffer()
	reader := newSecurityReader(log.open, buffer, 0)
	if err := reader.openAll(); err != nil {
		t.Fatal(err)
	}
	created := false
	for poll := 1; poll <= 2; poll++ {
		reader.pollOnce()
		for drained := false; !drained; {
			select {
			case event := <-buffer.Events():
				if event.Kind == KindExec && event.PID == writer {
					created = true
				}
				if event.Kind == KindFileWrite {
					if !created {
						t.Fatalf("poll %d delivered the write before the creation of its process", poll)
					}
					return
				}
			default:
				drained = true
			}
		}
	}
	t.Fatal("the write was not delivered once the reader caught up")
}
