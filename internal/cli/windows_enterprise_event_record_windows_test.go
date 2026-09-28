// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// A DefenseClaw Application-log event carries a record id that the
// administrator-only lifecycle log holds with the event ID and the SHA-256 of
// the exact message, so an entry another account wrote under the same source
// can be told apart.
func TestWindowsEnterpriseEventCarriesARecordTheLifecycleLogHolds(t *testing.T) {
	previousID, previousWriter := windowsEnterpriseEventRecordID, windowsEnterpriseEventWriter
	t.Cleanup(func() { windowsEnterpriseEventRecordID, windowsEnterpriseEventWriter = previousID, previousWriter })
	windowsEnterpriseEventRecordID = func() (string, error) { return "0123456789abcdef0123456789abcdef", nil }
	var written string
	var writtenID uint32
	windowsEnterpriseEventWriter = func(id uint32, _ string, message string) error {
		writtenID, written = id, message
		return nil
	}

	result := enterprisestatus.New("install", "standalone", "windows", "1.0.51")
	result.Finish("windows", 0)
	event := writeWindowsEnterpriseEvent(result)
	if event == nil {
		t.Fatal("no event record for a finished install")
	}
	if !strings.HasSuffix(written, "\r\nrecord 0123456789abcdef0123456789abcdef") {
		t.Fatalf("event message does not end with its record:\n%s", written)
	}
	digest := sha256.Sum256([]byte(written))
	if event.ID != writtenID || event.Record != "0123456789abcdef0123456789abcdef" || event.SHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("event record %+v does not match the written event (id %d)", event, writtenID)
	}

	directory := t.TempDir()
	if _, err := writeWindowsEnterpriseLifecycleLog(directory, result, event); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(directory, windowsEnterpriseLogName))
	if err != nil {
		t.Fatal(err)
	}
	var line struct {
		Event *windowsEnterpriseEventRecord `json:"event"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(body))), &line); err != nil {
		t.Fatal(err)
	}
	if line.Event == nil || *line.Event != *event {
		t.Fatalf("lifecycle log event = %+v, want %+v", line.Event, event)
	}
}

// The event check starts from the administrator-only
// lifecycle log. The genuine event passes; a later copy that reuses its
// record, and an entry without a record, do not; and the newest lifecycle
// record must have its entry in the Application log. Entries are parsed from
// the XML the event log renders, whose raw CR LF line ends the message
// digest depends on.
func TestWindowsEnterpriseEventCheckRejectsAReusedRecord(t *testing.T) {
	const recordA, recordB = "0123456789abcdef0123456789abcdef", "fedcba9876543210fedcba9876543210"
	base := time.Date(2026, 9, 28, 4, 0, 0, 0, time.UTC)
	success := "DefenseClaw enterprise ensure (standalone) ok=true exit=0 version=1.0.51\r\nwarning w: <a> & b\r\nrecord " + recordA
	failure := "DefenseClaw enterprise repair (standalone) ok=false exit=1603 version=1.0.51\r\nrecord " + recordB
	lines := []windowsLifecycleEventLine{
		{Time: base, Action: "ensure", Event: windowsEnterpriseEventRecord{ID: 112, Record: recordA, SHA256: windowsEnterpriseEventDigest(success)}},
		{Time: base.Add(time.Hour), Action: "repair", Event: windowsEnterpriseEventRecord{ID: 130, Record: recordB, SHA256: windowsEnterpriseEventDigest(failure)}},
	}
	rendered := func(number int, id int, at time.Time, message string) windowsApplicationLogEntry {
		escaped := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(message)
		entry, err := parseWindowsApplicationEventXML(fmt.Sprintf(
			"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='DefenseClaw Enterprise'/>"+
				"<EventID Qualifiers='0'>%d</EventID><TimeCreated SystemTime='%s'/><EventRecordID>%d</EventRecordID></System>"+
				"<EventData><Data>%s</Data></EventData></Event>", id, at.Format(time.RFC3339Nano), number, escaped))
		if err != nil {
			t.Fatal(err)
		}
		return entry
	}
	entries := []windowsApplicationLogEntry{
		rendered(10, 112, base.Add(-time.Second), success),
		rendered(11, 112, base.Add(time.Minute), success),
		rendered(12, 112, base.Add(2*time.Minute), "DefenseClaw enterprise ensure (standalone) ok=true exit=0 version=1.0.51"),
	}
	report := checkWindowsEnterpriseEvents(entries, lines)
	var verdicts []string
	for _, event := range report.Events {
		verdicts = append(verdicts, event.Verdict)
	}
	if got := strings.Join(verdicts, ","); got != "defenseclaw,not_defenseclaw,not_defenseclaw" {
		t.Fatalf("verdicts = %s (%+v)", got, report.Events)
	}
	if !strings.Contains(report.Events[1].Reason, "copy") || report.Newest == nil || report.Newest.Record != recordB ||
		report.Newest.InApplicationLog || report.OK || len(report.Problems) != 3 {
		t.Fatalf("report = %+v", report)
	}

	entries = append(entries[:1], rendered(13, 130, base.Add(time.Hour-time.Second), failure))
	if report := checkWindowsEnterpriseEvents(entries, lines); !report.OK || report.FromDefenseClaw != 2 || !report.Newest.InApplicationLog {
		t.Fatalf("genuine entries report = %+v", report)
	}
}
