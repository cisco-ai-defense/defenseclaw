// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
	"unsafe"

	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"
)

var (
	windowsEventLogAPI   = windows.NewLazySystemDLL("wevtapi.dll")
	procWindowsEvtQuery  = windowsEventLogAPI.NewProc("EvtQuery")
	procWindowsEvtNext   = windowsEventLogAPI.NewProc("EvtNext")
	procWindowsEvtRender = windowsEventLogAPI.NewProc("EvtRender")
	procWindowsEvtClose  = windowsEventLogAPI.NewProc("EvtClose")
)

const (
	windowsEvtQueryChannelPath      = 0x1
	windowsEvtQueryForwardDirection = 0x100
	windowsEvtRenderEventXML        = 1
	// windowsEnterpriseEventReadLimit bounds one check; the Application log
	// keeps far fewer DefenseClaw entries on a real host.
	windowsEnterpriseEventReadLimit = 100000
)

func init() {
	enterpriseWindowsCmd.AddCommand(newWindowsEnterpriseEventsCommand())
}

func newWindowsEnterpriseEventsCommand() *cobra.Command {
	var (
		jsonOutput bool
		limit      int
	)
	cmd := &cobra.Command{
		Use:   "events",
		Short: "Tell DefenseClaw's Application-log events apart from entries other accounts wrote",
		Long: `Check every Application-log entry under the "DefenseClaw Enterprise" source
against the lifecycle log (%WINDIR%\Logs\DefenseClaw\enterprise-lifecycle.log),
which only administrators and LocalSystem can write.

Any account can write Application-log entries under any source name. An entry
is DefenseClaw's only when it ends with "record <id>", the lifecycle log holds
that record with the same event ID and the SHA-256 of the exact message, it
was written within two minutes of that lifecycle line, and no earlier entry
carried the same record. Entries older than the lifecycle log's first event
record are shown as unverifiable.

Exits 1 when an entry was not written by DefenseClaw, or when the newest
lifecycle record has no entry in the Application log. Any account can run it.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if limit < 0 {
				return errors.New("--max must be 0 (all) or more")
			}
			directory, err := windowsEnterpriseLogDirectory()
			if err != nil {
				return fmt.Errorf("locate the lifecycle log: %w", err)
			}
			logPath := filepath.Join(directory, windowsEnterpriseLogName)
			lines, err := readWindowsLifecycleEventLines(logPath, windowsEnterpriseLogGenerates)
			if err != nil {
				return err
			}
			entries, err := readWindowsEnterpriseApplicationEvents()
			if err != nil {
				return fmt.Errorf("read the Application log: %w", err)
			}
			report := checkWindowsEnterpriseEvents(entries, lines)
			report.Source, report.LifecycleLog = windowsEnterpriseEventSrc, logPath
			if jsonOutput {
				encoder := json.NewEncoder(cmd.OutOrStdout())
				encoder.SetIndent("", "  ")
				if err := encoder.Encode(report); err != nil {
					return err
				}
			} else {
				writeWindowsEventCheckReport(cmd.OutOrStdout(), report, limit)
				for _, problem := range report.Problems {
					fmt.Fprintf(cmd.OutOrStdout(), "  problem: %s\n", problem)
				}
			}
			if !report.OK {
				return fmt.Errorf("%d DefenseClaw Enterprise Application-log problem(s); see the report above", len(report.Problems))
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "emit machine-readable JSON (every entry)")
	cmd.Flags().IntVar(&limit, "max", 20, "show only the newest N entries (0 shows all); every entry is checked")
	return cmd
}

// readWindowsEnterpriseApplicationEvents reads every Application-log entry
// under the DefenseClaw Enterprise source, oldest first.
func readWindowsEnterpriseApplicationEvents() ([]windowsApplicationLogEntry, error) {
	channel, err := windows.UTF16PtrFromString("Application")
	if err != nil {
		return nil, err
	}
	query, err := windows.UTF16PtrFromString(fmt.Sprintf("*[System[Provider[@Name='%s']]]", windowsEnterpriseEventSrc))
	if err != nil {
		return nil, err
	}
	handle, _, callErr := procWindowsEvtQuery.Call(0, uintptr(unsafe.Pointer(channel)), uintptr(unsafe.Pointer(query)),
		uintptr(windowsEvtQueryChannelPath|windowsEvtQueryForwardDirection))
	if handle == 0 {
		return nil, fmt.Errorf("query the Application log: %w", callErr)
	}
	defer procWindowsEvtClose.Call(handle)

	var entries []windowsApplicationLogEntry
	events := make([]windows.Handle, 64)
	for len(entries) < windowsEnterpriseEventReadLimit {
		var returned uint32
		ok, _, callErr := procWindowsEvtNext.Call(handle, uintptr(len(events)), uintptr(unsafe.Pointer(&events[0])),
			uintptr(windows.INFINITE), 0, uintptr(unsafe.Pointer(&returned)))
		if ok == 0 {
			if errors.Is(callErr, windows.ERROR_NO_MORE_ITEMS) {
				return entries, nil
			}
			return nil, fmt.Errorf("read the Application log: %w", callErr)
		}
		var renderErr error
		for index := 0; index < int(returned); index++ {
			raw, err := renderWindowsEventXML(events[index])
			procWindowsEvtClose.Call(uintptr(events[index]))
			if err != nil {
				renderErr = err
				continue
			}
			entry, err := parseWindowsApplicationEventXML(raw)
			if err != nil {
				renderErr = err
				continue
			}
			entries = append(entries, entry)
		}
		if renderErr != nil {
			return nil, renderErr
		}
	}
	return entries, nil
}

func renderWindowsEventXML(event windows.Handle) (string, error) {
	var used, properties uint32
	procWindowsEvtRender.Call(0, uintptr(event), windowsEvtRenderEventXML, 0, 0,
		uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&properties)))
	if used == 0 {
		return "", errors.New("render an Application-log entry: empty event")
	}
	buffer := make([]uint16, used/2+1)
	ok, _, callErr := procWindowsEvtRender.Call(0, uintptr(event), windowsEvtRenderEventXML, uintptr(len(buffer)*2),
		uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&properties)))
	if ok == 0 {
		return "", fmt.Errorf("render an Application-log entry: %w", callErr)
	}
	return windows.UTF16ToString(buffer), nil
}

// windowsEnterpriseEventRecordTolerance bounds the gap between an event and
// its lifecycle line. The line is written right after the event, so a larger
// gap means the entry is a later copy of a genuine one.
const windowsEnterpriseEventRecordTolerance = 2 * time.Minute

// Verdicts of `enterprise windows events`.
const (
	windowsEventFromDefenseClaw    = "defenseclaw"
	windowsEventNotFromDefenseClaw = "not_defenseclaw"
	windowsEventBeforeRecords      = "before_records"
)

var windowsEnterpriseEventRecordSuffix = regexp.MustCompile(`\r\nrecord ([0-9a-f]{32})$`)

// windowsApplicationLogEntry is one Application-log entry under the
// DefenseClaw Enterprise source, as the event log returns it.
type windowsApplicationLogEntry struct {
	RecordNumber uint64
	EventID      uint32
	Time         time.Time
	Strings      []string
}

// windowsLifecycleEventLine is one lifecycle log line that recorded an event.
type windowsLifecycleEventLine struct {
	Time   time.Time
	Action string
	Event  windowsEnterpriseEventRecord
}

type windowsEventCheckEntry struct {
	Time         time.Time `json:"time"`
	EventID      uint32    `json:"event_id"`
	RecordNumber uint64    `json:"event_record_id"`
	Record       string    `json:"record,omitempty"`
	Action       string    `json:"action,omitempty"`
	Verdict      string    `json:"verdict"`
	Reason       string    `json:"reason,omitempty"`
}

type windowsEventCheckNewest struct {
	Record           string    `json:"record"`
	EventID          uint32    `json:"event_id"`
	Action           string    `json:"action,omitempty"`
	Time             time.Time `json:"time"`
	InApplicationLog bool      `json:"in_application_log"`
}

type windowsEventCheckReport struct {
	Source             string                   `json:"source"`
	LifecycleLog       string                   `json:"lifecycle_log"`
	RecordsSince       *time.Time               `json:"records_since,omitempty"`
	Checked            int                      `json:"checked"`
	FromDefenseClaw    int                      `json:"from_defenseclaw"`
	NotFromDefenseClaw int                      `json:"not_from_defenseclaw"`
	BeforeRecords      int                      `json:"before_records"`
	Newest             *windowsEventCheckNewest `json:"newest_record,omitempty"`
	Events             []windowsEventCheckEntry `json:"events"`
	Problems           []string                 `json:"problems,omitempty"`
	OK                 bool                     `json:"ok"`
}

// windowsEnterpriseEventDigest is the SHA-256 the lifecycle log stores for
// an event message: over the text the event log keeps, which has each
// invalid UTF-8 byte replaced with U+FFFD by the UTF-16 conversion.
func windowsEnterpriseEventDigest(message string) string {
	digest := sha256.Sum256([]byte(string([]rune(message))))
	return hex.EncodeToString(digest[:])
}

// checkWindowsEnterpriseEvents tells the DefenseClaw Enterprise entries
// DefenseClaw wrote apart from entries another account wrote under the same
// source. An entry is DefenseClaw's only when its record is on a lifecycle
// log line with the same event ID and the SHA-256 of the exact message, it
// was written within two minutes of that line, and no earlier entry carried
// the same record. Entries older than the first recorded line are reported
// as before_records: they predate event records or the retained log.
func checkWindowsEnterpriseEvents(entries []windowsApplicationLogEntry, lines []windowsLifecycleEventLine) windowsEventCheckReport {
	report := windowsEventCheckReport{Events: []windowsEventCheckEntry{}}
	ordered := append([]windowsApplicationLogEntry(nil), entries...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].RecordNumber < ordered[j].RecordNumber })

	byRecord := make(map[string]windowsLifecycleEventLine, len(lines))
	var since time.Time
	var newest *windowsLifecycleEventLine
	for index := range lines {
		line := lines[index]
		if line.Event.Record == "" {
			continue
		}
		if _, exists := byRecord[line.Event.Record]; !exists {
			byRecord[line.Event.Record] = line
		}
		if since.IsZero() || line.Time.Before(since) {
			since = line.Time
		}
		if newest == nil || !line.Time.Before(newest.Time) {
			newest = &lines[index]
		}
	}
	if !since.IsZero() {
		recordsSince := since
		report.RecordsSince = &recordsSince
	}
	beforeRecords := func(at time.Time) bool { return since.IsZero() || at.Before(since) }

	seen := map[string]bool{}
	for _, entry := range ordered {
		result := windowsEventCheckEntry{Time: entry.Time, EventID: entry.EventID, RecordNumber: entry.RecordNumber}
		message := ""
		if len(entry.Strings) == 1 {
			message = entry.Strings[0]
		}
		if match := windowsEnterpriseEventRecordSuffix.FindStringSubmatch(message); match != nil {
			result.Record = match[1]
		}
		line, recorded := byRecord[result.Record]
		switch {
		case result.Record == "" && beforeRecords(entry.Time):
			result.Verdict, result.Reason = windowsEventBeforeRecords, "no record; written before the lifecycle log's first event record"
		case result.Record == "":
			result.Verdict, result.Reason = windowsEventNotFromDefenseClaw, "no record"
		case !recorded && beforeRecords(entry.Time):
			result.Verdict, result.Reason = windowsEventBeforeRecords, "its lifecycle line is no longer in the retained lifecycle log"
		case !recorded:
			result.Verdict, result.Reason = windowsEventNotFromDefenseClaw, "the lifecycle log does not hold this record"
		case seen[result.Record]:
			result.Verdict, result.Reason = windowsEventNotFromDefenseClaw, "an earlier entry already carried this record, so this one is a copy"
		case line.Event.ID != entry.EventID:
			result.Verdict, result.Reason = windowsEventNotFromDefenseClaw, fmt.Sprintf("event ID %d, but the lifecycle log recorded event ID %d for this record", entry.EventID, line.Event.ID)
		case !strings.EqualFold(windowsEnterpriseEventDigest(message), line.Event.SHA256):
			result.Verdict, result.Reason = windowsEventNotFromDefenseClaw, "the message differs from the one the lifecycle log recorded"
		case entry.Time.Sub(line.Time) > windowsEnterpriseEventRecordTolerance || line.Time.Sub(entry.Time) > windowsEnterpriseEventRecordTolerance:
			result.Verdict, result.Reason = windowsEventNotFromDefenseClaw, fmt.Sprintf("written at %s, but the lifecycle log recorded this record at %s, so this one is a copy", entry.Time.UTC().Format(time.RFC3339), line.Time.UTC().Format(time.RFC3339))
		default:
			result.Verdict, result.Action = windowsEventFromDefenseClaw, line.Action
		}
		if result.Record != "" {
			seen[result.Record] = true
		}
		switch result.Verdict {
		case windowsEventFromDefenseClaw:
			report.FromDefenseClaw++
		case windowsEventBeforeRecords:
			report.BeforeRecords++
		default:
			report.NotFromDefenseClaw++
			report.Problems = append(report.Problems, fmt.Sprintf("%s event %d (log record %d) was not written by DefenseClaw: %s",
				entry.Time.UTC().Format(time.RFC3339), entry.EventID, entry.RecordNumber, result.Reason))
		}
		report.Events = append(report.Events, result)
	}
	report.Checked = len(report.Events)

	if newest != nil {
		report.Newest = &windowsEventCheckNewest{Record: newest.Event.Record, EventID: newest.Event.ID, Action: newest.Action, Time: newest.Time}
		for _, event := range report.Events {
			if event.Verdict == windowsEventFromDefenseClaw && event.Record == newest.Event.Record {
				report.Newest.InApplicationLog = true
				break
			}
		}
		if !report.Newest.InApplicationLog {
			report.Problems = append(report.Problems, fmt.Sprintf("the Application log holds no DefenseClaw entry for the newest lifecycle record %s (%s, event %d at %s)",
				newest.Event.Record, newest.Action, newest.Event.ID, newest.Time.UTC().Format(time.RFC3339)))
		}
	}
	report.OK = len(report.Problems) == 0
	return report
}

// readWindowsLifecycleEventLines reads the lines that recorded an event from
// the lifecycle log and its rotated generations, oldest first. A line that
// does not parse is skipped: it cannot vouch for any event.
func readWindowsLifecycleEventLines(path string, generations int) ([]windowsLifecycleEventLine, error) {
	var lines []windowsLifecycleEventLine
	for generation := generations - 1; generation >= 0; generation-- {
		name := path
		if generation > 0 {
			name = fmt.Sprintf("%s.%d", path, generation)
		}
		body, err := os.ReadFile(name)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read the lifecycle log %s: %w", name, err)
		}
		lines = append(lines, parseWindowsLifecycleEventLines(body)...)
	}
	return lines, nil
}

func parseWindowsLifecycleEventLines(body []byte) []windowsLifecycleEventLine {
	var lines []windowsLifecycleEventLine
	for _, raw := range bytes.Split(body, []byte("\n")) {
		raw = bytes.TrimSpace(raw)
		if len(raw) == 0 {
			continue
		}
		var line struct {
			Time   string                        `json:"time"`
			Event  *windowsEnterpriseEventRecord `json:"event"`
			Result struct {
				Action string `json:"action"`
			} `json:"result"`
		}
		if err := json.Unmarshal(raw, &line); err != nil || line.Event == nil || line.Event.Record == "" {
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, line.Time)
		if err != nil {
			continue
		}
		lines = append(lines, windowsLifecycleEventLine{Time: at, Action: line.Result.Action, Event: *line.Event})
	}
	return lines
}

// parseWindowsApplicationEventXML reads the fields the check needs from an
// event rendered as XML. The insertion strings are taken from the raw XML,
// not from encoding/xml character data, which would turn the message's
// CR LF line ends into LF and change its digest.
func parseWindowsApplicationEventXML(raw string) (windowsApplicationLogEntry, error) {
	var system struct {
		EventID  string `xml:"System>EventID"`
		RecordID uint64 `xml:"System>EventRecordID"`
		Created  struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"System>TimeCreated"`
	}
	// The System element holds only what the event log itself recorded;
	// parse it apart from the entry's own text, which any account chooses.
	header := raw
	if end := strings.Index(raw, "</System>"); end >= 0 {
		header = raw[:end] + "</System></Event>"
	}
	if err := xml.Unmarshal([]byte(header), &system); err != nil {
		return windowsApplicationLogEntry{}, fmt.Errorf("parse event XML: %w", err)
	}
	id, err := strconv.ParseUint(strings.TrimSpace(system.EventID), 10, 32)
	if err != nil {
		return windowsApplicationLogEntry{}, fmt.Errorf("parse event ID %q: %w", system.EventID, err)
	}
	at, err := time.Parse(time.RFC3339Nano, system.Created.SystemTime)
	if err != nil {
		return windowsApplicationLogEntry{}, fmt.Errorf("parse event time %q: %w", system.Created.SystemTime, err)
	}
	// Text that does not parse cannot be DefenseClaw's (its messages always
	// render as plain character data); the entry is kept without strings so
	// the check reports it instead of failing.
	values, _ := windowsEventDataStrings(raw)
	return windowsApplicationLogEntry{RecordNumber: system.RecordID, EventID: uint32(id), Time: at, Strings: values}, nil
}

func windowsEventDataStrings(raw string) ([]string, error) {
	decoder := xml.NewDecoder(strings.NewReader(raw))
	values := []string{}
	inEventData := false
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return values, nil
		}
		if err != nil {
			return nil, fmt.Errorf("parse event data: %w", err)
		}
		switch element := token.(type) {
		case xml.StartElement:
			if element.Name.Local == "EventData" {
				inEventData = true
				continue
			}
			if !inEventData || element.Name.Local != "Data" {
				continue
			}
			start := decoder.InputOffset()
			if err := decoder.Skip(); err != nil {
				return nil, fmt.Errorf("parse event data: %w", err)
			}
			inner := raw[start:decoder.InputOffset()]
			if end := strings.LastIndex(inner, "</"); end >= 0 {
				inner = inner[:end]
			}
			value, err := unescapeWindowsEventXMLText(inner)
			if err != nil {
				return nil, err
			}
			values = append(values, value)
		case xml.EndElement:
			if element.Name.Local == "EventData" {
				inEventData = false
			}
		}
	}
}

// unescapeWindowsEventXMLText decodes the XML references of raw character
// data and leaves everything else, including CR, as it is.
func unescapeWindowsEventXMLText(text string) (string, error) {
	if strings.Contains(text, "<![CDATA[") {
		return "", errors.New("parse event data: CDATA sections are not supported")
	}
	var builder strings.Builder
	for {
		index := strings.IndexByte(text, '&')
		if index < 0 {
			builder.WriteString(text)
			return builder.String(), nil
		}
		builder.WriteString(text[:index])
		text = text[index:]
		end := strings.IndexByte(text, ';')
		if end < 0 {
			return "", errors.New("parse event data: unterminated character reference")
		}
		name := text[1:end]
		text = text[end+1:]
		switch name {
		case "lt":
			builder.WriteByte('<')
		case "gt":
			builder.WriteByte('>')
		case "amp":
			builder.WriteByte('&')
		case "quot":
			builder.WriteByte('"')
		case "apos":
			builder.WriteByte('\'')
		default:
			if !strings.HasPrefix(name, "#") {
				return "", fmt.Errorf("parse event data: unknown reference &%s;", name)
			}
			base, digits := 10, name[1:]
			if strings.HasPrefix(digits, "x") || strings.HasPrefix(digits, "X") {
				base, digits = 16, digits[1:]
			}
			code, err := strconv.ParseUint(digits, base, 32)
			if err != nil || !utf8.ValidRune(rune(code)) {
				return "", fmt.Errorf("parse event data: bad character reference &%s;", name)
			}
			builder.WriteRune(rune(code))
		}
	}
}

func writeWindowsEventCheckReport(out io.Writer, report windowsEventCheckReport, limit int) {
	fmt.Fprintf(out, "Application-log entries under %q, checked against %s\n", report.Source, report.LifecycleLog)
	shown := report.Events
	if limit > 0 && len(shown) > limit {
		fmt.Fprintf(out, "  (the newest %d of %d entries; --max 0 shows all)\n", limit, len(shown))
		shown = shown[len(shown)-limit:]
	}
	for _, event := range shown {
		record := event.Record
		if record == "" {
			record = "-"
		}
		verdict := "DefenseClaw"
		switch event.Verdict {
		case windowsEventNotFromDefenseClaw:
			verdict = "NOT DefenseClaw: " + event.Reason
		case windowsEventBeforeRecords:
			verdict = "unverifiable: " + event.Reason
		default:
			if event.Action != "" {
				verdict += " (" + event.Action + ")"
			}
		}
		fmt.Fprintf(out, "  %s  event %-3d  record %-32s  %s\n", event.Time.UTC().Format(time.RFC3339), event.EventID, record, verdict)
	}
	if report.Newest == nil {
		fmt.Fprintln(out, "Newest lifecycle record: none yet; the lifecycle log has no event records")
	} else {
		state := "in the Application log"
		if !report.Newest.InApplicationLog {
			state = "MISSING from the Application log"
		}
		fmt.Fprintf(out, "Newest lifecycle record: %s (%s, event %d at %s): %s\n", report.Newest.Record, report.Newest.Action,
			report.Newest.EventID, report.Newest.Time.UTC().Format(time.RFC3339), state)
	}
	fmt.Fprintf(out, "Checked %d: %d from DefenseClaw, %d not from DefenseClaw, %d unverifiable\n",
		report.Checked, report.FromDefenseClaw, report.NotFromDefenseClaw, report.BeforeRecords)
}
