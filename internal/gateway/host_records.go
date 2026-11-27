// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The host record count (rel-1-0-10:GAP-2042, issue #1452). A managed hook
// that decides without the gateway (fail open or closed, a call shed past
// its retry budget, an integrity boundary) writes one record to the host
// log: the local syslog (journald on Linux) or the Windows Application event
// log, under the gateway service name (hookexec recordManagedHookDecision,
// GAP-1029). Those decisions are not in the gateway audit. A managed gateway
// counts the hook records of the last 24 hours, so status and doctor can say
// that a hook blocked calls on its own while the gateway reported healthy.
//
// The records are not authenticated: any local account can write the same
// tag or event source. They are only counted, never written to the audit
// store and never taken as a gateway decision. A read is bounded: at most
// hostRecordReadMax entries, hostRecordLineMax bytes per record line and
// hostRecordOutputMax bytes of reader output, hostRecordReadWait per read,
// and one read per hostRecordReadEvery; a line that is not a record the hook
// writes is counted as dropped.
const (
	hostRecordWindow    = 24 * time.Hour
	hostRecordReadMax   = 500
	hostRecordLineMax   = 1000
	hostRecordOutputMax = 4 << 20
	hostRecordReadWait  = 30 * time.Second
	hostRecordReadEvery = 5 * time.Minute
)

// HostRecordsSnapshot is the /health and /status "host_records" object of a
// managed gateway.
type HostRecordsSnapshot struct {
	// Readable: the host log was read; Reason says why not.
	Readable    bool   `json:"readable"`
	Reason      string `json:"reason,omitempty"`
	WindowHours int    `json:"window_hours"`
	// Records = Blocks + Allows: the hook decision records of the window.
	Records int `json:"records"`
	Blocks  int `json:"blocks"`
	Allows  int `json:"allows"`
	// Dropped: entries under the gateway's tag or source that are not a
	// well-formed hook record (oversized, forged or cut lines).
	Dropped int `json:"dropped"`
	// ReadLimitReached: the window has more than ReadMax entries; the counts
	// are of the newest ReadMax.
	ReadLimitReached bool       `json:"read_limit_reached,omitempty"`
	ReadMax          int        `json:"read_max"`
	LastRead         *time.Time `json:"last_read,omitempty"`
}

// hostRecordRead is what one platform read returns: the record lines of the
// window, newest first, at most hostRecordReadMax+1 of them.
type hostRecordRead struct {
	lines  []string
	capped bool // the reader output passed hostRecordOutputMax
}

type hostRecordReader struct {
	mu   sync.Mutex
	now  func() time.Time
	read func(ctx context.Context, source string, since time.Time) (hostRecordRead, error)
	snap HostRecordsSnapshot
	busy bool
	at   time.Time // start of the last read
}

// hostRecords is the process reader of the managed gateway.
var hostRecords = &hostRecordReader{now: time.Now, read: readHostRecordLines}

// snapshot returns the last count and starts a new read in the background
// when the last one is older than hostRecordReadEvery.
func (h *hostRecordReader) snapshot() HostRecordsSnapshot {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.kickLocked()
	snap := h.snap
	if snap.LastRead == nil && snap.Reason == "" {
		snap.Reason = "not read yet"
	}
	snap.WindowHours, snap.ReadMax = int(hostRecordWindow/time.Hour), hostRecordReadMax
	return snap
}

// kick starts a read now unless one ran in the last hostRecordReadEvery.
func (h *hostRecordReader) kick() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.kickLocked()
}

func (h *hostRecordReader) kickLocked() {
	now := h.now()
	if h.busy || (!h.at.IsZero() && now.Sub(h.at) < hostRecordReadEvery) {
		return
	}
	h.busy, h.at = true, now
	go h.refresh(now)
}

func (h *hostRecordReader) refresh(now time.Time) {
	ctx, cancel := context.WithTimeout(context.Background(), hostRecordReadWait)
	defer cancel()
	got, err := h.read(ctx, hostRecordSource(), now.Add(-hostRecordWindow))
	snap := HostRecordsSnapshot{}
	if err != nil {
		snap.Reason = boundedManagedReason(err.Error())
	} else {
		snap = countHostRecords(got)
		read := now.UTC().Truncate(time.Second)
		snap.LastRead = &read
	}
	h.mu.Lock()
	h.snap, h.busy = snap, false
	h.mu.Unlock()
}

func boundedManagedReason(s string) string {
	s = strings.ToValidUTF8(strings.TrimSpace(s), "")
	if len(s) > 200 {
		s = strings.ToValidUTF8(s[:200], "")
	}
	return s
}

// countHostRecords counts the hook decision records of one read.
func countHostRecords(got hostRecordRead) HostRecordsSnapshot {
	snap := HostRecordsSnapshot{Readable: true}
	lines := got.lines
	if len(lines) > hostRecordReadMax || got.capped {
		snap.ReadLimitReached = true
	}
	if len(lines) > hostRecordReadMax {
		lines = lines[:hostRecordReadMax]
	}
	for _, line := range lines {
		switch decision, ok, hook := parseHostRecordLine(line); {
		case !ok:
			snap.Dropped++
		case !hook:
		case decision == "block":
			snap.Blocks++
		default:
			snap.Allows++
		}
	}
	snap.Records = snap.Blocks + snap.Allows
	return snap
}

// parseHostRecordLine reads one line under the gateway's tag or source.
// hook is true for a managed hook decision record (component hook, marker
// boundary or degraded); ok is false for a line the hook does not write
// that way: oversized, an unknown leading token, not marker then key="value"
// pairs, a repeated key, or a decision other than allow or block. Other
// records of the hook process (trust advisories, a provider overlay note)
// are ok and not hook.
func parseHostRecordLine(line string) (decision string, ok, hook bool) {
	line = strings.TrimRight(line, "\r\n")
	if len(line) > hostRecordLineMax {
		return "", false, false
	}
	marker, rest, _ := strings.Cut(line, " ")
	if marker != managed.MarkerBoundary && marker != managed.MarkerDegraded {
		// Another record the hook process writes, or a line it never does.
		return "", hostRecordOtherMarkers[marker], false
	}
	fields := map[string]string{}
	for rest != "" {
		key, tail, found := strings.Cut(rest, "=")
		if !found || !hostRecordKey(key) {
			return "", false, false
		}
		quoted, err := strconv.QuotedPrefix(tail)
		if err != nil {
			return "", false, false
		}
		value, err := strconv.Unquote(quoted)
		if err != nil {
			return "", false, false
		}
		if _, dup := fields[key]; dup {
			return "", false, false
		}
		fields[key] = value
		rest = tail[len(quoted):]
		if rest != "" {
			if rest[0] != ' ' {
				return "", false, false
			}
			rest = rest[1:]
		}
	}
	if fields["component"] != "hook" {
		return "", true, false
	}
	switch d := fields["decision"]; d {
	case "allow", "block":
		return d, true, true
	}
	return "", false, false
}

// hostRecordOtherMarkers are the other leading tokens of the records the
// hook process writes under the gateway's tag (managed resilience events and
// trust advisories): not hook decisions, not dropped.
var hostRecordOtherMarkers = map[string]bool{
	managed.MarkerRepair: true, managed.MarkerAccept: true, managed.MarkerSkip: true,
	managed.MarkerPrereq: true, managed.MarkerRecover: true,
	managed.TrustAdvisoryMarker: true, managed.TrustDriftAdvisoryMarker: true,
}

func hostRecordKey(key string) bool {
	if key == "" || len(key) > 32 {
		return false
	}
	for i := 0; i < len(key); i++ {
		if c := key[i]; (c < 'a' || c > 'z') && c != '_' {
			return false
		}
	}
	return true
}

// hostRecordCommand runs a host log reader with a bounded output.
func hostRecordCommand(ctx context.Context, path string, args ...string) ([]byte, bool, error) {
	cmd := exec.CommandContext(ctx, path, args...)
	out := &hostRecordOutput{max: hostRecordOutputMax}
	cmd.Stdout = out
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, false, errors.New("the host log did not answer in time")
		}
		return nil, false, err
	}
	return out.buf.Bytes(), out.capped, nil
}

// hostRecordOutput keeps the first max bytes and drops the rest.
type hostRecordOutput struct {
	buf    bytes.Buffer
	max    int
	capped bool
}

func (o *hostRecordOutput) Write(p []byte) (int, error) {
	if room := o.max - o.buf.Len(); room < len(p) {
		o.capped = true
		if room > 0 {
			o.buf.Write(p[:room])
		}
		return len(p), nil
	}
	return o.buf.Write(p)
}

// parseJournalRecords reads journalctl --output=json lines: MESSAGE is a
// string, or an array of bytes when it is not valid UTF-8.
func parseJournalRecords(out []byte) []string {
	var lines []string
	for _, raw := range bytes.Split(out, []byte("\n")) {
		raw = bytes.TrimSpace(raw)
		if len(raw) == 0 {
			continue
		}
		var entry struct {
			Message json.RawMessage `json:"MESSAGE"`
		}
		if json.Unmarshal(raw, &entry) != nil || len(entry.Message) == 0 {
			lines = append(lines, "")
			continue
		}
		var text string
		if json.Unmarshal(entry.Message, &text) != nil {
			var b []byte
			var ints []int
			if json.Unmarshal(entry.Message, &ints) != nil {
				lines = append(lines, "")
				continue
			}
			for _, v := range ints {
				if v < 0 || v > 255 {
					b = nil
					break
				}
				b = append(b, byte(v))
			}
			text = string(b)
		}
		lines = append(lines, text)
	}
	return lines
}

// parseUnifiedLogRecords reads log show --style ndjson lines: eventMessage,
// with the syslog tag of the sender removed when it is kept.
func parseUnifiedLogRecords(out []byte, source string) []string {
	var lines []string
	for _, raw := range bytes.Split(out, []byte("\n")) {
		raw = bytes.TrimSpace(raw)
		if len(raw) == 0 {
			continue
		}
		var entry struct {
			EventMessage *string `json:"eventMessage"`
		}
		if json.Unmarshal(raw, &entry) != nil {
			lines = append(lines, "")
			continue
		}
		if entry.EventMessage == nil {
			continue // the closing summary object
		}
		lines = append(lines, stripSyslogTag(*entry.EventMessage, source))
	}
	return lines
}

// stripSyslogTag removes a leading "source[pid]: " or "source: ".
func stripSyslogTag(message, source string) string {
	rest, ok := strings.CutPrefix(message, source)
	if !ok {
		return message
	}
	if strings.HasPrefix(rest, "[") {
		end := strings.Index(rest, "]")
		if end < 0 {
			return message
		}
		if _, err := strconv.ParseUint(rest[1:end], 10, 32); err != nil {
			return message
		}
		rest = rest[end+1:]
	}
	if after, ok := strings.CutPrefix(rest, ": "); ok {
		return after
	}
	return message
}

// parseEventLogRecords reads wevtutil qe /f:xml output: a sequence of Event
// elements, the record line in the first EventData Data.
func parseEventLogRecords(out []byte) []string {
	var lines []string
	dec := xml.NewDecoder(bytes.NewReader(out))
	for {
		tok, err := dec.Token()
		if err != nil {
			return lines
		}
		start, ok := tok.(xml.StartElement)
		if !ok || start.Name.Local != "Event" {
			continue
		}
		var event struct {
			Data []string `xml:"EventData>Data"`
		}
		if dec.DecodeElement(&event, &start) != nil {
			lines = append(lines, "")
			return lines
		}
		if len(event.Data) == 0 {
			lines = append(lines, "")
			continue
		}
		lines = append(lines, event.Data[0])
	}
}
