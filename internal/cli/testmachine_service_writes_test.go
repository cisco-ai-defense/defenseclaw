// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The TestMain machine guard compares the computer's DefenseClaw folders
// before and after the package's tests (GAP-0079). On a managed computer the
// DefenseClaw services run while the tests do, and they rewrite their own
// folders on their own schedule: the hook guardian rewrites its state, its
// activation receipt, the unprotected-agent record and the machine-policy
// records on every pass (a new updated_at and reconcile_id, nothing else),
// and the services append to their logs. A fingerprint of size and
// modification time reported every one of those as a test's write, so a run
// longer than one guardian pass always failed (GAP-0093).
//
// A service-owned folder is therefore compared by meaning, not by time:
//
//   - a JSON record by its content with the services' own pass stamps
//     (testServiceVolatileKeys) removed, so a service pass that changes
//     nothing else is the same record and any other change is a change;
//   - a log by append-only growth: what was there before must still be its
//     exact start, and what was added must not name this test run (its temp
//     folder, its registry sandbox, its executable), which every test's own
//     writes do;
//   - any other file by its content, and a folder by the names in it (a new,
//     removed or replaced entry is a change, its time is not).
//
// The guard also re-reads a changed snapshot once the services' writes have
// settled (guardTestMachine), so a record caught between a service's write
// and rename is not a change. A test's write stays, so it is still reported.

// diffTestMachineRegistry lists what changed between two machine snapshots
// (registry values and folder fingerprints).
func diffTestMachineRegistry(before, after map[string]string) []string {
	var changes []string
	for name, value := range before {
		if now, ok := after[name]; !ok {
			changes = append(changes, "removed "+name+" = "+value)
		} else if now != value {
			changes = append(changes, "changed "+name+" = "+value+" -> "+now)
		}
	}
	for name, value := range after {
		if _, ok := before[name]; !ok {
			changes = append(changes, "added "+name+" = "+value)
		}
	}
	sort.Strings(changes)
	return changes
}

// testServiceVolatileKeys are the pass stamps the DefenseClaw services write
// into their own records on every pass, at any depth.
var testServiceVolatileKeys = map[string]bool{"updated_at": true, "reconcile_id": true}

// testServiceFileHashLimit bounds the files the guard reads whole; a larger
// file in a service folder (the hook payload) is compared by size and time.
// A log has no limit: it is hashed as a stream and only its new tail is read
// (testServiceLogFingerprint), because the hook guardian's log grows by about
// 1 MB a day and is never rotated, so on a computer up more than about nine
// days a size-and-time compare reported every guardian pass again (GAP-0093
// review S1).
const testServiceFileHashLimit = 8 << 20

// testServiceFolders are the service-owned folders of one machine
// snapshot: roots are compared by meaning, before is the snapshot an after
// snapshot is compared with (nil for the first), and runMarkers name this
// test run. The machine walk leaves roots out (as its skip list) and
// fingerprintTestServiceFolders records them.
type testServiceFolders struct {
	roots      []string
	before     map[string]string
	runMarkers []string
}

// fingerprintTestServiceFolders records every service-owned folder of
// folders by meaning (see the comment at the top of this file).
func fingerprintTestServiceFolders(snapshot map[string]string, folders testServiceFolders) {
	for _, root := range folders.roots {
		if root != "" {
			fingerprintTestServiceTree(snapshot, root, folders)
		}
	}
}

// testEntryKind names the kind of a folder entry.
func testEntryKind(entry fs.DirEntry) string {
	switch {
	case entry.IsDir():
		return "folder"
	case entry.Type()&fs.ModeSymlink != 0:
		return "link"
	case !entry.Type().IsRegular():
		return "other"
	}
	return "file"
}

// fingerprintTestServiceTree records a service-owned folder by meaning (see
// the comment at the top of this file). A folder this identity cannot list
// (a standard user and the guardian's state folder) is recorded without its
// modified time, which the service's own rewrites move: such an identity
// cannot write in it either.
func fingerprintTestServiceTree(snapshot map[string]string, root string, folders testServiceFolders) {
	_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		key := "file " + path
		if err != nil {
			switch {
			case errors.Is(err, fs.ErrNotExist):
				delete(snapshot, key)
			case entry != nil && entry.IsDir():
				snapshot[key] = "service folder, contents unreadable: " + err.Error()
			default:
				snapshot[key] = "unreadable: " + err.Error()
			}
			return nil
		}
		if kind := testEntryKind(entry); kind != "file" {
			snapshot[key] = "service " + kind
			return nil
		}
		snapshot[key] = testServiceFileFingerprint(path, folders.before[key], folders.runMarkers)
		return nil
	})
}

// testServiceFileFingerprint is the fingerprint of one file in a service
// folder. before is its fingerprint in the first snapshot ("" in that
// snapshot or for a new file).
func testServiceFileFingerprint(path, before string, runMarkers []string) string {
	info, err := os.Lstat(path)
	if err != nil {
		return "unreadable: " + err.Error()
	}
	if strings.EqualFold(filepath.Ext(path), ".log") {
		return testServiceLogFingerprint(path, before, runMarkers)
	}
	if info.Size() > testServiceFileHashLimit {
		return fmt.Sprintf("service file %d %s", info.Size(), info.ModTime().UTC().Format(time.RFC3339Nano))
	}
	body, err := readTestServiceFile(path)
	if err != nil {
		return "unreadable: " + err.Error()
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		if canonical, ok := testServiceRecordMeaning(body); ok {
			return "service record " + testSHA256(canonical)
		}
		return fmt.Sprintf("service record unparsed %d %s", len(body), testSHA256(body))
	}
	return fmt.Sprintf("service file %d %s", len(body), testSHA256(body))
}

// readTestServiceFile reads a file the services may hold open for writing.
func readTestServiceFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, testServiceFileHashLimit+1))
}

func testSHA256(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// testServiceRecordMeaning is a JSON record without the services' pass
// stamps, canonically encoded.
func testServiceRecordMeaning(body []byte) ([]byte, bool) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, false
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, false
	}
	canonical, err := json.Marshal(dropTestServiceVolatileKeys(value))
	return canonical, err == nil
}

func dropTestServiceVolatileKeys(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		for key, nested := range typed {
			if testServiceVolatileKeys[key] {
				delete(typed, key)
				continue
			}
			typed[key] = dropTestServiceVolatileKeys(nested)
		}
	case []any:
		for i, nested := range typed {
			typed[i] = dropTestServiceVolatileKeys(nested)
		}
	}
	return value
}

// testServiceLogFingerprint is "service log <size> <sha256>" in the first
// snapshot. In a later one, a log that kept its earlier content as its
// exact start and only grew by text that does not name this run keeps its
// first fingerprint; a log that was rewritten, truncated, or grew by text
// that names this run gets another. The log is read as a stream, whatever
// its size: its earlier bytes are hashed, not held, and only the tail
// written since is searched for the run's markers.
func testServiceLogFingerprint(path, before string, runMarkers []string) string {
	file, err := os.Open(path)
	if err != nil {
		return "unreadable: " + err.Error()
	}
	defer file.Close()
	whole := sha256.New()
	fields := strings.Fields(before)
	size, sizeErr := int64(-1), errors.New("no earlier fingerprint")
	if len(fields) == 4 && fields[0] == "service" && fields[1] == "log" {
		size, sizeErr = strconv.ParseInt(fields[2], 10, 64)
	}
	if sizeErr != nil || size < 0 {
		read, err := io.Copy(whole, file)
		if err != nil {
			return "unreadable: " + err.Error()
		}
		return fmt.Sprintf("service log %d %s", read, hex.EncodeToString(whole.Sum(nil)))
	}
	earlier := sha256.New()
	read, err := io.CopyN(io.MultiWriter(earlier, whole), file, size)
	if err != nil && !errors.Is(err, io.EOF) {
		return "unreadable: " + err.Error()
	}
	kept := read == size && hex.EncodeToString(earlier.Sum(nil)) == fields[3]
	tail := newTestRunMarkerScanner(runMarkers)
	added, err := io.Copy(io.MultiWriter(whole, tail), file)
	if err != nil {
		return "unreadable: " + err.Error()
	}
	now := fmt.Sprintf("service log %d %s", read+added, hex.EncodeToString(whole.Sum(nil)))
	switch {
	case !kept:
		return now + " (its earlier content was rewritten or truncated)"
	case tail.found != "":
		return now + " (a line written during the run names the test run: " + tail.found + ")"
	}
	return before
}

// testRunMarkerScanner is an io.Writer that reports the first run marker
// the text written to it names, ignoring ASCII case, across the boundaries
// of the writes.
type testRunMarkerScanner struct {
	markers [][]byte
	carry   []byte
	keep    int
	found   string
}

func newTestRunMarkerScanner(runMarkers []string) *testRunMarkerScanner {
	scanner := &testRunMarkerScanner{}
	for _, marker := range runMarkers {
		if marker = strings.TrimSpace(marker); marker != "" {
			lower := testASCIILower([]byte(marker))
			scanner.markers = append(scanner.markers, lower)
			scanner.keep = max(scanner.keep, len(lower)-1)
		}
	}
	return scanner
}

func (s *testRunMarkerScanner) Write(chunk []byte) (int, error) {
	if s.found != "" || len(s.markers) == 0 {
		return len(chunk), nil
	}
	text := append(s.carry, testASCIILower(chunk)...)
	for _, marker := range s.markers {
		if bytes.Contains(text, marker) {
			s.found = string(marker)
			return len(chunk), nil
		}
	}
	s.carry = append(s.carry[:0], text[max(0, len(text)-s.keep):]...)
	return len(chunk), nil
}

// testASCIILower is a lower-case copy of text, ASCII letters only, so a
// marker split across two writes still matches byte for byte.
func testASCIILower(text []byte) []byte {
	lower := make([]byte, len(text))
	for i, c := range text {
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		lower[i] = c
	}
	return lower
}

// TestTestMachineServiceFoldersTellTheServicesWritesFromATests checks the
// GAP-0093 rules with a fake service folder: a service pass (new pass stamps,
// an identical rewrite, a replaced folder entry, appended service log lines)
// is not a change, and each kind of test write in the same folder is.
func TestTestMachineServiceFoldersTellTheServicesWritesFromATests(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state")
	service := filepath.Join(state, "guardian-state")
	logs := filepath.Join(state, "logs")
	runTemp := filepath.Join(root, "run-temp")
	path := func(name string) string { return filepath.Join(state, filepath.FromSlash(name)) }
	write := func(name, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path(name)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path(name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	appendLog := func(text string) {
		t.Helper()
		file, err := os.OpenFile(path("logs/guardian.log"), os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.WriteString(text); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	const activation = `{"version":1,"updated_at":"%s","reconcile_id":"%s","ok":true,"protected_targets":[{"user":"u","updated_at":"%s"}]}`
	reset := func() {
		t.Helper()
		if err := os.RemoveAll(state); err != nil {
			t.Fatal(err)
		}
		write("guardian-state/activation.json", fmt.Sprintf(activation, "2026-11-06T18:00:00Z", "aa", "2026-11-06T18:00:00Z"))
		write("guardian-state/unprotected-agents.json", `{"version":1,"agents":[]}`)
		write("guardian-state/.state", "ready\n")
		write("logs/guardian.log", "[hook-guardian] reconcile reason=interval status=ok\n")
		write("runtime/audit.db", "1")
		write("etc/config.yaml", "a: 1\n")
	}
	folders := testServiceFolders{roots: []string{service, logs}, runMarkers: []string{runTemp, `Software\DefenseClaw-test-42`}}
	snapshot := func(before map[string]string) map[string]string {
		folders.before = before
		out := map[string]string{}
		fingerprintTestServiceFolders(out, folders)
		return out
	}
	servicePass := func() {
		time.Sleep(20 * time.Millisecond) // a later modification time
		write("guardian-state/activation.json", fmt.Sprintf(activation, "2026-11-06T18:05:00Z", "bb", "2026-11-06T18:05:00Z"))
		write("guardian-state/unprotected-agents.json", `{"version":1,"agents":[]}`)
		write("guardian-state/.state", "ready\n")
		appendLog("[hook-guardian] reconcile reason=interval status=ok\n[hook-enumerator] cycle complete users=0\n")
		write("runtime/audit.db", "12")
	}

	reset()
	before := snapshot(nil)
	servicePass()
	if changes := diffTestMachineRegistry(before, snapshot(before)); len(changes) != 0 {
		t.Fatalf("a service pass alone is reported as a test's write:\n%s", strings.Join(changes, "\n"))
	}

	for _, tc := range []struct {
		name, want string
		write      func()
	}{
		{"a changed record", "guardian-state/activation.json", func() {
			write("guardian-state/activation.json", fmt.Sprintf(strings.Replace(activation, `"ok":true`, `"ok":false`, 1), "2026-11-06T18:05:00Z", "bb", "x"))
		}},
		{"a record a target was added to", "guardian-state/activation.json", func() {
			write("guardian-state/activation.json", `{"version":1,"updated_at":"x","reconcile_id":"y","ok":true,"protected_targets":[{"user":"u"},{"user":"test"}]}`)
		}},
		{"a record that is no longer JSON", "guardian-state/unprotected-agents.json", func() { write("guardian-state/unprotected-agents.json", "fixture") }},
		{"a new file", "guardian-state/fixture.json", func() { write("guardian-state/fixture.json", "{}") }},
		{"a removed file", "guardian-state/.state", func() {
			if err := os.Remove(path("guardian-state/.state")); err != nil {
				t.Fatal(err)
			}
		}},
		{"a changed plain file", "guardian-state/.state", func() { write("guardian-state/.state", "fixture\n") }},
		{"a rewritten log", "logs/guardian.log", func() { write("logs/guardian.log", "[hook-guardian] fixture\n") }},
		{"a truncated log", "logs/guardian.log", func() { write("logs/guardian.log", "") }},
		{"a log line naming the run's temp folder", "logs/guardian.log", func() {
			appendLog("[hook-guardian] warn: replaced the restore record in " + filepath.Join(runTemp, "TestX", "001") + "\n")
		}},
		{"a log line naming the run's registry sandbox", "logs/guardian.log", func() {
			appendLog(`[hook-guardian] marker HKCU\Software\DefenseClaw-test-42\Enterprise` + "\n")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reset()
			before := snapshot(nil)
			servicePass()
			tc.write()
			changes := strings.Join(diffTestMachineRegistry(before, snapshot(before)), "\n")
			if !strings.Contains(changes, path(tc.want)) {
				t.Fatalf("the guard missed %s in %s:\n%s", tc.name, tc.want, changes)
			}
			if strings.Contains(changes, "audit.db") {
				t.Fatalf("the guard reports the left-out data folder:\n%s", changes)
			}
		})
	}
}

// GAP-0093 review S1: a service log larger than testServiceFileHashLimit is
// still compared by content (the guardian's log is never rotated), and a
// marker the run's tail names across the scanner's write boundaries is
// still seen.
func TestTestMachineServiceLogOverTheHashLimitIsComparedByContent(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "logs", "hook-guardian.log")
	if err := os.MkdirAll(filepath.Dir(log), 0o700); err != nil {
		t.Fatal(err)
	}
	line := []byte("[hook-guardian] reconcile reason=interval status=ok users=3\n")
	big := bytes.Repeat(line, testServiceFileHashLimit/len(line)+4096)
	if len(big) <= testServiceFileHashLimit {
		t.Fatalf("fixture log is %d bytes, not over the %d byte limit", len(big), testServiceFileHashLimit)
	}
	runTemp := filepath.Join(dir, "defenseclaw-cli-test-4242")
	markers := []string{runTemp, `Software\DefenseClaw-test-42`}
	reset := func() {
		t.Helper()
		if err := os.WriteFile(log, big, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	appendLog := func(text []byte) {
		t.Helper()
		file, err := os.OpenFile(log, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write(text); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	snapshot := func(before map[string]string) map[string]string {
		out := map[string]string{}
		fingerprintTestServiceFolders(out, testServiceFolders{roots: []string{filepath.Dir(log)}, before: before, runMarkers: markers})
		return out
	}

	reset()
	before := snapshot(nil)
	if got := before["file "+log]; !strings.HasPrefix(got, fmt.Sprintf("service log %d ", len(big))) {
		t.Fatalf("a %d byte log is fingerprinted as %q, not by its content", len(big), got)
	}
	time.Sleep(20 * time.Millisecond) // a later modification time
	appendLog(bytes.Repeat(line, 3))
	if changes := diffTestMachineRegistry(before, snapshot(before)); len(changes) != 0 {
		t.Fatalf("the guardian's own lines appended to a log over the limit are reported:\n%s", strings.Join(changes, "\n"))
	}

	// A tail longer than one copy buffer (32 KiB) that names the run where
	// two writes to the scanner meet: the run's folder (in upper case) starts
	// in the first 32768 bytes of the tail and ends in the second chunk
	// (GAP-0093, review 2 L1).
	marker := strings.ToUpper(runTemp)
	straddle := append(bytes.Repeat([]byte("x"), 32<<10-len(marker)/2), []byte(marker+`\TestX\001`+"\n")...)
	if at := bytes.Index(straddle, []byte(marker)); at >= 32<<10 || at+len(marker) <= 32<<10 {
		t.Fatalf("the run's folder (%d bytes) at byte %d does not straddle byte %d", len(marker), at, 32<<10)
	}
	for _, tc := range []struct {
		name  string
		write func()
	}{
		{"a line naming the run's temp folder", func() { appendLog([]byte("[hook-guardian] warn: " + filepath.Join(runTemp, "TestX", "001") + "\n")) }},
		{"a long tail naming the run across a write boundary", func() { appendLog(straddle) }},
		{"a rewritten earlier byte", func() {
			file, err := os.OpenFile(log, os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.WriteAt([]byte("X"), int64(len(big)/2)); err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
		}},
		{"a truncated log", func() {
			if err := os.Truncate(log, int64(len(big)-len(line))); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reset()
			before := snapshot(nil)
			tc.write()
			if changes := diffTestMachineRegistry(before, snapshot(before)); len(changes) != 1 || !strings.Contains(changes[0], log) {
				t.Fatalf("the guard missed %s in a log over the limit:\n%s", tc.name, strings.Join(changes, "\n"))
			}
		})
	}
}
