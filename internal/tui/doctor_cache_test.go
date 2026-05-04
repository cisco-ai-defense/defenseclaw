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

package tui

// Unit tests for the P3-#21 doctor cache. Exercise the round-trip
// (save → load), the derived helpers (Age, IsStale, TopFailures,
// SummaryLine, FormatAge) and compatibility with the Python CLI's
// on-disk format — including the RFC3339 `Z`-suffixed timestamp we
// emit from cmd_doctor.py's _write_doctor_cache helper.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDoctorCache_IsEmpty(t *testing.T) {
	t.Parallel()
	var nilCache *DoctorCache
	if !nilCache.IsEmpty() {
		t.Fatalf("nil cache should be empty")
	}
	var zero DoctorCache
	if !zero.IsEmpty() {
		t.Fatalf("zero-value cache should be empty")
	}
	c := &DoctorCache{Passed: 1}
	if c.IsEmpty() {
		t.Fatalf("cache with passed=1 should not be empty")
	}
}

func TestDoctorCache_AgeAndStale(t *testing.T) {
	t.Parallel()
	var nilCache *DoctorCache
	if nilCache.Age() >= 0 {
		t.Fatalf("nil cache age should be negative, got %v", nilCache.Age())
	}
	if !nilCache.IsStale() {
		t.Fatalf("nil cache should always be stale")
	}

	fresh := &DoctorCache{CapturedAt: time.Now().Add(-5 * time.Minute)}
	if fresh.IsStale() {
		t.Fatalf("5-minute cache should not be stale (StaleAfter=%v)", StaleAfter)
	}
	if age := fresh.Age(); age < 4*time.Minute || age > 6*time.Minute {
		t.Fatalf("fresh cache age = %v, want ~5m", age)
	}

	old := &DoctorCache{CapturedAt: time.Now().Add(-StaleAfter - time.Minute)}
	if !old.IsStale() {
		t.Fatalf("cache older than %v should be stale", StaleAfter)
	}
}

func TestDoctorCache_TopFailures_FailsFirst(t *testing.T) {
	t.Parallel()
	c := &DoctorCache{
		Checks: []DoctorCheck{
			{Status: "pass", Label: "p1"},
			{Status: "warn", Label: "w1"},
			{Status: "fail", Label: "f1"},
			{Status: "skip", Label: "s1"},
			{Status: "fail", Label: "f2"},
			{Status: "warn", Label: "w2"},
		},
	}
	got := c.TopFailures(10)
	want := []string{"f1", "f2", "w1", "w2"}
	if len(got) != len(want) {
		t.Fatalf("len=%d, want %d", len(got), len(want))
	}
	for i, ck := range got {
		if ck.Label != want[i] {
			t.Fatalf("TopFailures[%d] = %q, want %q", i, ck.Label, want[i])
		}
	}
	// Bound respected.
	bounded := c.TopFailures(1)
	if len(bounded) != 1 || bounded[0].Label != "f1" {
		t.Fatalf("bounded top-1 = %+v, want [f1]", bounded)
	}
	// Negative max → empty.
	if got := c.TopFailures(0); len(got) != 0 {
		t.Fatalf("TopFailures(0) = %+v, want empty", got)
	}
}

func TestDoctorCache_SaveLoadRoundtrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	c := &DoctorCache{
		CapturedAt: time.Date(2026, 4, 17, 10, 0, 0, 0, time.UTC),
		Passed:     3,
		Failed:     1,
		Warned:     2,
		Skipped:    0,
		Checks: []DoctorCheck{
			{Status: "pass", Label: "Config", Detail: "/etc/dc"},
			{Status: "fail", Label: "Sidecar", Detail: "unreachable"},
		},
	}
	if err := SaveDoctorCache(dir, c); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := LoadDoctorCache(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got == nil {
		t.Fatalf("load returned nil cache")
		return
	}
	if got.Passed != c.Passed || got.Failed != c.Failed || got.Warned != c.Warned || got.Skipped != c.Skipped {
		t.Fatalf("roundtrip counts differ: %+v vs %+v", got, c)
	}
	if len(got.Checks) != len(c.Checks) {
		t.Fatalf("roundtrip checks differ: %+v", got.Checks)
	}
	if !got.CapturedAt.Equal(c.CapturedAt) {
		t.Fatalf("captured_at changed: %v vs %v", got.CapturedAt, c.CapturedAt)
	}
}

func TestDoctorCache_LoadNotExist_ReturnsNilNil(t *testing.T) {
	t.Parallel()
	got, err := LoadDoctorCache(t.TempDir())
	if err != nil {
		t.Fatalf("expected nil err for missing file, got %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil cache for missing file, got %+v", got)
	}
}

func TestDoctorCache_LoadNoDataDir_ReturnsNilNil(t *testing.T) {
	t.Parallel()
	got, err := LoadDoctorCache("")
	if err != nil {
		t.Fatalf("expected nil err for empty data_dir, got %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil cache for empty data_dir")
	}
}

func TestDoctorCache_LoadMalformedJSON_ReturnsError(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := DoctorCachePath(dir)
	if err := os.WriteFile(path, []byte("not-json"), 0o644); err != nil {
		t.Fatalf("write bad json: %v", err)
	}
	_, err := LoadDoctorCache(dir)
	if err == nil {
		t.Fatalf("expected parse error for malformed JSON")
	}
}

func TestDoctorCache_SaveNoDataDir_Error(t *testing.T) {
	t.Parallel()
	if err := SaveDoctorCache("", &DoctorCache{}); err == nil {
		t.Fatalf("SaveDoctorCache with empty dir should error")
	}
}

func TestDoctorCache_SaveNilCache_Error(t *testing.T) {
	t.Parallel()
	if err := SaveDoctorCache(t.TempDir(), nil); err == nil {
		t.Fatalf("SaveDoctorCache(nil) should error")
	}
}

// TestDoctorCache_SaveStampsCapturedAt ensures we fill in a
// CapturedAt when the caller leaves it zero, so we never persist a
// cache that looks "never captured" to the loader.
func TestDoctorCache_SaveStampsCapturedAt(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	c := &DoctorCache{Passed: 1}
	before := time.Now().Add(-time.Second)
	if err := SaveDoctorCache(dir, c); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := LoadDoctorCache(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.CapturedAt.Before(before) {
		t.Fatalf("captured_at not stamped: %v", got.CapturedAt)
	}
}

// TestDoctorCache_PythonCompatibleTimestamp ensures we can load the
// exact on-disk shape the CLI writes (ISO-8601 with `Z` suffix,
// indent=2, the snake_case keys). This is the wire contract
// between cmd_doctor.py._write_doctor_cache and LoadDoctorCache.
func TestDoctorCache_PythonCompatibleTimestamp(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Exactly what Python produces via isoformat(...).replace("+00:00","Z").
	raw := `{
  "passed": 2,
  "failed": 1,
  "warned": 0,
  "skipped": 3,
  "checks": [
    {"status": "pass", "label": "Config", "detail": "ok"},
    {"status": "fail", "label": "Sidecar", "detail": "unreachable"}
  ],
  "captured_at": "2026-04-17T10:00:00Z"
}`
	if err := os.WriteFile(DoctorCachePath(dir), []byte(raw), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := LoadDoctorCache(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.Passed != 2 || got.Failed != 1 || got.Skipped != 3 {
		t.Fatalf("counts mismatch: %+v", got)
	}
	want := time.Date(2026, 4, 17, 10, 0, 0, 0, time.UTC)
	if !got.CapturedAt.Equal(want) {
		t.Fatalf("captured_at = %v, want %v", got.CapturedAt, want)
	}
}

func TestDoctorCache_AtomicSave_NoPartialFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := SaveDoctorCache(dir, &DoctorCache{Passed: 1}); err != nil {
		t.Fatalf("save: %v", err)
	}
	// After a successful save, there should be exactly one file in
	// the data_dir (the doctor_cache.json) — no lingering tempfile.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	got := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasPrefix(e.Name(), ".doctor_cache.") {
			t.Fatalf("found leftover tempfile: %q", e.Name())
		}
		got++
	}
	if got != 1 {
		t.Fatalf("expected 1 regular file after save, got %d", got)
	}
}

func TestParseDoctorJSON_Success(t *testing.T) {
	t.Parallel()
	raw := []byte(`{
  "passed": 1,
  "failed": 2,
  "warned": 3,
  "skipped": 4,
  "checks": [
    {"status": "pass", "label": "a", "detail": ""},
    {"status": "fail", "label": "b", "detail": "x"}
  ]
}`)
	c, err := ParseDoctorJSON(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if c.Passed != 1 || c.Failed != 2 || c.Warned != 3 || c.Skipped != 4 {
		t.Fatalf("counts mismatch: %+v", c)
	}
	if c.CapturedAt.IsZero() {
		t.Fatalf("CapturedAt must be stamped")
	}
	if len(c.Checks) != 2 {
		t.Fatalf("checks len = %d, want 2", len(c.Checks))
	}
}

func TestParseDoctorJSON_Malformed(t *testing.T) {
	t.Parallel()
	if _, err := ParseDoctorJSON([]byte("not json")); err == nil {
		t.Fatalf("expected error for malformed JSON")
	}
}

func TestFormatAge(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		d    time.Duration
		want string
	}{
		{"never", -1, "never"},
		{"just now", 5 * time.Second, "just now"},
		{"30s", 30 * time.Second, "30s ago"},
		{"59s", 59 * time.Second, "59s ago"},
		{"2m", 2 * time.Minute, "2m ago"},
		{"59m", 59 * time.Minute, "59m ago"},
		{"2h", 2 * time.Hour, "2h ago"},
		{"2d", 48 * time.Hour, "2d ago"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := FormatAge(tc.d); got != tc.want {
				t.Fatalf("FormatAge(%v) = %q, want %q", tc.d, got, tc.want)
			}
		})
	}
}

func TestSortChecksByStatus(t *testing.T) {
	t.Parallel()
	in := []DoctorCheck{
		{Status: "pass", Label: "p1"},
		{Status: "skip", Label: "s1"},
		{Status: "fail", Label: "f1"},
		{Status: "pass", Label: "p2"},
		{Status: "warn", Label: "w1"},
		{Status: "fail", Label: "f2"},
		{Status: "unknown", Label: "u1"},
	}
	got := SortChecksByStatus(in)
	labels := []string{}
	for _, ck := range got {
		labels = append(labels, ck.Label)
	}
	want := []string{"f1", "f2", "w1", "p1", "p2", "s1", "u1"}
	for i, lbl := range labels {
		if lbl != want[i] {
			t.Fatalf("sorted[%d] = %q, want %q (full: %v)", i, lbl, want[i], labels)
		}
	}
	// Stability: original slice untouched.
	if in[0].Label != "p1" {
		t.Fatalf("SortChecksByStatus mutated input")
	}
}

func TestDoctorCache_SummaryLine(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		c    *DoctorCache
		want string
	}{
		{"nil", nil, "no data"},
		{"empty", &DoctorCache{}, "no data"},
		{
			"pass-only",
			&DoctorCache{CapturedAt: time.Now(), Passed: 3},
			"3 pass",
		},
		{
			"mixed",
			&DoctorCache{
				CapturedAt: time.Now(),
				Passed:     3, Failed: 1, Warned: 2, Skipped: 4,
			},
			"3 pass, 1 fail, 2 warn, 4 skip",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.c.SummaryLine(); got != tc.want {
				t.Fatalf("SummaryLine = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDoctorCachePath(t *testing.T) {
	t.Parallel()
	if got := DoctorCachePath(""); got != "" {
		t.Fatalf("DoctorCachePath(\"\") = %q, want empty", got)
	}
	got := DoctorCachePath("/tmp/dc")
	want := filepath.Join("/tmp/dc", "doctor_cache.json")
	if got != want {
		t.Fatalf("DoctorCachePath(/tmp/dc) = %q, want %q", got, want)
	}
}

// TestDoctorCache_ConcurrentReadersSeeAtomicWrite is a lightweight
// sanity check that after SaveDoctorCache returns, the file
// contents are complete JSON rather than a partial write — the
// atomic-rename contract the renderer relies on.
func TestDoctorCache_ConcurrentReadersSeeAtomicWrite(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	c := &DoctorCache{Passed: 5, Failed: 1, Checks: []DoctorCheck{
		{Status: "fail", Label: "x", Detail: "y"},
	}}
	for i := 0; i < 20; i++ {
		if err := SaveDoctorCache(dir, c); err != nil {
			t.Fatalf("save iter %d: %v", i, err)
		}
		raw, err := os.ReadFile(DoctorCachePath(dir))
		if err != nil {
			t.Fatalf("read iter %d: %v", i, err)
		}
		var check DoctorCache
		if err := json.Unmarshal(raw, &check); err != nil {
			t.Fatalf("parse iter %d: %v", i, err)
		}
		if check.Passed != 5 || check.Failed != 1 {
			t.Fatalf("iter %d: unexpected counts %+v", i, check)
		}
	}
}

// TestDoctorCache_SaveReplacesExisting makes sure we overwrite any
// prior cache cleanly — otherwise users who run doctor across
// configuration changes would see stale readings forever.
func TestDoctorCache_SaveReplacesExisting(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := SaveDoctorCache(dir, &DoctorCache{Passed: 1}); err != nil {
		t.Fatalf("first save: %v", err)
	}
	if err := SaveDoctorCache(dir, &DoctorCache{Failed: 7}); err != nil {
		t.Fatalf("second save: %v", err)
	}
	got, err := LoadDoctorCache(dir)
	if err != nil || got == nil {
		t.Fatalf("load: %v / %+v", err, got)
	}
	if got.Passed != 0 || got.Failed != 7 {
		t.Fatalf("expected second save to win, got %+v", got)
	}
}

// TestDoctorCache_LoadCorruptFile_Soft ensures a corrupt file
// produces a plain error (not a panic) so the Update handler can
// surface a toast rather than crashing the TUI.
func TestDoctorCache_LoadCorruptFile_Soft(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(DoctorCachePath(dir), []byte("{bad"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := LoadDoctorCache(dir)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	// The error should mention the cache context so user logs are
	// grep-able, but it must not wrap os.ErrNotExist (we use that
	// sentinel to mean "no file yet").
	if errors.Is(err, os.ErrNotExist) {
		t.Fatalf("corrupt file should not look like ErrNotExist")
	}
	if !strings.Contains(err.Error(), "doctor cache") {
		t.Fatalf("expected context 'doctor cache' in error, got %v", err)
	}
}
