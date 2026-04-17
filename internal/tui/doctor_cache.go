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

// P3-#21: Overview "Doctor Status" section backed by a cached copy of
// `defenseclaw doctor --json-output`. The real doctor command probes
// network endpoints and third-party APIs (Anthropic, OpenAI, Splunk,
// OTLP, webhooks, VirusTotal) and is intentionally slow — far too
// slow to call synchronously every time the Overview panel
// re-renders. Instead we:
//
//   1. Store the most recent JSON result on disk next to the config
//      (defenseclaw DOCTOR cache file) with a timestamp.
//   2. Render a compact pass/fail/warn/skip summary plus the top
//      failures on the Overview panel.
//   3. Re-run the CLI in the background on demand (e.g. Ctrl-R over
//      the Overview panel) and update the cache atomically.
//
// The cache is purely advisory — operators can always `defenseclaw
// doctor` directly for the live view — but it gives the TUI a
// reliable "is everything plugged in?" sidebar without needing to
// be an endpoint-probing client itself.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// DoctorCheck mirrors one entry in the CLI's `_DoctorResult.checks`.
// Keys match the Python to_dict() output verbatim so we can unmarshal
// without a translation layer.
type DoctorCheck struct {
	Status string `json:"status"` // pass | fail | warn | skip
	Label  string `json:"label"`
	Detail string `json:"detail"`
}

// DoctorCache is the on-disk / in-memory representation of a cached
// doctor run. The "raw" Doctor JSON is flat (passed/failed/etc. plus
// checks[]); we wrap it with a CapturedAt timestamp so the Overview
// panel can render "last verified 5m ago" without guessing at mtime.
type DoctorCache struct {
	CapturedAt time.Time     `json:"captured_at"`
	Passed     int           `json:"passed"`
	Failed     int           `json:"failed"`
	Warned     int           `json:"warned"`
	Skipped    int           `json:"skipped"`
	Checks     []DoctorCheck `json:"checks"`
}

// IsEmpty returns true when there is no meaningful cached state —
// either nothing on disk yet, or a zero-value value. Render code
// uses this to show a "not yet run" hint instead of a misleading "0
// passed, 0 failed" summary.
func (c *DoctorCache) IsEmpty() bool {
	if c == nil {
		return true
	}
	return c.CapturedAt.IsZero() &&
		c.Passed == 0 && c.Failed == 0 &&
		c.Warned == 0 && c.Skipped == 0 &&
		len(c.Checks) == 0
}

// Age returns how long ago the cache was captured, or -1 if unset.
// A negative duration means "no data" — callers should check
// IsEmpty first.
func (c *DoctorCache) Age() time.Duration {
	if c == nil || c.CapturedAt.IsZero() {
		return -1
	}
	return time.Since(c.CapturedAt)
}

// StaleAfter is the recommended freshness window for the cache. A
// cache older than this is still shown (data is still useful) but
// the renderer flags it with a "stale" hint so operators know to
// re-run doctor. The value matches the practical "a coffee break"
// interval; longer than a `make test`, shorter than an afternoon.
const StaleAfter = 15 * time.Minute

// IsStale reports whether the cache is older than StaleAfter.
func (c *DoctorCache) IsStale() bool {
	if c == nil || c.CapturedAt.IsZero() {
		return true
	}
	return time.Since(c.CapturedAt) > StaleAfter
}

// TopFailures returns up to max failing or warning checks, sorted
// with fails first. This is what the Overview panel shows beneath
// the summary line so an at-a-glance scan answers "what's broken?"
// without making the operator open the full panel.
func (c *DoctorCache) TopFailures(max int) []DoctorCheck {
	if c == nil || max <= 0 {
		return nil
	}
	var fails, warns []DoctorCheck
	for _, ck := range c.Checks {
		switch ck.Status {
		case "fail":
			fails = append(fails, ck)
		case "warn":
			warns = append(warns, ck)
		}
	}
	// Stable ordering: preserve original order within each bucket
	// so the user sees checks in the same order they ran.
	out := append(fails, warns...)
	if len(out) > max {
		out = out[:max]
	}
	return out
}

// doctorCacheFileName is deliberately snake_case so it visually
// matches the other Go-owned artifacts we drop under data_dir
// (audit.db, policies/, etc.). Lives under data_dir, same directory
// as config.yaml; no extra permissions required.
const doctorCacheFileName = "doctor_cache.json"

// DoctorCachePath returns the absolute path to the doctor cache
// file for a given data_dir. Returns "" for an empty input so
// callers can bail out cleanly — we never want to silently write
// into $PWD if the config loader failed to populate data_dir.
func DoctorCachePath(dataDir string) string {
	if dataDir == "" {
		return ""
	}
	return filepath.Join(dataDir, doctorCacheFileName)
}

// LoadDoctorCache reads and parses the cache file. A missing file
// returns (nil, nil) so callers can distinguish "no data yet" from
// "read/parse error". Malformed JSON is treated as a soft failure
// (the TUI logs it and renders the "not yet run" hint) — we don't
// want a corrupt cache to crash the whole panel.
func LoadDoctorCache(dataDir string) (*DoctorCache, error) {
	path := DoctorCachePath(dataDir)
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("tui: read doctor cache: %w", err)
	}
	var c DoctorCache
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("tui: parse doctor cache: %w", err)
	}
	return &c, nil
}

// SaveDoctorCache persists the cache atomically by writing to a
// tempfile in the same directory and renaming over the target. This
// avoids a partially-written JSON blob if the TUI exits mid-write
// (which would otherwise poison the next LoadDoctorCache).
func SaveDoctorCache(dataDir string, c *DoctorCache) error {
	path := DoctorCachePath(dataDir)
	if path == "" {
		return errors.New("tui: no data_dir configured for doctor cache")
	}
	if c == nil {
		return errors.New("tui: nil doctor cache")
	}
	if c.CapturedAt.IsZero() {
		c.CapturedAt = time.Now().UTC()
	}
	// Ensure data_dir exists — on a fresh install the Setup wizard
	// creates it, but tests can call us with a brand-new TempDir.
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return fmt.Errorf("tui: mkdir doctor cache dir: %w", err)
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("tui: marshal doctor cache: %w", err)
	}
	tmp, err := os.CreateTemp(dataDir, ".doctor_cache.*.json")
	if err != nil {
		return fmt.Errorf("tui: tempfile for doctor cache: %w", err)
	}
	tmpPath := tmp.Name()
	// Clean up on error paths.
	defer func() {
		if _, statErr := os.Stat(tmpPath); statErr == nil {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("tui: write doctor cache: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("tui: close doctor cache: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("tui: rename doctor cache: %w", err)
	}
	return nil
}

// ParseDoctorJSON converts a raw `defenseclaw doctor --json-output`
// payload into a DoctorCache. The CLI emits the flat shape
// {passed, failed, warned, skipped, checks[]} — we stamp the
// current time as CapturedAt so callers don't need to do it
// manually. Kept separate from SaveDoctorCache so the background
// goroutine can parse the pipe output before handing the result to
// the UI thread.
func ParseDoctorJSON(raw []byte) (*DoctorCache, error) {
	var flat struct {
		Passed  int           `json:"passed"`
		Failed  int           `json:"failed"`
		Warned  int           `json:"warned"`
		Skipped int           `json:"skipped"`
		Checks  []DoctorCheck `json:"checks"`
	}
	if err := json.Unmarshal(raw, &flat); err != nil {
		return nil, fmt.Errorf("tui: parse doctor json: %w", err)
	}
	return &DoctorCache{
		CapturedAt: time.Now().UTC(),
		Passed:     flat.Passed,
		Failed:     flat.Failed,
		Warned:     flat.Warned,
		Skipped:    flat.Skipped,
		Checks:     flat.Checks,
	}, nil
}

// FormatAge returns a compact human-friendly "5m ago" / "just now"
// string for the cache age. Centralized here so tests can assert on
// the output without threading a clock through the panel renderer.
func FormatAge(d time.Duration) string {
	if d < 0 {
		return "never"
	}
	if d < 30*time.Second {
		return "just now"
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(d.Hours()/24))
}

// SortChecksByStatus returns a copy of checks sorted fail > warn >
// pass > skip, with stable ordering inside each bucket. Only used
// by the expanded doctor modal (future work) and tests — the
// Overview panel uses TopFailures directly.
func SortChecksByStatus(in []DoctorCheck) []DoctorCheck {
	out := make([]DoctorCheck, len(in))
	copy(out, in)
	rank := map[string]int{"fail": 0, "warn": 1, "pass": 2, "skip": 3}
	sort.SliceStable(out, func(i, j int) bool {
		ri, iok := rank[out[i].Status]
		rj, jok := rank[out[j].Status]
		if !iok {
			ri = 99
		}
		if !jok {
			rj = 99
		}
		return ri < rj
	})
	return out
}

// credentialCheckPrefix matches the label the Python CLI emits for
// any required credential that the registry sweep
// (“_check_registry_credentials“ in “cmd_doctor.py“) flags as
// missing: “credential <ENV_NAME>“. Kept as a package-level
// constant so tests and the Overview renderer agree on the exact
// string; changing this requires a coordinated CLI update.
const credentialCheckPrefix = "credential "

// MissingRequiredCredentials returns the env-var names of REQUIRED
// credentials the CLI's doctor sweep flagged as unset in the last
// cached run. Only “fail“ entries produced by the registry sweep
// are included — OPTIONAL / NOT_USED credentials do not surface
// through this helper because they never emit a fail check.
//
// The list preserves the order the CLI emitted the checks in so
// deterministic UIs (notices, e2e snapshots) stay stable across
// runs. A nil or empty cache returns nil.
func (c *DoctorCache) MissingRequiredCredentials() []string {
	if c == nil || len(c.Checks) == 0 {
		return nil
	}
	var out []string
	for _, ck := range c.Checks {
		if ck.Status != "fail" {
			continue
		}
		if !strings.HasPrefix(ck.Label, credentialCheckPrefix) {
			continue
		}
		name := strings.TrimSpace(strings.TrimPrefix(ck.Label, credentialCheckPrefix))
		if name != "" {
			out = append(out, name)
		}
	}
	return out
}

// SummaryLine returns a one-line "3 pass, 2 fail, 1 warn, 1 skip"
// breakdown. Strings are plain (no lipgloss styling) so this helper
// stays usable from tests and non-TTY callers (e.g. the fail
// rendering in a log line).
func (c *DoctorCache) SummaryLine() string {
	if c == nil || c.IsEmpty() {
		return "no data"
	}
	var parts []string
	if c.Passed > 0 {
		parts = append(parts, fmt.Sprintf("%d pass", c.Passed))
	}
	if c.Failed > 0 {
		parts = append(parts, fmt.Sprintf("%d fail", c.Failed))
	}
	if c.Warned > 0 {
		parts = append(parts, fmt.Sprintf("%d warn", c.Warned))
	}
	if c.Skipped > 0 {
		parts = append(parts, fmt.Sprintf("%d skip", c.Skipped))
	}
	if len(parts) == 0 {
		return "no data"
	}
	return strings.Join(parts, ", ")
}
