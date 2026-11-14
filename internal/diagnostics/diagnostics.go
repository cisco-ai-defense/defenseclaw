// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package diagnostics owns the support-safe summary folder under the data
// directory. Support bundles collect every *.json file in that folder with a
// single wildcard, so a feature can make its state collectable by writing a
// file here instead of changing the collection manifest.
//
// The folder is an allow-list by construction: nothing else under the data
// directory (audit databases, judge bodies, keys) is collected, and every
// file here must be registered once with Register. Files must carry metadata
// only: states, codes, counts, timestamps and versions. No tokens, prompt or
// tool content, raw error text or email addresses.
package diagnostics

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

const (
	// DirName is the folder name under the data directory.
	DirName = "diagnostics"
	// MaxFileBytes bounds one encoded file.
	MaxFileBytes = 256 << 10
	// MaxFiles bounds the number of *.json files in the folder.
	MaxFiles = 32
	// MaxTotalBytes bounds the folder's *.json files together.
	MaxTotalBytes = 2 << 20
)

// HealthReportFile is the gateway's last endpoint health report. Its shape is
// HealthReportFileContent.
const HealthReportFile = "health_report_last.json"

// HealthReportFileVersion is the HealthReportFileContent schema version.
const HealthReportFileVersion = 1

// HealthReportFileContent is what the gateway writes to HealthReportFile
// after every report it builds, and what status commands read back. Report
// is the report body, keyed by its defenseclaw.health.* attribute names.
type HealthReportFileContent struct {
	SchemaVersion int             `json:"schema_version"`
	BuiltAt       string          `json:"built_at"`
	Report        json.RawMessage `json:"report"`
	Delivery      HealthDelivery  `json:"delivery"`
}

// HealthDelivery is the outcome of handing the report to telemetry. Result is
// "queued" when the record was accepted for export, "not_routed" when no
// managed destination took it, or "failed"; FailureClass is a bounded code,
// never raw error text. CloudState and CloudLastSuccessAt are the managed
// destination's own health at build time.
type HealthDelivery struct {
	Result             string `json:"result"`
	At                 string `json:"at"`
	FailureClass       string `json:"failure_class,omitempty"`
	CloudState         string `json:"cloud_state,omitempty"`
	CloudLastSuccessAt string `json:"cloud_last_success_at,omitempty"`
}

var (
	namePattern = regexp.MustCompile(`^[a-z0-9_]+\.json$`)

	registryMu sync.RWMutex
	registry   = map[string]string{}

	// writeMu serializes the limit check and the write, so two writers in
	// one process cannot both pass the folder budget.
	writeMu sync.Mutex
)

// ErrUnregistered is returned for a write to a name that was never registered.
var ErrUnregistered = errors.New("diagnostics: file name is not registered")

// ErrLimit is returned when a write would exceed a per-file or folder limit.
// The existing file, if any, is left unchanged.
var ErrLimit = errors.New("diagnostics: write exceeds the folder limits")

// Register declares a file name and its owning component. It panics on an
// invalid or duplicate name, so a mistake fails at process start and in tests.
func Register(name, owner string) {
	if !namePattern.MatchString(name) {
		panic(fmt.Sprintf("diagnostics: invalid file name %q", name))
	}
	if strings.TrimSpace(owner) == "" {
		panic(fmt.Sprintf("diagnostics: file %q has no owner", name))
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	if existing, ok := registry[name]; ok {
		panic(fmt.Sprintf("diagnostics: file %q already registered by %s", name, existing))
	}
	registry[name] = owner
}

// Registered returns the registered file names, sorted.
func Registered() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func registered(name string) bool {
	registryMu.RLock()
	defer registryMu.RUnlock()
	_, ok := registry[name]
	return ok
}

// Dir returns the diagnostics folder for a data directory.
func Dir(dataDir string) string {
	return filepath.Join(dataDir, DirName)
}

// Path returns the path of a diagnostics file for a data directory.
func Path(dataDir, name string) string {
	return filepath.Join(Dir(dataDir), name)
}

// WriteJSON encodes value as indented JSON and atomically replaces the named
// file. The temporary file does not match *.json, so a collector never sees a
// partial file. A write that would exceed a limit fails without truncating.
func WriteJSON(dataDir, name string, value any) error {
	if strings.TrimSpace(dataDir) == "" {
		return errors.New("diagnostics: empty data directory")
	}
	if !registered(name) {
		return fmt.Errorf("%w: %s", ErrUnregistered, name)
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("diagnostics: encode %s: %w", name, err)
	}
	data = append(data, '\n')
	if len(data) > MaxFileBytes {
		return fmt.Errorf("%w: %s is %d bytes, limit %d", ErrLimit, name, len(data), MaxFileBytes)
	}

	writeMu.Lock()
	defer writeMu.Unlock()
	dir := Dir(dataDir)
	count, total, err := folderUsage(dir, name)
	if err != nil {
		return err
	}
	if count+1 > MaxFiles || total+int64(len(data)) > MaxTotalBytes {
		return fmt.Errorf("%w: folder would hold %d files and %d bytes", ErrLimit, count+1, total+int64(len(data)))
	}
	if err := safefile.Write(filepath.Join(dir, name), data); err != nil {
		return fmt.Errorf("diagnostics: write %s: %w", name, err)
	}
	return nil
}

// folderUsage counts the *.json files other than skip and their total size.
// A missing folder is empty.
func folderUsage(dir, skip string) (int, int64, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return 0, 0, nil
	}
	if err != nil {
		return 0, 0, fmt.Errorf("diagnostics: read folder: %w", err)
	}
	var count int
	var total int64
	for _, entry := range entries {
		name := entry.Name()
		if name == skip || !entry.Type().IsRegular() || !strings.HasSuffix(name, ".json") {
			continue
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			continue
		}
		count++
		total += info.Size()
	}
	return count, total, nil
}
