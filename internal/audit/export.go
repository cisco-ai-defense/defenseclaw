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

package audit

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// ExportJSONLOptions configures NDJSON export (v7).
type ExportJSONLOptions struct {
	// IncludeActivity writes activity_events as a second JSONL stream.
	IncludeActivity bool
	// ActivityPath is the output path for activity rows when IncludeActivity is true.
	// Empty means derive from AuditPath by inserting ".activity" before the extension.
	ActivityPath string
}

func (s *Store) ExportJSON(path string, limit int) error {
	events, err := s.ListEvents(limit)
	if err != nil {
		return fmt.Errorf("audit: export json: %w", err)
	}

	data, err := json.MarshalIndent(events, "", "  ")
	if err != nil {
		return fmt.Errorf("audit: marshal json: %w", err)
	}

	if path == "-" || path == "" {
		_, err = os.Stdout.Write(data)
		fmt.Println()
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// ExportJSONL writes one JSON object per line (NDJSON). Audit rows include
// every v7 field present on audit.Event. When opts.IncludeActivity is set,
// activity events are written to opts.ActivityPath (or <audit>.activity.jsonl).
func (s *Store) ExportJSONL(auditPath string, limit int, opts ExportJSONLOptions) error {
	events, err := s.ListEvents(limit)
	if err != nil {
		return fmt.Errorf("audit: export jsonl list: %w", err)
	}
	if err := encodeEventsNDJSON(auditPath, events); err != nil {
		return err
	}
	if !opts.IncludeActivity {
		return nil
	}
	actPath := opts.ActivityPath
	if actPath == "" && auditPath != "" && auditPath != "-" {
		if i := strings.LastIndex(auditPath, "."); i > 0 {
			actPath = auditPath[:i] + ".activity" + auditPath[i:]
		} else {
			actPath = auditPath + ".activity.jsonl"
		}
	}
	rows, err := s.ListActivityEvents(limit)
	if err != nil {
		return fmt.Errorf("audit: export jsonl activity list: %w", err)
	}
	return encodeActivityNDJSON(actPath, rows)
}

func encodeEventsNDJSON(path string, events []Event) error {
	w, err := openNDJSON(path)
	if err != nil {
		return err
	}
	defer w.Close()
	enc := json.NewEncoder(w)
	for _, e := range events {
		if err := enc.Encode(e); err != nil {
			return fmt.Errorf("audit: encode audit row: %w", err)
		}
	}
	return nil
}

func encodeActivityNDJSON(path string, rows []ActivityEventRow) error {
	w, err := openNDJSON(path)
	if err != nil {
		return err
	}
	defer w.Close()
	enc := json.NewEncoder(w)
	for _, e := range rows {
		if err := enc.Encode(e); err != nil {
			return fmt.Errorf("audit: encode activity row: %w", err)
		}
	}
	return nil
}

func openNDJSON(path string) (io.WriteCloser, error) {
	if path == "-" || path == "" {
		return nopCloser{os.Stdout}, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("audit: create ndjson: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("audit: chmod ndjson: %w", err)
	}
	return f, nil
}

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }

func (s *Store) ExportCSV(path string, limit int) error {
	events, err := s.ListEvents(limit)
	if err != nil {
		return fmt.Errorf("audit: export csv: %w", err)
	}

	var f *os.File
	if path == "-" || path == "" {
		f = os.Stdout
	} else {
		var err error
		f, err = os.Create(path)
		if err != nil {
			return fmt.Errorf("audit: create csv: %w", err)
		}
		defer f.Close()
		if err := os.Chmod(path, 0o600); err != nil {
			return fmt.Errorf("audit: chmod csv: %w", err)
		}
	}

	w := csv.NewWriter(f)
	if err := w.Write([]string{"id", "timestamp", "action", "target", "actor", "details", "severity", "run_id"}); err != nil {
		return err
	}
	for _, e := range events {
		if err := w.Write([]string{
			e.ID,
			e.Timestamp.Format("2006-01-02T15:04:05Z"),
			e.Action,
			e.Target,
			e.Actor,
			e.Details,
			e.Severity,
			e.RunID,
		}); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}

// ExportSplunk used to backfill historical events into Splunk HEC. The
// generic audit-sinks system now performs the same job declaratively
// (configure a `splunk_hec` sink, then call `defenseclaw audit replay
// --to-sinks`). The function is intentionally unexported here; the
// replay path lives in internal/cli and constructs sinks from
// config.AuditSink directly.
