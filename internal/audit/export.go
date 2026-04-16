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
	"os"
)

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
