// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

const hookFailuresDroppedFile = "hook-failures.dropped"
const hookFailuresDroppedPosition = "hook-failures.dropped.reported"

type droppedFailurePosition struct {
	Offset int64  `json:"offset"`
	Head   string `json:"head"`
}

func readDroppedFailurePosition(logDir string) droppedFailurePosition {
	data, err := os.ReadFile(filepath.Join(logDir, hookFailuresDroppedPosition))
	if err != nil {
		return droppedFailurePosition{}
	}
	var position droppedFailurePosition
	if json.Unmarshal(data, &position) != nil {
		return droppedFailurePosition{}
	}
	return position
}

func writeDroppedFailurePosition(logDir string, position droppedFailurePosition) error {
	data, err := json.Marshal(position)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(logDir, hookFailuresDroppedPosition+".*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(append(data, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(name, filepath.Join(logDir, hookFailuresDroppedPosition))
}

// reportDroppedHookFailuresIn reads the prepared local record when the
// ordinary failure log could not finish before a hook process ended.
func reportDroppedHookFailuresIn(logDir string, logger *audit.Logger) error {
	f, err := os.Open(filepath.Join(logDir, hookFailuresDroppedFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("hook failure marker is not a regular file")
	}
	position := readDroppedFailurePosition(logDir)
	head := hookFailuresHead(f)
	if position.Offset < 0 || position.Offset > info.Size() || (position.Head != "" && position.Head != head) {
		position.Offset = 0
	}
	position.Head = head
	if _, err := f.Seek(position.Offset, io.SeekStart); err != nil {
		return err
	}
	reader := bufio.NewReader(io.LimitReader(f, hookFailOpenReportMaxBytes))
	rows := make([]audit.HookFailureAuditRow, 0, hookFailureBatchSize)
	ends := make([]int64, 0, hookFailureBatchSize)
	last := position.Offset
	flush := func() error {
		if len(rows) == 0 {
			return nil
		}
		settled, err := logger.LogHookFailureRowsAtomic(context.Background(), rows)
		if settled > 0 {
			position.Offset = ends[settled-1]
			if saveErr := writeDroppedFailurePosition(logDir, position); saveErr != nil {
				return saveErr
			}
		}
		rows, ends = rows[:0], ends[:0]
		if err != nil {
			return err
		}
		time.Sleep(hookFailureLiveYield)
		return nil
	}
	for seen := 0; seen < hookFailureRowsPerReport; {
		line, readErr := reader.ReadBytes('\n')
		if len(line) == 0 || line[len(line)-1] != '\n' {
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				return readErr
			}
			break
		}
		last += int64(len(line))
		if len(line) > 4096 || !bytes.HasPrefix(line, []byte("DCID")) {
			continue
		}
		var entry hookFailureLine
		if json.Unmarshal(line[4:], &entry) != nil || strings.TrimSpace(entry.Connector) == "" {
			continue
		}
		if _, parseErr := time.Parse(time.RFC3339, strings.TrimSpace(entry.TS)); parseErr != nil {
			continue
		}
		entry.Connector = strings.ToLower(strings.TrimSpace(entry.Connector))
		blocked := entry.blockedByHook()
		if !blocked && !entry.ranUnchecked() {
			continue
		}
		call := hookFailureCall{entry: entry, end: last, blocked: blocked}
		action, target, details, severity := hookFailureRow(call)
		details = strings.ReplaceAll(details, hookFailuresFile, hookFailuresDroppedFile)
		rows = append(rows, audit.HookFailureAuditRow{
			Envelope: audit.CorrelationEnvelope{Connector: entry.Connector, SessionID: entry.SessionID,
				RequestID: entry.CallID, ToolID: entry.ToolID},
			Action: action, Target: target, Details: details, Severity: severity,
		})
		ends = append(ends, last)
		seen++
		if len(rows) == hookFailureBatchSize {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	if err := flush(); err != nil {
		return err
	}
	if position.Offset != last {
		position.Offset = last
		return writeDroppedFailurePosition(logDir, position)
	}
	return nil
}
