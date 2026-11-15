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

package gateway

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// The live source of `explain --input` / `--last`: every decision the Rego
// cascade policy set, or failed on, or that a floor raised after it, is kept
// with its policy input (input v1 carries no prompt, argument, evidence or
// file content) in <data_dir>/cascade-decisions.jsonl, owner-only. A full
// file (maxCascadeRecordBytes) moves to .1, replacing the older one. Writes
// are asynchronous and bounded: the hook path only enqueues, and a record
// that finds the queue full is dropped and counted.

// CascadeDecisionsFile is the decision record in the data directory.
const CascadeDecisionsFile = "cascade-decisions.jsonl"

const (
	maxCascadeRecordBytes = 1 << 20
	cascadeRecordQueue    = 256
)

// CascadeDecisionRecord is one recorded decision.
type CascadeDecisionRecord struct {
	Time      string         `json:"time"`
	Connector string         `json:"connector"`
	Surface   string         `json:"surface"`
	Live      CascadeOutcome `json:"live"`
	Input     map[string]any `json:"input"`
}

type cascadeRecordJob struct {
	path string
	line []byte
}

var (
	cascadeRecordOnce    sync.Once
	cascadeRecordCh      chan cascadeRecordJob
	cascadeRecordPending sync.WaitGroup
	cascadeRecordDropped atomic.Int64
	cascadeRecordErrOnce sync.Once
)

// recordCascadeDecision enqueues one decision of the policy for the record.
func recordCascadeDecision(cfg *config.Config, connector, surface string, out CascadeOutcome, input map[string]any) {
	if cfg == nil || strings.TrimSpace(cfg.DataDir) == "" {
		return
	}
	line, err := json.Marshal(CascadeDecisionRecord{
		Time: time.Now().UTC().Format(time.RFC3339Nano), Connector: config.NormalizeConnectorName(connector),
		Surface: surface, Live: out, Input: input,
	})
	if err != nil {
		return
	}
	cascadeRecordOnce.Do(func() {
		cascadeRecordCh = make(chan cascadeRecordJob, cascadeRecordQueue)
		go cascadeRecordWriter()
	})
	cascadeRecordPending.Add(1)
	select {
	case cascadeRecordCh <- cascadeRecordJob{path: filepath.Join(cfg.DataDir, CascadeDecisionsFile), line: append(line, '\n')}:
	default:
		cascadeRecordPending.Done()
		cascadeRecordDropped.Add(1)
	}
}

func cascadeRecordWriter() {
	for job := range cascadeRecordCh {
		if err := appendCascadeRecord(job.path, job.line); err != nil {
			cascadeRecordErrOnce.Do(func() {
				fmt.Fprintf(os.Stderr, "[guardrail] could not record a cascade decision in %s: %v (explain --last will not see it)\n", job.path, err)
			})
		}
		cascadeRecordPending.Done()
	}
}

// flushCascadeRecords waits until every enqueued record is written (tests,
// shutdown).
func flushCascadeRecords() { cascadeRecordPending.Wait() }

func appendCascadeRecord(path string, line []byte) error {
	if info, err := os.Stat(path); err == nil && info.Size()+int64(len(line)) > maxCascadeRecordBytes {
		if err := os.Rename(path, path+".1"); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) // #nosec G304 -- the gateway's own data directory.
	if err != nil {
		return err
	}
	_, werr := f.Write(line)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

// ReadCascadeDecision reads the nth most recent recorded decision (1 = the
// latest) from the data directory of cfg.
func ReadCascadeDecision(cfg *config.Config, nth int) (CascadeDecisionRecord, error) {
	if cfg == nil || strings.TrimSpace(cfg.DataDir) == "" {
		return CascadeDecisionRecord{}, errors.New("no data directory")
	}
	if nth < 1 {
		nth = 1
	}
	path := filepath.Join(cfg.DataDir, CascadeDecisionsFile)
	var lines [][]byte
	for _, p := range []string{path + ".1", path} {
		raw, err := os.ReadFile(p) // #nosec G304 -- the gateway's own data directory.
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return CascadeDecisionRecord{}, err
		}
		sc := bufio.NewScanner(bytes.NewReader(raw))
		sc.Buffer(make([]byte, 0, 64<<10), maxCascadeRecordBytes)
		for sc.Scan() {
			if l := bytes.TrimSpace(sc.Bytes()); len(l) > 0 {
				lines = append(lines, bytes.Clone(l))
			}
		}
	}
	if len(lines) < nth {
		return CascadeDecisionRecord{}, fmt.Errorf("%s holds %d recorded decision(s); the gateway records a decision when the cascade policy sets it, fails, or a floor raises it", path, len(lines))
	}
	var rec CascadeDecisionRecord
	if err := json.Unmarshal(lines[len(lines)-nth], &rec); err != nil {
		return CascadeDecisionRecord{}, fmt.Errorf("%s: %w", path, err)
	}
	return rec, nil
}
