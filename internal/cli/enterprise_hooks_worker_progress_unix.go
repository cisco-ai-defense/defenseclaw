// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"sync"
	"time"
)

// A worker answers once, after its last target. The guardian watch loop
// interrupts a pass for every new file event, and a worker the parent kills
// before that answer takes the evidence of the hook files and config entries
// it already put back with it: the restore is counted, audited and recorded
// nowhere, and the next pass finds everything in order (GAP-0754). So a worker
// whose parent asked for it (enterpriseHookWorkerRequest.Progress) also writes
// one line to its output when it begins to repair a target, and one when it
// ends, with the repaired target's result. The parent keeps those results when
// it kills the worker, and does not kill a worker that is in the middle of a
// repair (enterpriseHookWorkerContext).

// enterpriseHookWorkerProgress is one of those lines.
type enterpriseHookWorkerProgress struct {
	// Repairing: the worker began to repair a protected target.
	Repairing bool `json:"repairing,omitempty"`
	// Result ends a repair: the target the worker put back. A repair that
	// ended without one (it failed, or it only changed configuration) leaves
	// it nil.
	Result *enterpriseHookWorkerTargetResult `json:"result,omitempty"`
}

// enterpriseHookWorkerProgressWriter writes progress lines to the worker's
// output. A nil writer drops them: the parent did not ask.
type enterpriseHookWorkerProgressWriter struct {
	mu  sync.Mutex
	out io.Writer
}

type enterpriseHookWorkerProgressKey struct{}

func withEnterpriseHookWorkerProgress(ctx context.Context, out io.Writer) context.Context {
	return context.WithValue(ctx, enterpriseHookWorkerProgressKey{}, &enterpriseHookWorkerProgressWriter{out: out})
}

func enterpriseHookWorkerProgressOf(ctx context.Context) *enterpriseHookWorkerProgressWriter {
	writer, _ := ctx.Value(enterpriseHookWorkerProgressKey{}).(*enterpriseHookWorkerProgressWriter)
	return writer
}

// emit writes one line. A failed write is not reported here: the answer that
// follows uses the same output and reports it.
func (w *enterpriseHookWorkerProgressWriter) emit(progress enterpriseHookWorkerProgress) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	_ = json.NewEncoder(w.out).Encode(enterpriseHookWorkerResponse{Version: enterpriseHookWorkerProtocolVersion, Progress: &progress})
}

// begin says a repair of a protected target starts.
func (w *enterpriseHookWorkerProgressWriter) begin() {
	w.emit(enterpriseHookWorkerProgress{Repairing: true})
}

// end says the repair that began has ended, with the target when it put one
// back.
func (w *enterpriseHookWorkerProgressWriter) end(outcome enterpriseHookWorkerTargetResult) {
	progress := enterpriseHookWorkerProgress{}
	if outcome.OK && outcome.Repaired {
		progress.Result = &outcome
	}
	w.emit(progress)
}

// enterpriseHookWorkerOutput is a worker's output as far as it is readable:
// the progress lines, then the answer when it came.
type enterpriseHookWorkerOutput struct {
	// repairing counts the repairs that began and have not ended.
	repairing int
	// repaired holds the targets the worker ended a repair of, by index.
	repaired []enterpriseHookWorkerTargetResult
	// response is the answer, once answered. err is why the output holds none.
	response enterpriseHookWorkerResponse
	answered bool
	err      error
}

// parseEnterpriseHookWorkerOutput reads raw, which may end in the middle of
// a line (the worker is still writing, or was killed).
func parseEnterpriseHookWorkerOutput(raw []byte) enterpriseHookWorkerOutput {
	var out enterpriseHookWorkerOutput
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	for {
		var line enterpriseHookWorkerResponse
		if err := decoder.Decode(&line); err != nil {
			out.err = err
			return out
		}
		if line.Progress == nil {
			out.response, out.answered = line, true
			return out
		}
		if line.Version != enterpriseHookWorkerProtocolVersion {
			continue
		}
		if line.Progress.Repairing {
			out.repairing++
			continue
		}
		out.repairing = max(out.repairing-1, 0)
		if result := line.Progress.Result; result != nil {
			replaced := false
			for i := range out.repaired {
				if out.repaired[i].Index == result.Index {
					out.repaired[i], replaced = *result, true
				}
			}
			if !replaced {
				out.repaired = append(out.repaired, *result)
			}
		}
	}
}

// enterpriseHookWorkerRepairPoll is how often the parent re-reads the output
// of a worker it would kill, to see whether its repair has ended.
var enterpriseHookWorkerRepairPoll = 25 * time.Millisecond

// workerOutputBuffer is read while the worker still writes it.
func (b *workerOutputBuffer) snapshot() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.buf.Bytes())
}
