// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
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
//
// A repair that has no end line, or that ended in a failure, is neither a
// healthy target nor a no-op. Whether the target is healthy is the worker's
// word and only a completed install gives it; whether the worker put a file
// back is a fact of the files. The parent fingerprints the target's owned
// hook files before it starts the worker (enterpriseHookWorkerRestoreFiles)
// and again once the worker has ended without a healthy answer for a target
// whose repair began: a changed file is a restore, counted, audited and
// recorded, and the target stays failed so that the next pass checks it
// again. A worker that died before it wrote anything leaves no evidence and
// no restore.

// enterpriseHookWorkerProgress is one of those lines.
type enterpriseHookWorkerProgress struct {
	// Repairing: the worker began to repair the protected target Index.
	Repairing bool `json:"repairing,omitempty"`
	Index     int  `json:"index"`
	// Restores, on a begin line: the install rewrites the target's hook
	// files, not only its configuration (the hook runtime being intact), so
	// the parent looks for a restore if the repair does not end healthy.
	Restores bool `json:"restores,omitempty"`
	// Result, on an end line: the target the worker put back. A repair that
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

// begin says a repair of a protected target starts. restores is false when
// the install only changes configuration.
func (w *enterpriseHookWorkerProgressWriter) begin(target enterpriseHookWorkerTarget, restores bool) {
	if w == nil {
		return
	}
	w.emit(enterpriseHookWorkerProgress{Repairing: true, Index: target.Index, Restores: restores})
}

// end says the repair that began has ended, with the target when it put one
// back.
func (w *enterpriseHookWorkerProgressWriter) end(outcome enterpriseHookWorkerTargetResult) {
	progress := enterpriseHookWorkerProgress{Index: outcome.Index}
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
	// restoring holds the targets whose repair began with a restore of their
	// hook files, ended or not.
	restoring map[int]bool
	// repaired holds the targets the worker ended a healthy repair of, by index.
	repaired []enterpriseHookWorkerTargetResult
	// response is the answer, once answered. err is why the output holds none.
	response enterpriseHookWorkerResponse
	answered bool
	err      error
}

// parseEnterpriseHookWorkerOutput reads raw, which may end in the middle of
// a line (the worker is still writing, or was killed).
func parseEnterpriseHookWorkerOutput(raw []byte) (out enterpriseHookWorkerOutput) {
	open := map[int]bool{}
	defer func() {
		if !out.answered {
			out.repairing = len(open)
			slices.SortFunc(out.repaired, func(a, b enterpriseHookWorkerTargetResult) int { return a.Index - b.Index })
		}
	}()
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
		progress := line.Progress
		if progress.Repairing {
			open[progress.Index] = true
			if progress.Restores {
				if out.restoring == nil {
					out.restoring = map[int]bool{}
				}
				out.restoring[progress.Index] = true
			}
			continue
		}
		delete(open, progress.Index)
		if result := progress.Result; result != nil {
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

// enterpriseHookWorkerRestoreFiles holds, by target index, the fingerprints
// of the owned hook files of a protected target before its worker ran.
type enterpriseHookWorkerRestoreFiles map[int]map[string]string

// snapshotEnterpriseHookWorkerRestoreFiles fingerprints the owned files of
// every protected target the worker may repair, for a request that asked for
// progress. The parent reads before and after, so both are read by the
// same account.
func snapshotEnterpriseHookWorkerRestoreFiles(request enterpriseHookWorkerRequest) enterpriseHookWorkerRestoreFiles {
	if !request.Progress {
		return nil
	}
	var files enterpriseHookWorkerRestoreFiles
	var registry *connector.Registry
	for _, target := range request.Targets {
		if target.Mode != enterpriseHookWorkerModeVerifyOrRepair || !target.PreviouslyProtected {
			continue
		}
		if registry == nil {
			registry = newEnterpriseHooksConnectorRegistry()
		}
		owned, err := enterprisehooks.WatchOwnedFiles(target.Options.installOptions(registry))
		if err != nil {
			continue
		}
		before := map[string]string{}
		for _, path := range slices.Concat(owned.ExclusiveWriter, owned.SharedWriter) {
			before[path] = enterpriseHookOwnedFileFingerprint(path)
		}
		if files == nil {
			files = enterpriseHookWorkerRestoreFiles{}
		}
		files[target.Index] = before
	}
	return files
}

// withRestores marks, in results, every target whose repair began with a
// restore, did not end healthy, and left an owned file other than it found
// it: Repaired true, the target otherwise as the worker left it (a target
// with no result of its own is failed with cause). Healthy targets keep what
// their worker said.
func (files enterpriseHookWorkerRestoreFiles) withRestores(results []enterpriseHookWorkerTargetResult, restoring map[int]bool, cause error) []enterpriseHookWorkerTargetResult {
	for _, index := range slices.Sorted(maps.Keys(restoring)) {
		before, ok := files[index]
		if !ok {
			continue
		}
		at := slices.IndexFunc(results, func(r enterpriseHookWorkerTargetResult) bool { return r.Index == index })
		if at >= 0 && (results[at].OK || results[at].Repaired || results[at].Pending) {
			continue
		}
		changed := false
		for path, fingerprint := range before {
			if enterpriseHookOwnedFileFingerprint(path) != fingerprint {
				changed = true
				break
			}
		}
		if !changed {
			continue
		}
		if at >= 0 {
			results[at].Repaired = true
			continue
		}
		message := "the worker ended before it answered for this target"
		if cause != nil {
			message = cause.Error()
		}
		results = append(results, enterpriseHookWorkerTargetResult{Index: index, Repaired: true, Error: message})
	}
	slices.SortFunc(results, func(a, b enterpriseHookWorkerTargetResult) int { return a.Index - b.Index })
	return results
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
