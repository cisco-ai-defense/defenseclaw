// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// A worker answers once, after its last target. The guardian watch loop
// interrupts a pass for every new file event, and a worker the parent kills
// before that answer takes the evidence of the hook elements it already put
// back with it: the restore is counted, audited and recorded nowhere, and the
// next pass finds everything in order (GAP-0754). So a worker whose parent
// asked for it (enterpriseHookWorkerRequest.Progress) also writes one line to
// its output when it begins to repair a target, and one when it ends. The
// parent keeps those lines when it kills the worker, and does not kill a
// worker that is in the middle of a repair (enterpriseHookWorkerContext).
//
// A restore is a result, never a write. The protected elements of a target are
// its hook entry in the agent config and its hook runtime files
// (enterprisehooks.ProbeHookElements). The worker probes them when it begins
// a repair and again when the install returns, and reports a restore for each
// element that did not match before and matches now (RestoredElements),
// whether or not the target is healthy. A write to a file the agent also
// writes for its own settings, or any other write, that leaves an element as
// it was reports nothing. When the worker ends in the middle of the install,
// the parent has the elements that were broken from the begin line and asks a
// short worker for the account to probe them again (probeUnfinishedRepairs).

// enterpriseHookWorkerProgress is one of those lines.
type enterpriseHookWorkerProgress struct {
	// Repairing: the worker began to repair the protected target Index.
	Repairing bool `json:"repairing,omitempty"`
	Index     int  `json:"index"`
	// Broken, on a begin line: the protected elements that did not match
	// when the install began (enterprisehooks.HookElement*). None when the
	// install only changes configuration, or the elements could not be read.
	Broken []string `json:"broken,omitempty"`
	// Result, on an end line: the target when the repair rewrote it. A repair
	// that ended in a failure without restoring an element leaves it nil.
	Result *enterpriseHookWorkerTargetResult `json:"result,omitempty"`
}

// enterpriseHookWorkerProgressWriter writes progress lines to the worker
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

// begin says a repair of a protected target starts, with the elements that
// did not match before it.
func (w *enterpriseHookWorkerProgressWriter) begin(target enterpriseHookWorkerTarget, broken []string) {
	if w == nil {
		return
	}
	w.emit(enterpriseHookWorkerProgress{Repairing: true, Index: target.Index, Broken: broken})
}

// end says the repair that began has ended, with the target when it rewrote
// it.
func (w *enterpriseHookWorkerProgressWriter) end(outcome enterpriseHookWorkerTargetResult) {
	progress := enterpriseHookWorkerProgress{Index: outcome.Index}
	if outcome.Repaired {
		progress.Result = &outcome
	}
	w.emit(progress)
}

// repairEnterpriseHookTarget puts a protected target back after its check
// found it broken. When the parent asked for progress it reads which
// protected elements did not match before the install (broken, and only when
// the install rewrites hook material, restores) and which of them match once
// it has returned, error or not, and returns those as the restore. Without
// progress nothing is read and no restore is named.
func repairEnterpriseHookTarget(ctx context.Context, progress *enterpriseHookWorkerProgressWriter, target enterpriseHookWorkerTarget, opts enterprisehooks.InstallOptions, restores bool) (enterprisehooks.InstallResult, []string, error) {
	var broken []string
	if progress != nil && restores {
		if before, err := enterpriseHookWorkerProber(ctx, opts); err == nil {
			broken = before.Broken()
		}
	}
	progress.begin(target, broken)
	result, err := reinstallEnterpriseHookTarget(ctx, opts)
	var restored []string
	if len(broken) > 0 {
		if after, probeErr := enterpriseHookWorkerProber(ctx, opts); probeErr == nil {
			restored = restoredHookElements(broken, after)
		}
	}
	return result, restored, err
}

// restoredHookElements returns the elements of broken that match in after, in
// the order of broken. Only the protected elements the guardian knows are
// returned, so a name a worker made up reports nothing.
func restoredHookElements(broken []string, after enterprisehooks.HookElements) []string {
	var restored []string
	for _, name := range broken {
		switch {
		case name == enterprisehooks.HookElementEntry && after.Entry,
			name == enterprisehooks.HookElementRuntime && after.Runtime:
			if !slices.Contains(restored, name) {
				restored = append(restored, name)
			}
		}
	}
	return restored
}

// enterpriseHookWorkerOutput is a worker output as far as it is readable:
// the progress lines, then the answer when it came.
type enterpriseHookWorkerOutput struct {
	// repairing counts the repairs that began and have not ended.
	repairing int
	// unfinished holds, by target index, the protected elements that did not
	// match when a repair began that has not ended.
	unfinished map[int][]string
	// repaired holds the targets the worker ended a repair of that rewrote
	// them, by index.
	repaired []enterpriseHookWorkerTargetResult
	// response is the answer, once answered. err is why the output holds none.
	response enterpriseHookWorkerResponse
	answered bool
	err      error
}

// parseEnterpriseHookWorkerOutput reads raw, which may end in the middle of
// a line (the worker is still writing, or was killed).
func parseEnterpriseHookWorkerOutput(raw []byte) (out enterpriseHookWorkerOutput) {
	open := map[int][]string{}
	defer func() {
		if !out.answered {
			out.repairing = len(open)
			for index, broken := range open {
				if len(broken) == 0 {
					continue
				}
				if out.unfinished == nil {
					out.unfinished = map[int][]string{}
				}
				out.unfinished[index] = broken
			}
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
			open[progress.Index] = progress.Broken
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

// enterpriseHookWorkerPostmortem bounds the worker that reads what a repair
// the parent ended left behind.
var enterpriseHookWorkerPostmortem = 10 * time.Second

// restoresOfEndedWorker returns, for a worker that ended without its answer,
// the targets it restored: those it finished repairing and said so, and those
// whose repair it began and did not finish, read again by a short worker for
// the account (a probe_elements target per repair) because only the result
// tells what the install put back before it ended. A target the second
// worker cannot read reports no restore, and its failure is the cause.
func restoresOfEndedWorker(account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest, output enterpriseHookWorkerOutput, cause error) []enterpriseHookWorkerTargetResult {
	results := slices.Clone(output.repaired)
	var probes []enterpriseHookWorkerTarget
	for _, target := range request.Targets {
		if broken := output.unfinished[target.Index]; len(broken) > 0 && target.Mode == enterpriseHookWorkerModeVerifyOrRepair {
			target.Mode, target.Broken = enterpriseHookWorkerModeProbeElements, broken
			probes = append(probes, target)
		}
	}
	if len(probes) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), enterpriseHookWorkerPostmortem)
		defer cancel()
		message := "the worker ended before it answered for this target"
		if cause != nil {
			message = cause.Error()
		}
		response, err := runEnterpriseHookWorker(ctx, account, enterpriseHookWorkerRequest{
			Operation: enterpriseHookWorkerOpApply, Standalone: request.Standalone, Targets: probes})
		if err != nil {
			fmt.Fprintf(enterpriseHookWorkerLog, "[hook-guardian] warn: could not read what the ended worker of %s restored: %v\n", account.User, err)
		}
		for _, probe := range response.Targets {
			if len(probe.RestoredElements) > 0 && !slices.ContainsFunc(results, func(r enterpriseHookWorkerTargetResult) bool { return r.Index == probe.Index }) {
				results = append(results, enterpriseHookWorkerTargetResult{Index: probe.Index, Repaired: true,
					RestoredElements: probe.RestoredElements, Error: message})
			}
		}
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
