// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func restartProofRow(t *testing.T, home string) map[string]string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(home, "logs", "hook-failures.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var row map[string]string
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(data))), &row); err != nil {
		t.Fatal(err)
	}
	return row
}

// TestGAP0295NoAnswerRecordsProofReason is the base regression: a no-answer
// row records why it did not qualify for the per-user restart window.
func TestGAP0295NoAnswerRecordsProofReason(t *testing.T) {
	stubRestartWindowProof(t, false)
	opts, sp, _ := restartWindowCall(t, "open", false, nil)
	if _, ok := failPerUserRestartWindow(answerDeadlineEnded(), opts, sp, "open"); ok {
		t.Fatal("rejected proof took the restart answer")
	}
	_ = failNoAnswer(opts, sp, "closed")
	row := restartProofRow(t, opts.Home)
	if row["restart_proof"] != "proof_rejected" || row["outcome"] != "fail_closed" {
		t.Fatalf("no-answer row = %+v, want the rejected proof and closed outcome", row)
	}
}

func TestGAP0295RestartProofFieldIsPerUserOnly(t *testing.T) {
	for _, tc := range []struct {
		name         string
		mutate       func(*Options)
		failOpenOnly bool
	}{
		{"managed socket", func(o *Options) { o.ManagedUnixSocket = "/not-used-by-test/hook.sock" }, false},
		{"Secure Client", func(o *Options) { o.SecureClient = true }, false},
		{"fail-open-only connector", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts, sp, _ := restartWindowCall(t, "open", false, tc.mutate)
			sp.failOpenOnly = tc.failOpenOnly
			opts.failureLog.setRestartReason("no_holder")
			logHookFailure(opts, sp, perUserGatewayNoAnswerReason, "transport", "closed", true)
			if row := restartProofRow(t, opts.Home); row["restart_proof"] != "" {
				t.Fatalf("non-per-user no-answer row has restart proof: %+v", row)
			}
		})
	}
}

func TestGAP0295WatchdogNoAnswerRecordsProofReason(t *testing.T) {
	previous := perUserRestartWindowProof
	perUserRestartWindowProof = func(string, *perUserPeerCheck) restartProofResult {
		return restartProofResult{reason: "no_holder"}
	}
	t.Cleanup(func() { perUserRestartWindowProof = previous })
	opts, _, w := restartWindowCall(t, "open", false, nil)
	// Without an exit callback, the watchdog writes its row before returning.
	w.exit = nil
	w.watch(time.Now())
	row := restartProofRow(t, opts.Home)
	if row["restart_proof"] != "no_holder" || row["outcome"] != "fail_closed" {
		t.Fatalf("watchdog no-answer row = %+v", row)
	}
}

func TestGAP0295NoAnswerReasonTaxonomy(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		proof        restartProofResult
		modeNotReady bool
		timeout      bool
	}{
		{"not fresh", "not_fresh", restartProofResult{reason: "not_fresh"}, false, false},
		{"no holder", "no_holder", restartProofResult{reason: "no_holder"}, false, false},
		{"answered before", "answered_before", restartProofResult{reason: "answered_before"}, false, false},
		{"mode not ready", "outage_mode_not_ready", restartProofResult{ok: true}, true, false},
		{"proof timeout", "proof_timeout", restartProofResult{ok: true}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proofDone := make(chan struct{}, 1)
			releaseProof := make(chan struct{})
			if tc.timeout {
				defer close(releaseProof)
			}
			previous := perUserRestartWindowProof
			perUserRestartWindowProof = func(string, *perUserPeerCheck) restartProofResult {
				if tc.timeout {
					<-releaseProof
					proofDone <- struct{}{}
				}
				return tc.proof
			}
			t.Cleanup(func() { perUserRestartWindowProof = previous })
			t.Cleanup(func() {
				if tc.timeout {
					select {
					case <-proofDone:
					case <-time.After(time.Second):
						t.Error("timed-out proof did not finish")
					}
				}
			})
			previousWait := restartProofWait
			if tc.timeout {
				restartProofWait = 5 * time.Millisecond
			}
			t.Cleanup(func() { restartProofWait = previousWait })
			opts, sp, w := restartWindowCall(t, "open", false, nil)
			if tc.modeNotReady {
				w.mu.Lock()
				w.restart, w.restartChoice = nil, nil
				w.mu.Unlock()
			}
			if _, ok := failPerUserRestartWindow(answerDeadlineEnded(), opts, sp, "open"); ok {
				t.Fatal("unproven call took the restart answer")
			}
			logged := opts
			logged.answerWatch = nil
			logHookFailure(logged, sp, perUserGatewayNoAnswerReason, "transport", "closed", true)
			if row := restartProofRow(t, opts.Home); row["restart_proof"] != tc.reason {
				t.Fatalf("restart proof reason = %q, want %q", row["restart_proof"], tc.reason)
			}
		})
	}
}

func TestGAP0295ProvenRestartKeepsOutageAnswer(t *testing.T) {
	stubRestartWindowProof(t, true)
	opts, sp, _ := restartWindowCall(t, "open", false, nil)
	if _, ok := failPerUserRestartWindow(answerDeadlineEnded(), opts, sp, "open"); !ok {
		t.Fatal("proven restart did not take the outage answer")
	}
	row := restartProofRow(t, opts.Home)
	if row["outcome"] != "fail_open" || row["restart_proof"] != "" {
		t.Fatalf("proven restart row = %+v, want the open outage without a failure reason", row)
	}
}
