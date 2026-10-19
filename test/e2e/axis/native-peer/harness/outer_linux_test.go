// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

type failReady struct{}

func (failReady) Write([]byte) (int, error) { return 0, errors.New("fixed readiness failure") }

type mustNotRead struct{ t *testing.T }

func (r mustNotRead) Read([]byte) (int, error) {
	r.t.Fatal("GRANT consumed despite failed READY")
	return 0, io.EOF
}

func TestFixedWorkerRequiresReadyThenOneExactGrant(t *testing.T) {
	for _, grant := range []string{workerGrant, "", "wrong", workerGrant + workerGrant, workerGrant + "x"} {
		var ready bytes.Buffer
		err := readyThenGrant(&ready, strings.NewReader(grant))
		if (err == nil) != (grant == workerGrant) || ready.String() != workerReady {
			t.Fatal("fixed readiness/grant contract broadened")
		}
	}
	if err := readyThenGrant(failReady{}, mustNotRead{t}); err == nil {
		t.Fatal("failed readiness admitted worker")
	}
	// No child image or namespace is created by this wire-only ordering test.
	var ready bytes.Buffer
	reader := &orderedGrant{ready: &ready, reader: strings.NewReader(workerGrant)}
	if err := readyThenGrant(&ready, reader); err != nil {
		t.Fatal(err)
	}
}

type orderedGrant struct {
	ready  *bytes.Buffer
	reader *strings.Reader
}

func (r *orderedGrant) Read(p []byte) (int, error) {
	if r.ready.String() != workerReady {
		return 0, errors.New("read before fixed readiness")
	}
	return r.reader.Read(p)
}

func TestUnreviewedWorkerRegistryRefusesBeforeNativeDescriptors(t *testing.T) {
	record, owner, err := executeWorkerWithRegistry([]string{"--receipt", "missing", "--evidence", "missing"}, reviewedRegistry{})
	if !errors.Is(err, errUnreviewed) || record["execution_performed"] != false || len(owner.pending) != 0 || record["worker_admission_stage"] != "registry" {
		t.Fatal("unreviewed worker reached a native capability")
	}
}

func TestSyntheticWorkerMetadataStageRefusesBeforeNativeDescriptors(t *testing.T) {
	record, owner, err := executeWorkerWithRegistry(nil, syntheticRegistry(t))
	if err == nil || record["worker_admission_stage"] != "metadata" || record["execution_performed"] != false || len(owner.pending) != 0 {
		t.Fatal("invalid synthetic worker metadata reached native descriptors")
	}
}

func TestOuterCustodyCompletedWaitPreferredOverCanceledContext(t *testing.T) {
	done := make(chan struct{})
	close(done)
	o := &outerCustodian{pidfd: -1, done: done, complete: true}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := o.stopAndWait(ctx); err != nil {
		t.Fatal(err)
	}
	pending := &outerCustodian{pidfd: -1, done: make(chan struct{}), starting: true}
	if err := pending.stopAndWait(ctx); !errors.Is(err, context.Canceled) || !pending.closed || !pending.starting {
		t.Fatal("pending kernel start lost retained cleanup state")
	}
}

func TestOuterCaptureBoundsBytesWithoutExecutingImage(t *testing.T) {
	b := &boundedCapture{}
	if _, err := b.Write(bytes.Repeat([]byte{'x'}, outputLimit)); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Write([]byte{'y'}); err == nil {
		t.Fatal("oversized child capture accepted")
	}
	data, overflow := b.snapshot()
	if len(data) != outputLimit || !overflow {
		t.Fatal("bounded capture observation differs")
	}
}

func TestNativeStartErrnoEvidenceUsesOnlyFixedClassification(t *testing.T) {
	for _, item := range []struct {
		err  error
		want string
	}{{nil, "none"}, {&os.PathError{Op: "private", Path: "/synthetic/private-path", Err: unix.EPERM}, "eperm"},
		{errors.Join(errors.New("private details"), unix.EACCES), "eacces"}, {context.Canceled, "cancelled"},
		{errors.New("arbitrary exception details"), "other"}} {
		if got := startErrnoClass(item.err); got != item.want {
			t.Fatalf("fixed classification differs: %q", got)
		}
	}
}

func TestProcPIDViewDistinguishesMismatchFromUnavailableWithoutNativeCalls(t *testing.T) {
	for _, item := range []struct {
		link               string
		pid                int
		err                error
		available, matches bool
	}{{"1", 1, nil, true, true}, {"41", 1, nil, true, false}, {"", 1, nil, false, false},
		{"1", 1, errors.New("fixed read error"), false, false}, {"01", 1, nil, false, false},
		{"12345678901", 1, nil, false, false}, {"/synthetic/private-path", 1, nil, false, false}} {
		available, matches := procSelfPIDView(item.link, item.pid, item.err)
		if available != item.available || matches != item.matches {
			t.Fatal("proc PID view classification differs")
		}
	}
}

func TestEarlyWorkerFailureRetainsBoundedDiagnosticsAfterObservation(t *testing.T) {
	owner := &outerCustodian{pidfd: -1, complete: true, exit: 1, startStage: "exec_start_refused", startErrno: "eperm"}
	stdout, stderr := &boundedCapture{}, &boundedCapture{}
	_, _ = stdout.Write([]byte("fixed worker admission JSON\n"))
	_, _ = stderr.Write(bytes.Repeat([]byte{'x'}, outputLimit))
	_, _ = stderr.Write([]byte("overflow"))
	record := map[string]any{"passed": false, "execution_performed": false}
	retainWorkerObservation(record, owner, stdout, stderr)
	if record["worker_start_stage"] != "exec_start_refused" || record["worker_start_errno"] != "eperm" ||
		record["worker_native_wait_complete"] != false || record["owned_worker_exit_code"] != 1 ||
		record["owned_worker_stdout"] != "fixed worker admission JSON\n" || record["owned_worker_stderr_truncated"] != true ||
		len(record["owned_worker_stderr"].(string)) != outputLimit || record["passed"] != false || record["execution_performed"] != false {
		t.Fatal("early failure evidence was lost or became success")
	}
	owner.started = true
	retainWorkerObservation(record, owner, stdout, stderr)
	if record["worker_native_wait_complete"] != true {
		t.Fatal("completed owned native wait was not distinguished from pre-exec refusal")
	}
}
