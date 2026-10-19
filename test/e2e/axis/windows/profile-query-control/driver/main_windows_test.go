// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build ignore

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBoundedCaptureDrainsAndRecordsOverflow(t *testing.T) {
	var c capture
	input := strings.Repeat("x", 2*captureLimit)
	if n, err := c.Write([]byte(input)); err != nil || n != len(input) {
		t.Fatal("bounded capture did not drain fixed output")
	}
	value, overflow := c.snapshot()
	if len(value) != captureLimit || !overflow {
		t.Fatal("output bound or overflow evidence lost")
	}
}

func TestStrictCompletionDoesNotAcceptRefusalUnknownShapeOrTrailingOutput(t *testing.T) {
	no := false
	r := childReport{Scope: "fixed_windows_read_only_synthetic_profile_query", Stage: "query_completed",
		Completed: true, Synthetic: true, Environment: true, ThreadIdentity: "absent",
		Classes: &classSummary{WellFormed: true, KnownExact: &no, KnownFold: &no, PrivateExact: &no,
			PrivateFold: &no, TailShape: &no, EqualBase: &no, EqualBaseFold: &no}}
	status := "0x00000000"
	r.KnownHRESULT, r.NativeHRESULT = &status, &status
	encode := func(r childReport) string { b, _ := json.Marshal(r); return string(b) }
	if !completeReport(encode(r)) || completeReport(encode(r)+"{}") {
		t.Fatal("single exact diagnostic report contract failed")
	}
	for _, change := range []func(*childReport){
		func(r *childReport) { r.Completed = false },
		func(r *childReport) { r.Stage = "synthetic_native_folder_query_refused" },
		func(r *childReport) { r.Classes = nil },
		func(r *childReport) { r.WriteCalls = true },
		func(r *childReport) { r.NativeHRESULT = nil },
		func(r *childReport) { r.ThreadIdentity = "thread_token_query_refused" },
	} {
		changed := r
		change(&changed)
		if completeReport(encode(changed)) {
			t.Fatal("refused or unmeasured report became completion")
		}
	}
}

func TestSyntheticImagePinBlocksWritesAndRefusesDifferentBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixed-never-executed.exe")
	data := []byte("fixed synthetic bytes; never executed")
	if os.WriteFile(path, data, 0600) != nil {
		t.Fatal("fresh public fixture write failed")
	}
	digest := sha256.Sum256(data)
	held, err := pinFixedImage(path, hex.EncodeToString(digest[:]), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if file, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
		file.Close()
		held.close()
		t.Fatal("retained helper bytes permit writes")
	}
	if err := held.close(); err != nil {
		t.Fatal(err)
	}
	if held, err := pinFixedImage(path, strings.Repeat("0", 64), int64(len(data))); err == nil {
		held.close()
		t.Fatal("different fixed image hash accepted")
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal("failed admission leaked image custody")
	}
}
