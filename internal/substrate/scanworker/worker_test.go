// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanworker

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// startWorker serves w on a socket in a short temp folder.
func startWorker(t *testing.T, w *Worker) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "dcsw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	w.Dir = dir
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = w.Serve(ctx) }()
	for i := 0; i < 200; i++ {
		if _, err := os.Stat(filepath.Join(dir, scanner.ScanSocketName)); err == nil {
			return dir
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("worker did not start")
	return ""
}

func skillDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := os.WriteFile(filepath.Join(d, "SKILL.md"), []byte("---\nname: x\n---\nhi"), 0o600); err != nil {
		t.Fatal(err)
	}
	return d
}

func cleanScan(_ context.Context, kind, dir string, _ scanner.RemoteSettings) (*scanner.ScanResult, error) {
	return &scanner.ScanResult{Scanner: kind}, nil
}

func TestScanWorkerRefusesLinkInJob(t *testing.T) {
	var ran atomic.Bool
	dir := startWorker(t, &Worker{Scan: func(ctx context.Context, k, d string, s scanner.RemoteSettings) (*scanner.ScanResult, error) {
		ran.Store(true)
		return cleanScan(ctx, k, d, s)
	}})
	job := "0123456789abcdef0123456789abcdef"
	jd := filepath.Join(dir, scanner.ScanJobsDirName, job)
	if err := os.MkdirAll(jd, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(jd, "SKILL.md")); err != nil {
		t.Fatal(err)
	}
	ans := post(t, dir, scanner.RemoteScanRequest{Job: job, Kind: "skill"})
	if ans.Code != "refused" || ran.Load() {
		t.Fatalf("a job with a link: code=%q ran=%v", ans.Code, ran.Load())
	}
	if _, err := os.Lstat(jd); err == nil {
		t.Fatal("the refused job was not deleted")
	}
}

func TestScanWorkerBadJobID(t *testing.T) {
	dir := startWorker(t, &Worker{Scan: cleanScan})
	for _, job := range []string{"", "../etc", "0123456789ABCDEF0123456789ABCDEF", "0123"} {
		if ans := post(t, dir, scanner.RemoteScanRequest{Job: job, Kind: "skill"}); ans.Code != "refused" {
			t.Fatalf("job %q: code=%q", job, ans.Code)
		}
	}
	if ans := post(t, dir, scanner.RemoteScanRequest{Job: "0123456789abcdef0123456789abcdef", Kind: "exe"}); ans.Code != "refused" {
		t.Fatalf("bad kind: code=%q", ans.Code)
	}
}

// A full worker makes a scan wait inside its timeout, then answer timeout,
// which the gateway treats as an outage (the fail mode), never an allow.
func TestScanWorkerQueueFullWaitsNotAllows(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	var started atomic.Int32
	dir := startWorker(t, &Worker{Slots: 1, Queue: 1, Timeout: 300 * time.Millisecond,
		Scan: func(ctx context.Context, k, d string, s scanner.RemoteSettings) (*scanner.ScanResult, error) {
			started.Add(1)
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			return cleanScan(ctx, k, d, s)
		}})
	rs := &scanner.RemoteScanner{Kind: "skill", Dir: dir, Timeout: 300 * time.Millisecond}
	errs := make(chan error, 3)
	for i := 0; i < 3; i++ {
		go func() { _, err := rs.Scan(context.Background(), skillDir(t)); errs <- err }()
	}
	for i := 0; i < 3; i++ {
		if err := <-errs; err == nil || !scanner.Unavailable(err) {
			t.Fatalf("scan %d past a full worker: err=%v (want a timeout the fail mode decides)", i, err)
		}
	}
	if n := started.Load(); n != 1 {
		t.Fatalf("%d scans ran with one slot", n)
	}
}

func TestScanWorkerTimeout(t *testing.T) {
	dir := startWorker(t, &Worker{Timeout: 100 * time.Millisecond,
		Scan: func(ctx context.Context, _, _ string, _ scanner.RemoteSettings) (*scanner.ScanResult, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}})
	rs := &scanner.RemoteScanner{Kind: "skill", Dir: dir, Timeout: 100 * time.Millisecond}
	res, err := rs.Scan(context.Background(), skillDir(t))
	if res != nil || err == nil || !scanner.Unavailable(err) {
		t.Fatalf("slow scan: res=%v err=%v", res, err)
	}
}

// The job the gateway wrote reaches the scanner as regular files, and the
// worker deletes it after the scan.
func TestScanWorkerScansJobAndDeletesIt(t *testing.T) {
	var seen string
	dir := startWorker(t, &Worker{Scan: func(ctx context.Context, k, d string, s scanner.RemoteSettings) (*scanner.ScanResult, error) {
		b, err := os.ReadFile(filepath.Join(d, "SKILL.md"))
		seen = string(b)
		if s.Policy != "strict" {
			t.Errorf("settings did not arrive: %+v", s)
		}
		return &scanner.ScanResult{Scanner: "skill-scanner", Findings: []scanner.Finding{{RuleID: "R1", Severity: scanner.SeverityCritical}}}, err
	}})
	rs := &scanner.RemoteScanner{Kind: "skill", Dir: dir, Settings: scanner.RemoteSettings{Policy: "strict"}}
	src := skillDir(t)
	res, err := rs.Scan(context.Background(), src)
	if err != nil || res == nil || len(res.Findings) != 1 || res.Target != src {
		t.Fatalf("scan: res=%+v err=%v", res, err)
	}
	if seen == "" {
		t.Fatal("the scanner did not read the job's SKILL.md")
	}
	left, _ := os.ReadDir(filepath.Join(dir, scanner.ScanJobsDirName))
	if len(left) != 0 {
		t.Fatalf("%d job folders left", len(left))
	}
}

func TestScanWorkerHealth(t *testing.T) {
	dir := startWorker(t, &Worker{Scan: cleanScan, Version: func(context.Context) (string, error) { return "skill-scanner 2.3.2", nil }})
	h := (&scanner.RemoteScanner{Dir: dir}).Health(context.Background())
	if !h.Ready || h.Version != "skill-scanner 2.3.2" {
		t.Fatalf("health: %+v", h)
	}
	gone := (&scanner.RemoteScanner{Dir: t.TempDir()}).Health(context.Background())
	if gone.Ready || gone.Error == "" {
		t.Fatalf("no sidecar: %+v", gone)
	}
}

func post(t *testing.T, dir string, req scanner.RemoteScanRequest) scanner.RemoteScanAnswer {
	t.Helper()
	body, _ := json.Marshal(req)
	resp, err := scanner.ScanClient(dir).Post("http://scan/v1/scan", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var a scanner.RemoteScanAnswer
	if err := json.NewDecoder(resp.Body).Decode(&a); err != nil {
		t.Fatal(err)
	}
	return a
}
