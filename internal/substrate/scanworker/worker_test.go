// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanworker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"testing/synctest"
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

// skipSidecarClientOnWindows skips a test that sends a job through
// scanner.RemoteScanner. The scanner sidecar is Linux only (the chart's
// container; processutil.PodRunner refuses everywhere else, see
// TestGAP1035PodRunnerRefusesOffLinux), and the client refuses every Windows
// folder because Windows reports mode 0777 for all of them
// (scanner.TestRemoteScannerRefusesEveryScanOnWindows). The tests that post to
// the worker's handler directly still run on Windows.
func skipSidecarClientOnWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the scanner sidecar client is Linux only: it refuses every folder on Windows (GAP-1050)")
	}
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
		if runtime.GOOS == "windows" {
			t.Skipf("a standard Windows user holds no symbolic-link privilege: %v", err)
		}
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

// A full worker keeps excess requests waiting, and an expired request never
// receives an allow result. synctest advances all deadlines together, so a
// later scan cannot begin merely because the first timed out earlier.
func TestScanWorkerQueueFullWaitsNotAllows(t *testing.T) {
	dir := t.TempDir()
	jobs := make([]string, 3)
	for i := range jobs {
		jobs[i] = fmt.Sprintf("%032x", i+1)
		jd := filepath.Join(dir, scanner.ScanJobsDirName, jobs[i])
		if err := os.MkdirAll(jd, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(jd, "SKILL.md"), []byte("---\\nname: queued\\n---\\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	synctest.Test(t, func(t *testing.T) {
		var started atomic.Int32
		w := &Worker{Dir: dir, Slots: 1, Queue: 1, Timeout: 300 * time.Millisecond,
			Scan: func(ctx context.Context, _, _ string, _ scanner.RemoteSettings) (*scanner.ScanResult, error) {
				started.Add(1)
				<-ctx.Done()
				return nil, ctx.Err()
			}}
		handler := w.Handler()
		done := make(chan scanner.RemoteScanAnswer, len(jobs))
		for _, job := range jobs {
			job := job
			go func() {
				body, _ := json.Marshal(scanner.RemoteScanRequest{Job: job, Kind: scanner.RemoteKindSkill})
				req := httptest.NewRequest("POST", "/v1/scan", bytes.NewReader(body))
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				var ans scanner.RemoteScanAnswer
				if err := json.Unmarshal(rec.Body.Bytes(), &ans); err != nil {
					t.Errorf("job %s: bad answer: %v", job, err)
				}
				done <- ans
			}()
		}
		synctest.Wait()
		if got := started.Load(); got != 1 {
			t.Fatalf("full queue started %d concurrent scans, want one", got)
		}
		if len(done) != 0 {
			t.Fatal("a request answered before its timeout while the queue was full")
		}
		time.Sleep(300 * time.Millisecond) // fake clock in the synctest bubble
		synctest.Wait()
		for range jobs {
			ans := <-done
			if ans.Code != "timeout" || ans.Result != nil {
				t.Fatalf("full queue answered %+v, want timeout without result", ans)
			}
		}
	})
}

func TestScanWorkerTimeout(t *testing.T) {
	skipSidecarClientOnWindows(t)
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
	skipSidecarClientOnWindows(t)
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
