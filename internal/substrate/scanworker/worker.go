// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// Package scanworker is the Agent Substrate scanner sidecar
// (`defenseclaw-gateway substrate scan-worker`, GAP-0477). It runs in its own
// container of the gateway pod, with no Secret mounts, no service-account
// token and no listener but a 0600 unix socket in the shared emptyDir. It
// runs skill-scanner and the plugin scanner from the release's scanner
// runtime on job folders the gateway wrote, and answers the ScanResult; the
// gateway decides with its own policy.
//
// In the chart's sidecar the worker runs in the pod-contained mode (Pod,
// GAP-0828): a container's default seccomp profile refuses the namespaces the
// scanner's usual containment needs, so the container is the boundary and the
// worker, its PID 1, runs one scanner at a time and clears the container
// after each job.
package scanworker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/processutil"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// RuntimeLauncher is the scanner runtime launcher in the scanner image (the
// managed Linux package layout, which the image copies from the release).
const RuntimeLauncher = "/opt/defenseclaw/bin/defenseclaw-scanners"

const (
	defaultSlots = 2
	defaultQueue = 32
	maxRequest   = 1 << 20
	maxJobFiles  = 4096
)

// ScanFunc runs one scan of dir; a seam for tests.
type ScanFunc func(ctx context.Context, kind, dir string, st scanner.RemoteSettings) (*scanner.ScanResult, error)

// Worker serves POST /v1/scan and GET /v1/health on Dir/scan.sock.
type Worker struct {
	Dir     string
	Timeout time.Duration
	Slots   int
	Queue   int
	Scan    ScanFunc
	// Launcher is the scanner runtime launcher RuntimeScanner runs (default
	// RuntimeLauncher).
	Launcher string
	// Version reports the scanner runtime's version ("" and an error when
	// it cannot run).
	Version func(ctx context.Context) (string, error)
	// Pod is the pod-contained mode (GAP-0828); nil keeps the scanner's
	// namespace containment, which fails closed where namespaces are
	// refused. With Pod the worker runs one job at a time, scans with
	// Pod.Run, and Pod.Reset ends every job and health check.
	Pod *processutil.PodRunner

	admit chan struct{}
	run   chan struct{}
	// fatal ends Serve with an error: a container the worker could not
	// clear after a job, or a socket it could not listen on again.
	fatal chan error

	srv      *http.Server
	sockMu   sync.Mutex
	ln       *net.UnixListener
	sockInfo os.FileInfo
}

func (w *Worker) init() {
	slots, queue := w.Slots, w.Queue
	if slots <= 0 {
		slots = defaultSlots
	}
	if queue <= 0 {
		queue = defaultQueue
	}
	if w.Pod != nil {
		slots = 1
	}
	if w.Timeout <= 0 {
		w.Timeout = 20 * time.Second
	}
	w.admit = make(chan struct{}, slots+queue)
	w.run = make(chan struct{}, slots)
	w.fatal = make(chan error, 1)
	if w.Scan == nil {
		var contain func(*exec.Cmd, string) error
		if w.Pod != nil {
			contain = w.Pod.RunJob
		}
		launcher := w.Launcher
		if launcher == "" {
			launcher = RuntimeLauncher
		}
		w.Scan = RuntimeScanner(launcher, contain)
	}
}

// Handler is the worker's HTTP API.
func (w *Worker) Handler() http.Handler {
	w.init()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/scan", w.serveScan)
	mux.HandleFunc("GET /v1/health", w.serveHealth)
	return mux
}

// Serve listens on Dir/scan.sock (0600) until ctx ends. In pod mode it
// first empties the container's folders: a /tmp emptyDir outlives a
// container restart (GAP-0875). It returns an error, so the container
// restarts, when a job leaves the container in a state it cannot clear.
func (w *Worker) Serve(ctx context.Context) error {
	handler := w.Handler()
	if w.Pod != nil {
		if err := w.Pod.Reset(); err != nil {
			return err
		}
		if err := w.clearScanDir(); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Join(w.Dir, scanner.ScanJobsDirName), 0o700); err != nil {
		return err
	}
	if w.Pod != nil {
		if err := os.MkdirAll(filepath.Join(w.Dir, "active"), 0o700); err != nil {
			return err
		}
	}
	w.srv = &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ConnContext: withPeer}
	if err := w.listen(); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		_ = w.srv.Close()
		return nil
	case err := <-w.fatal:
		_ = w.srv.Close()
		return err
	}
}

// listen (again) binds Dir/scan.sock and serves it; an earlier listener is
// closed without removing what is at the path now.
func (w *Worker) listen() error {
	sock := filepath.Join(w.Dir, scanner.ScanSocketName)
	_ = os.Remove(sock)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		return err
	}
	fi, err := os.Lstat(sock)
	if err == nil {
		err = os.Chmod(sock, 0o600)
	}
	if err != nil {
		ln.Close()
		return err
	}
	w.sockMu.Lock()
	old := w.ln
	w.ln, w.sockInfo = ln, fi
	w.sockMu.Unlock()
	if old != nil {
		old.SetUnlinkOnClose(false)
		_ = old.Close()
	}
	go func() {
		err := w.srv.Serve(ln)
		w.sockMu.Lock()
		current := w.ln == ln
		w.sockMu.Unlock()
		if current && err != nil && !errors.Is(err, http.ErrServerClosed) {
			w.fail(err)
		}
	}()
	return nil
}

func (w *Worker) fail(err error) {
	select {
	case w.fatal <- err:
	default:
	}
}

// keepShared puts the shared scan folder back after a pod-mode job: the
// socket must be the one the worker listens on (a scanner that replaced it
// would answer later scans), the jobs folder a real folder, both private to
// the worker's user. The scanner's Landlock domain already refuses these
// writes (GAP-0873); this holds even where it did not.
func (w *Worker) keepShared() error {
	jobs := filepath.Join(w.Dir, scanner.ScanJobsDirName)
	if fi, err := os.Lstat(jobs); err != nil || !fi.IsDir() {
		_ = os.Remove(jobs)
		if err := os.Mkdir(jobs, 0o700); err != nil {
			return err
		}
	} else if fi.Mode().Perm() != 0o700 {
		if err := os.Chmod(jobs, 0o700); err != nil {
			return err
		}
	}
	sock := filepath.Join(w.Dir, scanner.ScanSocketName)
	w.sockMu.Lock()
	want := w.sockInfo
	w.sockMu.Unlock()
	fi, err := os.Lstat(sock)
	if err != nil || want == nil || !os.SameFile(fi, want) || fi.Mode().Type() != os.ModeSocket {
		return w.listen()
	}
	if fi.Mode().Perm() != 0o600 {
		return os.Chmod(sock, 0o600)
	}
	return nil
}

// clearScanDir removes what an earlier container left in the shared scan
// folder besides the gateway's jobs.
func (w *Worker) clearScanDir() error {
	entries, err := os.ReadDir(w.Dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Name() == scanner.ScanJobsDirName && e.IsDir() {
			continue
		}
		if err := os.RemoveAll(filepath.Join(w.Dir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

// endPodJob clears the container after a pod-mode job or health check and
// checks the shared folder. Its error is the answer; one only a new
// container clears also ends Serve.
func (w *Worker) endPodJob() error {
	if err := w.Pod.Reset(); err != nil {
		// A failed reset cannot prove the next job starts in a clean,
		// contained pod, regardless of whether cleanup or Check refused.
		w.fail(err)
		return err
	}
	if err := w.keepShared(); err != nil {
		err = fmt.Errorf("the scan worker cannot keep its socket: %w", err)
		w.fail(err)
		return err
	}
	return nil
}

func answer(rw http.ResponseWriter, status int, a scanner.RemoteScanAnswer) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(status)
	_ = json.NewEncoder(rw).Encode(a)
}

func (w *Worker) serveHealth(rw http.ResponseWriter, r *http.Request) {
	h := scanner.RemoteHealth{}
	if w.refusePeer(rw, r) {
		return
	}
	if w.Pod != nil {
		// The version check may start the runtime: it takes the job slot,
		// and a worker that cannot contain a scan is not ready.
		if !acquire(r.Context(), w.run) {
			return
		}
		defer func() { <-w.run }()
		if err := w.Pod.Check(); err != nil {
			h.Error = err.Error()
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(h)
			return
		}
	}
	if w.Version != nil {
		v, err := w.Version(r.Context())
		h.Version, h.Ready = v, err == nil
		if err != nil {
			h.Error = err.Error()
		}
	}
	if w.Pod != nil {
		if err := w.endPodJob(); err != nil {
			h.Ready, h.Error = false, err.Error()
		}
	}
	rw.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(rw).Encode(h)
}

// refusePeer refuses, in pod mode, a request from another process of the
// worker's own PID namespace: only a scanner runs there, and it must not ask
// for (and so delete) a queued job of the gateway's, which connects from its
// own container (GAP-0873).
func (w *Worker) refusePeer(rw http.ResponseWriter, r *http.Request) bool {
	if w.Pod == nil {
		return false
	}
	// The gateway is outside this container's PID namespace and appears as
	// PID 0. A missing credential is refused too, not treated as a gateway.
	if pid := peerPID(r.Context()); pid != 0 {
		answer(rw, http.StatusForbidden, scanner.RemoteScanAnswer{Code: "refused", Error: "a request not proven to be from the gateway container"})
		return true
	}
	return false
}

func (w *Worker) serveScan(rw http.ResponseWriter, r *http.Request) {
	if w.refusePeer(rw, r) {
		return
	}
	var req scanner.RemoteScanRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, maxRequest))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		answer(rw, http.StatusBadRequest, scanner.RemoteScanAnswer{Code: "refused", Error: "bad request: " + err.Error()})
		return
	}
	if !scanner.ScanJobIDRE.MatchString(req.Job) {
		answer(rw, http.StatusBadRequest, scanner.RemoteScanAnswer{Code: "refused", Error: "bad job id"})
		return
	}
	if req.Kind != scanner.RemoteKindSkill && req.Kind != scanner.RemoteKindPlugin {
		answer(rw, http.StatusBadRequest, scanner.RemoteScanAnswer{Code: "refused", Error: "bad kind"})
		return
	}
	// Every answer names its job, which the gateway checks (GAP-0873).
	answer := func(rw http.ResponseWriter, status int, a scanner.RemoteScanAnswer) {
		a.Job = req.Job
		answer(rw, status, a)
	}
	dir := filepath.Join(w.Dir, scanner.ScanJobsDirName, req.Job)
	// The job is the gateway's; the worker deletes it whatever the outcome.
	defer os.RemoveAll(dir)
	if err := checkJob(dir); err != nil {
		answer(rw, http.StatusBadRequest, scanner.RemoteScanAnswer{Code: "refused", Error: err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), w.Timeout)
	defer cancel()
	// A full queue waits inside the timeout; it never turns into an allow.
	if !acquire(ctx, w.admit) {
		answer(rw, http.StatusOK, scanner.RemoteScanAnswer{Code: "timeout", Error: "the scan waited past its timeout for a worker slot"})
		return
	}
	defer func() { <-w.admit }()
	if !acquire(ctx, w.run) {
		answer(rw, http.StatusOK, scanner.RemoteScanAnswer{Code: "timeout", Error: "the scan waited past its timeout for a worker slot"})
		return
	}
	defer func() { <-w.run }()
	scanDir := dir
	if w.Pod != nil {
		// The gateway may queue other users' jobs, but this scanner sees only
		// the accepted job. Landlock grants read access to this private path.
		scanDir = filepath.Join(w.Dir, "active", req.Job)
		if err := os.Rename(dir, scanDir); err != nil {
			answer(rw, http.StatusOK, scanner.RemoteScanAnswer{Code: "unavailable", Error: "cannot isolate the scan job: " + err.Error()})
			return
		}
		defer os.RemoveAll(scanDir)
		if err := checkJob(scanDir); err != nil {
			answer(rw, http.StatusBadRequest, scanner.RemoteScanAnswer{Code: "refused", Error: err.Error()})
			return
		}
	}
	res, err := w.Scan(ctx, req.Kind, scanDir, req.Settings)
	if w.Pod != nil {
		// Nothing the scan started or wrote may reach the next job; a
		// container that could not be cleared answers no result.
		if rerr := w.endPodJob(); rerr != nil {
			answer(rw, http.StatusOK, scanner.RemoteScanAnswer{Code: "unavailable", Error: rerr.Error()})
			return
		}
	}
	switch {
	case err == nil && res != nil:
		answer(rw, http.StatusOK, scanner.RemoteScanAnswer{Result: res})
	case ctx.Err() != nil:
		answer(rw, http.StatusOK, scanner.RemoteScanAnswer{Code: "timeout", Error: "the scan did not finish in time"})
	case err != nil && scanner.Unavailable(err):
		answer(rw, http.StatusOK, scanner.RemoteScanAnswer{Code: "unavailable", Error: err.Error()})
	default:
		msg := "the scanner returned no result"
		if err != nil {
			msg = err.Error()
		}
		answer(rw, http.StatusOK, scanner.RemoteScanAnswer{Result: res, Code: "failed", Error: msg})
	}
}

func acquire(ctx context.Context, sem chan struct{}) bool {
	select {
	case sem <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

// checkJob refuses a job that is not a real folder of folders and regular
// files: a link in a job could point the scanner at a file of the sidecar.
func checkJob(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("no such job")
	}
	if !fi.IsDir() {
		return fmt.Errorf("the job is not a folder")
	}
	n := 0
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if n++; n > maxJobFiles {
			return fmt.Errorf("the job has more than %d entries", maxJobFiles)
		}
		if !d.IsDir() && !d.Type().IsRegular() {
			return fmt.Errorf("the job has a link or a special file: %s", filepath.Base(p))
		}
		return nil
	})
}

// RuntimeScanner runs the release's scanner runtime at launcher: skill-scanner
// with the gateway's static settings, or the plugin scanner. contain runs
// each scanner command with the accepted job path (nil: the scanner's
// namespace containment).
func RuntimeScanner(launcher string, contain func(*exec.Cmd, string) error) ScanFunc {
	return func(ctx context.Context, kind, dir string, st scanner.RemoteSettings) (*scanner.ScanResult, error) {
		return runtimeScan(ctx, launcher, contain, kind, dir, st)
	}
}

func runtimeScan(ctx context.Context, launcher string, contain func(*exec.Cmd, string) error, kind, dir string, st scanner.RemoteSettings) (*scanner.ScanResult, error) {
	var run func(*exec.Cmd) error
	if contain != nil {
		run = func(cmd *exec.Cmd) error { return contain(cmd, dir) }
	}
	if kind == scanner.RemoteKindPlugin {
		return (&scanner.PluginScanner{BinaryPath: launcher, Contain: run}).Scan(ctx, dir)
	}
	cfg := config.SkillScannerConfig{Binary: launcher, Policy: st.Policy, Lenient: st.Lenient,
		UseBehavioral: st.UseBehavioral, UseTrigger: st.UseTrigger}
	if st.Policy == config.SkillScannerPolicyCustom {
		f, err := os.CreateTemp("", "dc-scan-policy-*.yaml")
		if err != nil {
			return nil, err
		}
		defer os.Remove(f.Name())
		if _, err := f.Write(st.CustomPolicy); err != nil {
			f.Close()
			return nil, err
		}
		f.Close()
		sum := sha256.Sum256(st.CustomPolicy)
		cfg.PolicyFile = config.AssetFileRef{Path: f.Name(), Digest: "sha256:" + hex.EncodeToString(sum[:])}
	}
	return (&scanner.SkillScanner{Config: cfg, Contain: run}).Scan(ctx, dir)
}
