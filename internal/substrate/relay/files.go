// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"archive/tar"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The file routes of the relay (A6): non-interactive exec and tar transfer,
// what `defenseclaw substrate run` needs to copy a project into the actor
// and bring the agent's work back. They sit behind the same session-token
// check as every other relay route.
//
//	POST /dcrelay/1/exec           run argv, stream stdout/stderr/exit frames
//	PUT  /dcrelay/1/files?dir=D    extract a tar below D
//	GET  /dcrelay/1/files?path=P   tar of the file or directory P

// Exec frame types: one byte, a 4-byte big-endian length, the payload. The
// exit frame's payload is the exit code in ASCII.
const (
	ExecStdout byte = 1
	ExecStderr byte = 2
	ExecExit   byte = 3
)

// Exit codes the relay chooses itself (the shell's conventions).
const (
	ExitTimedOut    = 124
	ExitOutputLimit = 125
	ExitNotRunnable = 127
)

const (
	// DefaultFilesMaxBytes caps the content of one upload.
	DefaultFilesMaxBytes int64 = 1 << 30
	// DefaultExecMaxOutput caps stdout plus stderr of one exec.
	DefaultExecMaxOutput int64 = 1 << 30
	// DefaultExecTimeout applies when a request sets none.
	DefaultExecTimeout = 600 * time.Second
	maxExecTimeout     = 24 * time.Hour
	maxExecRequest     = 1 << 20
	execChunk          = 32 << 10
	maxExecEnv         = 512
	// tarOverhead is what an upload body may carry beyond twice the content
	// cap: block headers and padding.
	tarOverhead = 1 << 20
	// FilesMaxBytesEnv overrides DefaultFilesMaxBytes for the relay process
	// (the upload cap, "max_bytes"). A later kit config field replaces it.
	FilesMaxBytesEnv = "DEFENSECLAW_RELAY_FILES_MAX_BYTES"
)

// ExecRequest is the body of POST /dcrelay/1/exec.
type ExecRequest struct {
	// Argv is exec'd directly: there is no shell.
	Argv []string `json:"argv"`
	// Workdir is absolute, or relative to the relay's working directory
	// ("" is that directory).
	Workdir string            `json:"workdir,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	// TimeoutSeconds bounds the command (DefaultExecTimeout when 0).
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
	// MaxOutputBytes bounds stdout plus stderr (DefaultExecMaxOutput when 0).
	MaxOutputBytes int64 `json:"max_output_bytes,omitempty"`
}

var envKeyRE = regexp.MustCompile(`^[A-Z0-9_]+$`)

func (r *ExecRequest) validate() error {
	if len(r.Argv) == 0 || r.Argv[0] == "" {
		return errors.New("argv[0] must name a command")
	}
	for _, a := range r.Argv {
		if strings.ContainsRune(a, 0) {
			return errors.New("argv holds a NUL byte")
		}
	}
	if len(r.Env) > maxExecEnv {
		return fmt.Errorf("more than %d environment variables", maxExecEnv)
	}
	for k, v := range r.Env {
		if !envKeyRE.MatchString(k) {
			return fmt.Errorf("environment variable name %q must use only A-Z, 0-9 and _", k)
		}
		if strings.ContainsRune(v, 0) {
			return fmt.Errorf("environment variable %s holds a NUL byte", k)
		}
	}
	if strings.ContainsRune(r.Workdir, 0) {
		return errors.New("workdir holds a NUL byte")
	}
	if r.TimeoutSeconds < 0 || time.Duration(r.TimeoutSeconds)*time.Second > maxExecTimeout {
		return fmt.Errorf("timeout_seconds must be between 0 and %d", int(maxExecTimeout/time.Second))
	}
	if r.MaxOutputBytes < 0 {
		return errors.New("max_output_bytes must not be negative")
	}
	return nil
}

// relayWorkdir is the directory relative paths and commands start in: the
// configured one, else the relay's own (the image WORKDIR), else /work.
func relayWorkdir(configured string) string {
	if configured != "" {
		return configured
	}
	if wd, err := os.Getwd(); err == nil && wd != "" {
		return wd
	}
	return "/work"
}

func (s *Server) resolvePath(p string) string {
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Join(relayWorkdir(s.opts.Config.Relay.Workdir), p)
}

func filesMaxBytes() int64 {
	if v := os.Getenv(FilesMaxBytesEnv); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			return n
		}
	}
	return DefaultFilesMaxBytes
}

// execStream writes frames to one response, safely from the two copiers of
// stdout and stderr, and enforces the output budget.
type execStream struct {
	mu     sync.Mutex
	w      io.Writer
	flush  func()
	werr   error
	left   int64
	over   bool
	cancel context.CancelFunc
}

func (e *execStream) frame(t byte, p []byte) {
	if e.werr != nil {
		return
	}
	var h [5]byte
	h[0] = t
	binary.BigEndian.PutUint32(h[1:], uint32(len(p)))
	if _, err := e.w.Write(h[:]); err != nil {
		e.werr = err
		e.cancel()
		return
	}
	if _, err := e.w.Write(p); err != nil {
		e.werr = err
		e.cancel()
		return
	}
	e.flush()
}

type execWriter struct {
	e *execStream
	t byte
}

// Write never fails: once the budget is spent or the client is gone the
// process is being killed and its remaining output is only drained.
func (w execWriter) Write(p []byte) (int, error) {
	e := w.e
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.over || e.werr != nil {
		return len(p), nil
	}
	data := p
	if int64(len(data)) > e.left {
		data = data[:e.left]
		e.over = true
		e.cancel()
	}
	e.left -= int64(len(data))
	for len(data) > 0 {
		n := min(len(data), execChunk)
		e.frame(w.t, data[:n])
		data = data[n:]
	}
	return len(p), nil
}

func (s *Server) fileExec(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.auth(w, r, "exec"); !ok {
		return
	}
	var req ExecRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxExecRequest)).Decode(&req); err != nil {
		http.Error(w, "relay: exec request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := req.validate(); err != nil {
		http.Error(w, "relay: exec request: "+err.Error(), http.StatusBadRequest)
		return
	}
	dir := s.resolvePath(req.Workdir)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	RunExec(r.Context(), req, dir, w, func() { _ = rc.Flush() })
}

// RunExec runs req in dir and writes its frames to w, ending with the exit
// frame (or nothing when the client went away). Exported for the actor-side
// tools that want the same framing.
func RunExec(ctx context.Context, req ExecRequest, dir string, w io.Writer, flush func()) {
	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = DefaultExecTimeout
	}
	limit := req.MaxOutputBytes
	if limit == 0 {
		limit = DefaultExecMaxOutput
	}
	tctx, cancelT := context.WithTimeout(ctx, timeout)
	defer cancelT()
	kctx, cancelK := context.WithCancel(tctx)
	defer cancelK()
	es := &execStream{w: w, flush: flush, left: limit, cancel: cancelK}

	cmd := exec.CommandContext(kctx, req.Argv[0], req.Argv[1:]...)
	cmd.Dir = dir
	cmd.Env = os.Environ()
	for k, v := range req.Env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	cmd.Stdin = nil // /dev/null
	cmd.Stdout = execWriter{es, ExecStdout}
	cmd.Stderr = execWriter{es, ExecStderr}
	setProcessGroup(cmd)
	cmd.Cancel = func() error { return killProcessGroup(cmd) }
	// A grandchild that keeps the pipes open must not hold the reply.
	cmd.WaitDelay = 2 * time.Second
	err := cmd.Run()

	es.mu.Lock()
	defer es.mu.Unlock()
	if es.werr != nil || ctx.Err() != nil {
		return
	}
	code := 0
	switch {
	case es.over:
		es.frame(ExecStderr, []byte(fmt.Sprintf("output limit of %d bytes reached", limit)))
		code = ExitOutputLimit
	case err != nil && tctx.Err() == context.DeadlineExceeded:
		es.frame(ExecStderr, []byte("timed out"))
		code = ExitTimedOut
	case cmd.ProcessState == nil:
		// The command did not start (not found, not executable, no such
		// directory): say so as a shell would.
		es.frame(ExecStderr, []byte(err.Error()+"\n"))
		code = ExitNotRunnable
	default:
		code = exitCodeOf(cmd.ProcessState)
	}
	es.frame(ExecExit, []byte(strconv.Itoa(code)))
}

// Tar errors.
var (
	// ErrUnsafePath: an entry is absolute, leaves the destination, or goes
	// through a symlink that does.
	ErrUnsafePath = errors.New("unsafe path in archive")
	// ErrUnsupportedEntry: an entry is not a file, directory or symlink.
	ErrUnsupportedEntry = errors.New("unsupported entry type in archive")
	// ErrBadArchive: the stream is not a readable tar.
	ErrBadArchive = errors.New("unreadable archive")
	// ErrTooLarge: the content is larger than the limit.
	ErrTooLarge = errors.New("archive is larger than the limit")
)

// ExtractOptions configures ExtractTar.
type ExtractOptions struct {
	// MaxBytes caps the total file content; 0 means no cap.
	MaxBytes int64
}

// ExtractResult counts what ExtractTar wrote.
type ExtractResult struct {
	Files, Dirs, Symlinks int
	Bytes                 int64
}

// cleanEntry returns the slash-separated path of a tar entry below the
// destination, "." for the destination itself.
func cleanEntry(name string) (string, error) {
	if name == "" || strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("%w: %q", ErrUnsafePath, name)
	}
	if runtime.GOOS == "windows" && strings.ContainsAny(name, `\:`) {
		return "", fmt.Errorf("%w: %q", ErrUnsafePath, name)
	}
	if strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("%w: %q is absolute", ErrUnsafePath, name)
	}
	p := path.Clean(name)
	if p == ".." || strings.HasPrefix(p, "../") {
		return "", fmt.Errorf("%w: %q leaves the destination", ErrUnsafePath, name)
	}
	return p, nil
}

// fsErr tells a path os.Root refused (a symlink leaving the tree) from a
// plain file-system failure.
func fsErr(name string, err error) error {
	if strings.Contains(err.Error(), "escapes from parent") || strings.Contains(err.Error(), "path escapes") {
		return fmt.Errorf("%w: %q goes through a link that leaves the destination", ErrUnsafePath, name)
	}
	return err
}

type dirMode struct {
	name string
	mode fs.FileMode
}

// ExtractTar extracts regular files, directories and symlinks from r below
// dir, which must exist. Modes and modification times are kept (without the
// set-id and sticky bits); every entry path is cleaned and refused when it
// is absolute or leaves dir; a symlink is created as it is (its target may
// point anywhere) but never followed out of dir while extracting, so a link
// cannot redirect a later entry. An entry replaces what is at its path.
// Device nodes, FIFOs and hard links are refused. Extraction is not atomic:
// a refused archive may have written the entries before the bad one.
func ExtractTar(r io.Reader, dir string, o ExtractOptions) (ExtractResult, error) {
	var res ExtractResult
	root, err := os.OpenRoot(dir)
	if err != nil {
		return res, err
	}
	defer root.Close()
	var dirs []dirMode
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			var mb *http.MaxBytesError
			if errors.As(err, &mb) {
				return res, fmt.Errorf("%w: %v", ErrTooLarge, err)
			}
			return res, fmt.Errorf("%w: %v", ErrBadArchive, err)
		}
		if hdr.Typeflag == tar.TypeXGlobalHeader {
			continue
		}
		name, err := cleanEntry(hdr.Name)
		if err != nil {
			return res, err
		}
		mode := fs.FileMode(hdr.Mode) & 0o777
		switch hdr.Typeflag {
		case tar.TypeDir:
			if name == "." {
				continue
			}
			if err := root.MkdirAll(name, 0o755); err != nil {
				return res, fsErr(name, err)
			}
			dirs = append(dirs, dirMode{name, mode})
			res.Dirs++
		case tar.TypeReg:
			if name == "." {
				return res, fmt.Errorf("%w: a file cannot be the destination", ErrUnsafePath)
			}
			res.Bytes += hdr.Size
			if o.MaxBytes > 0 && res.Bytes > o.MaxBytes {
				return res, fmt.Errorf("%w (%d bytes)", ErrTooLarge, o.MaxBytes)
			}
			if err := extractFile(root, tr, name, hdr, mode); err != nil {
				return res, err
			}
			res.Files++
		case tar.TypeSymlink:
			if name == "." || hdr.Linkname == "" || strings.ContainsRune(hdr.Linkname, 0) {
				return res, fmt.Errorf("%w: bad symlink %q", ErrUnsafePath, hdr.Name)
			}
			if err := replaceable(root, name); err != nil {
				return res, err
			}
			if err := mkParent(root, name); err != nil {
				return res, err
			}
			if err := root.Symlink(hdr.Linkname, name); err != nil {
				return res, fsErr(name, err)
			}
			res.Symlinks++
		default:
			return res, fmt.Errorf("%w: %q has type %q", ErrUnsupportedEntry, hdr.Name, string(hdr.Typeflag))
		}
	}
	// Directory modes last: a read-only directory must still take its files.
	for i := len(dirs) - 1; i >= 0; i-- {
		if err := root.Chmod(dirs[i].name, dirs[i].mode); err != nil {
			return res, fsErr(dirs[i].name, err)
		}
	}
	return res, nil
}

func mkParent(root *os.Root, name string) error {
	if d := path.Dir(name); d != "." {
		if err := root.MkdirAll(d, 0o755); err != nil {
			return fsErr(name, err)
		}
	}
	return nil
}

// replaceable removes whatever is at name (not following a link at name) so
// a new entry takes its place; it refuses to replace a directory.
func replaceable(root *os.Root, name string) error {
	fi, err := root.Lstat(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fsErr(name, err)
	}
	if fi.IsDir() {
		return fmt.Errorf("%w: %q is a directory here", ErrUnsafePath, name)
	}
	return root.Remove(name)
}

func extractFile(root *os.Root, r io.Reader, name string, hdr *tar.Header, mode fs.FileMode) error {
	if err := mkParent(root, name); err != nil {
		return err
	}
	if err := replaceable(root, name); err != nil {
		return err
	}
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fsErr(name, err)
	}
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if !hdr.ModTime.IsZero() {
		_ = root.Chtimes(name, hdr.ModTime, hdr.ModTime)
	}
	return nil
}

func (s *Server) filePut(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.auth(w, r, "files-put"); !ok {
		return
	}
	dir := r.URL.Query().Get("dir")
	if dir == "" || strings.ContainsRune(dir, 0) {
		http.Error(w, "relay: files: dir is required", http.StatusBadRequest)
		return
	}
	dir = s.resolvePath(dir)
	limit := filesMaxBytes()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		http.Error(w, "relay: files: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Content is capped by ExtractTar; the body (headers and padding
	// included) by a looser bound.
	body := http.MaxBytesReader(w, r.Body, 2*limit+tarOverhead)
	res, err := ExtractTar(body, dir, ExtractOptions{MaxBytes: limit})
	var tooBig *http.MaxBytesError
	switch {
	case err == nil:
		s.log.Info("relay.files.put", "files", res.Files, "dirs", res.Dirs, "symlinks", res.Symlinks, "bytes", res.Bytes)
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, ErrTooLarge), errors.As(err, &tooBig):
		http.Error(w, "relay: files: "+err.Error(), http.StatusRequestEntityTooLarge)
	case errors.Is(err, ErrUnsafePath), errors.Is(err, ErrUnsupportedEntry), errors.Is(err, ErrBadArchive):
		http.Error(w, "relay: files: "+err.Error(), http.StatusBadRequest)
	default:
		http.Error(w, "relay: files: "+err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) fileGet(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.auth(w, r, "files-get"); !ok {
		return
	}
	p := r.URL.Query().Get("path")
	if p == "" || strings.ContainsRune(p, 0) {
		http.Error(w, "relay: files: path is required", http.StatusBadRequest)
		return
	}
	p = s.resolvePath(p)
	if _, err := os.Stat(p); err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, fs.ErrNotExist) {
			code = http.StatusNotFound
		}
		http.Error(w, "relay: files: "+err.Error(), code)
		return
	}
	w.Header().Set("Content-Type", "application/x-tar")
	w.WriteHeader(http.StatusOK)
	if err := WriteTar(w, p); err != nil {
		s.log.Warn("relay.files.get", "error", err.Error())
		// The status is sent: cut the connection so the client sees a
		// broken stream and not a short archive.
		panic(http.ErrAbortHandler)
	}
}

// WriteTar writes the file or directory at p to w as a tar whose entry names
// start at filepath.Base(p) ("proj/", "proj/main.go"). Modes, modification
// times and symlinks are kept; owners are not; sockets, FIFOs and devices
// are left out. A symlink inside p is archived as a link, never followed.
func WriteTar(w io.Writer, p string) error {
	p = filepath.Clean(p)
	base := filepath.Base(p)
	if base == "." || base == string(filepath.Separator) {
		return fmt.Errorf("cannot archive %q", p)
	}
	top, err := filepath.EvalSymlinks(p)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(w)
	err = filepath.WalkDir(top, func(cur string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(top, cur)
		if err != nil {
			return err
		}
		name := base
		if rel != "." {
			name = path.Join(base, filepath.ToSlash(rel))
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		var link string
		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			if link, err = os.Readlink(cur); err != nil {
				return err
			}
		case info.IsDir(), info.Mode().IsRegular():
		default:
			return nil
		}
		hdr, err := tar.FileInfoHeader(info, link)
		if err != nil {
			return err
		}
		hdr.Name = name
		if info.IsDir() {
			hdr.Name += "/"
		}
		hdr.Mode = int64(info.Mode().Perm())
		hdr.Uid, hdr.Gid, hdr.Uname, hdr.Gname = 0, 0, "", ""
		hdr.AccessTime, hdr.ChangeTime = time.Time{}, time.Time{}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		f, err := os.Open(cur)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.CopyN(tw, f, hdr.Size)
		return err
	})
	if err != nil {
		return err
	}
	return tw.Close()
}
