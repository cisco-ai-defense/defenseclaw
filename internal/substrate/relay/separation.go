// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// separation is a relay that runs as root and starts everything as the
// agent's user (GAP-0116, separate_linux.go). nil is a relay of the agent's
// own user.
type separation struct {
	// cred is the agent's user; nil only in tests that run the child
	// commands as the test's user.
	cred agentCred
	// exe is the relay binary, run as the agent's user for file copies.
	exe string
}

// agentCred is the agent's user of a separated relay, nil otherwise.
func (sp *separation) agentCred() agentCred {
	if sp == nil {
		return nil
	}
	return sp.cred
}

// Child commands of the relay binary, run as the agent's user: every file
// the relay writes or reads for a launcher is written or read with the
// agent's permissions, so a root relay neither leaves root-owned files in
// the agent's folders nor reads a file the agent could not (a link the agent
// planted to /etc/shadow or the relay's keys).
const (
	childFilesPut = "files-put" // DIR LIMIT, tar on stdin, JSON result on stdout
	childFilesGet = "files-get" // PATH, tar on stdout; exit childNotFound when absent
	childStateDir = "state-dir" // HOME WORKDIR, the state root on stdout
	childNotFound = 3
	childDenied   = 4 // files-get: the agent's user may not read a part of PATH
)

// IsChildCommand reports whether args name one of the relay's child commands.
func IsChildCommand(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case childFilesPut, childFilesGet, childStateDir:
		return true
	}
	return false
}

// putResult is the JSON a files-put child prints.
type putResult struct {
	Result ExtractResult `json:"result"`
	Kind   string        `json:"kind,omitempty"`
	Error  string        `json:"error,omitempty"`
}

var extractKinds = []struct {
	kind string
	err  error
}{{"too_large", ErrTooLarge}, {"too_many", ErrTooManyEntries}, {"unsafe", ErrUnsafePath},
	{"unsupported", ErrUnsupportedEntry}, {"bad_archive", ErrBadArchive}}

// runChild runs a child command (as the agent's user; the parent set it).
func runChild(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	switch {
	case args[0] == childFilesPut && len(args) == 3:
		limit, err := strconv.ParseInt(args[2], 10, 64)
		if err != nil {
			fmt.Fprintln(stderr, "relay files-put: bad limit")
			return 2
		}
		out := putResult{}
		if err := os.MkdirAll(args[1], 0o755); err != nil {
			out.Error = err.Error()
		} else if out.Result, err = ExtractTar(stdin, args[1], ExtractOptions{MaxBytes: limit}); err != nil {
			out.Error = err.Error()
			for _, k := range extractKinds {
				if errors.Is(err, k.err) {
					out.Kind = k.kind
				}
			}
		}
		_ = json.NewEncoder(stdout).Encode(out)
		return 0
	case args[0] == childFilesGet && len(args) == 2:
		if err := readable(args[1]); err != nil {
			fmt.Fprintln(stderr, err.Error())
			switch {
			case errors.Is(err, fs.ErrNotExist):
				return childNotFound
			case errors.Is(err, fs.ErrPermission):
				return childDenied
			}
			return 1
		}
		if err := WriteTar(stdout, args[1]); err != nil {
			fmt.Fprintln(stderr, err.Error())
			return 1
		}
		return 0
	case args[0] == childStateDir && len(args) == 3:
		fmt.Fprintln(stdout, makeStateRoot(args[1], args[2]))
		return 0
	}
	fmt.Fprintf(stderr, "relay %s: bad arguments\n", args[0])
	return 2
}

func (sp *separation) child(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, sp.exe, args...)
	cmd.Env = os.Environ()
	setProcessGroup(cmd)
	sp.asAgent(cmd)
	cmd.Cancel = func() error { return killProcessGroup(cmd) }
	return cmd
}

// extract is ExtractTar into dir as the agent's user.
func (sp *separation) extract(ctx context.Context, r io.Reader, dir string, limit int64) (ExtractResult, error) {
	cmd := sp.child(ctx, childFilesPut, dir, strconv.FormatInt(limit, 10))
	cmd.Stdin = r
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return ExtractResult{}, fmt.Errorf("copy as the agent's user: %w: %s", err, strings.TrimSpace(errb.String()))
	}
	var res putResult
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		return ExtractResult{}, fmt.Errorf("copy as the agent's user: unreadable answer")
	}
	if res.Error == "" {
		return res.Result, nil
	}
	for _, k := range extractKinds {
		if res.Kind == k.kind {
			return res.Result, fmt.Errorf("%w: %s", k.err, res.Error)
		}
	}
	return res.Result, errors.New(res.Error)
}

// errChildNotFound is a files-get of a path that does not exist;
// errChildDenied one the agent's user may not read all of (GAP-0375).
var (
	errChildNotFound = errors.New("no such file or directory")
	errChildDenied   = errors.New("permission denied")
)

// tarTo starts writing the tar of p as the agent's user. ready is called
// once the child found p and checked that it can read all of it, before the
// first byte; a missing p is errChildNotFound, one the agent's user may not
// read errChildDenied, and nothing is written.
func (sp *separation) tarTo(ctx context.Context, w io.Writer, p string, ready func()) error {
	cmd := sp.child(ctx, childFilesGet, p)
	var errb bytes.Buffer
	cmd.Stderr = &errb
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	var first [1]byte
	n, rerr := io.ReadFull(stdout, first[:])
	if n == 0 {
		werr := cmd.Wait()
		var ee *exec.ExitError
		if errors.As(werr, &ee) {
			switch ee.ExitCode() {
			case childNotFound:
				return errChildNotFound
			case childDenied:
				return errChildDenied
			}
		}
		if werr == nil {
			werr = rerr
		}
		return fmt.Errorf("read as the agent's user: %v: %s", werr, strings.TrimSpace(errb.String()))
	}
	ready()
	if _, err := w.Write(first[:]); err != nil {
		_ = killProcessGroup(cmd)
		_ = cmd.Wait()
		return err
	}
	_, cerr := io.Copy(w, stdout)
	werr := cmd.Wait()
	if cerr != nil {
		return cerr
	}
	if werr != nil {
		return fmt.Errorf("read as the agent's user: %v: %s", werr, strings.TrimSpace(errb.String()))
	}
	return nil
}

// stateDir is makeStateRoot run as the agent's user.
func (sp *separation) stateDir(home, work string) string {
	cmd := sp.child(context.Background(), childStateDir, home, work)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// makeStateRoot makes the state root below home (stateRoot) and returns it,
// "" when there is none.
func makeStateRoot(home, work string) string {
	if !filepath.IsAbs(home) || filepath.Clean(home) == "/" {
		return ""
	}
	work = filepath.Clean(work)
	d := filepath.Join(home, ".local", "state", "defenseclaw", "copies")
	if d == work || strings.HasPrefix(d, work+string(filepath.Separator)) || strings.HasPrefix(work, d+string(filepath.Separator)) {
		return ""
	}
	if err := os.MkdirAll(d, 0o700); err != nil {
		return ""
	}
	if fi, err := os.Lstat(d); err != nil || !fi.IsDir() || fi.Mode().Perm()&0o077 != 0 {
		return ""
	}
	return d
}
