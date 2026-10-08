// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/jsonc"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// Zed keeps one guard for every thread of an agent and does not start a new
// one when it exits. A guard that ended its session for a central change
// (a profile that moved or changed mode) exited, and the next thread failed
// with "Incoming transport closed ... session/new" until the user pressed
// Retry (GAP-0906). Such a guard now stays: it answers the editor's requests
// with the reason until the user has run setup again, and then starts the
// guard the editor entry names now for the next thread, on the same pipe.

// relaunchInitWait bounds how long a relaunched guard may take to answer
// the editor's initialize request.
var relaunchInitWait = 2 * time.Minute

// editorInput is the editor's stdin. The proxy reads it until detach; the
// guard then reads the rest itself (rest). It keeps the editor's initialize
// request for a relaunched guard.
type editorInput struct {
	chunks     chan []byte
	detached   chan struct{}
	detachOnce sync.Once
	mu         sync.Mutex
	pending    []byte
	initialize []byte
}

func newEditorInput(src io.Reader) *editorInput {
	in := &editorInput{chunks: make(chan []byte), detached: make(chan struct{})}
	go in.pump(src)
	return in
}

func (in *editorInput) pump(src io.Reader) {
	defer close(in.chunks)
	var first []byte
	recording := true
	buf := make([]byte, 64<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			chunk := append([]byte(nil), buf[:n]...)
			if recording {
				first = append(first, chunk...)
				if end := bytes.IndexByte(first, '\n'); end >= 0 {
					if msg, parseErr := acp.ParseMessage(bytes.TrimSpace(first[:end])); parseErr == nil && msg.IsRequest() && msg.Method == "initialize" {
						in.mu.Lock()
						in.initialize = append([]byte(nil), bytes.TrimSpace(first[:end])...)
						in.mu.Unlock()
					}
					recording, first = false, nil
				} else if len(first) > acp.MaxFrameBytes {
					recording, first = false, nil
				}
			}
			in.chunks <- chunk
		}
		if err != nil {
			return
		}
	}
}

// Read is the proxy's view: end of input once detached.
func (in *editorInput) Read(p []byte) (int, error) {
	select {
	case <-in.detached:
		return 0, io.EOF
	default:
	}
	in.mu.Lock()
	if len(in.pending) > 0 {
		n := copy(p, in.pending)
		in.pending = in.pending[n:]
		in.mu.Unlock()
		return n, nil
	}
	in.mu.Unlock()
	select {
	case <-in.detached:
		return 0, io.EOF
	case chunk, ok := <-in.chunks:
		if !ok {
			return 0, io.EOF
		}
		in.mu.Lock()
		defer in.mu.Unlock()
		select {
		case <-in.detached:
			// Detached while this read waited: the guard reads it.
			in.pending = append(chunk, in.pending...)
			return 0, io.EOF
		default:
		}
		n := copy(p, chunk)
		in.pending = append(in.pending, chunk[n:]...)
		return n, nil
	}
}

func (in *editorInput) detach() { in.detachOnce.Do(func() { close(in.detached) }) }

func (in *editorInput) initializeRequest() []byte {
	in.mu.Lock()
	defer in.mu.Unlock()
	return in.initialize
}

// rest reads what the proxy left, after detach.
func (in *editorInput) rest() io.Reader { return restReader{in} }

type restReader struct{ in *editorInput }

func (r restReader) Read(p []byte) (int, error) {
	r.in.mu.Lock()
	if len(r.in.pending) > 0 {
		n := copy(p, r.in.pending)
		r.in.pending = r.in.pending[n:]
		r.in.mu.Unlock()
		return n, nil
	}
	r.in.mu.Unlock()
	chunk, ok := <-r.in.chunks
	if !ok {
		return 0, io.EOF
	}
	n := copy(p, chunk)
	if n < len(chunk) {
		r.in.mu.Lock()
		r.in.pending = append(r.in.pending, chunk[n:]...)
		r.in.mu.Unlock()
	}
	return n, nil
}

// relaunchCommand is the guard the editor entry names now, once setup wrote
// it again: this same guard executable with other arguments. ok is false
// while the entry is unchanged or names another program.
func relaunchCommand(contractLock, agentID string, current []string) (*exec.Cmd, bool) {
	body, err := safefile.ReadRegularFileBounded(filepath.Clean(contractLock), acp.MaxContractLockBytes)
	if err != nil {
		return nil, false
	}
	var lock struct {
		Client struct {
			ConfigPath string `json:"config_path"`
		} `json:"client"`
	}
	if json.Unmarshal(body, &lock) != nil || !filepath.IsAbs(lock.Client.ConfigPath) {
		return nil, false
	}
	settings, err := safefile.ReadRegularFileBounded(filepath.Clean(lock.Client.ConfigPath), 4<<20)
	if err != nil {
		return nil, false
	}
	var document struct {
		Servers map[string]struct {
			Command string            `json:"command"`
			Args    []string          `json:"args"`
			Env     map[string]string `json:"env"`
		} `json:"agent_servers"`
	}
	if json.Unmarshal(jsonc.Strip(bytes.TrimPrefix(settings, []byte("\xef\xbb\xbf"))), &document) != nil {
		return nil, false
	}
	entry, found := document.Servers[acp.ManagedEntryName(agentID)]
	guard, err := guardExecutable()
	if !found || err != nil || !sameGuardPath(entry.Command, guard) || slices.Equal(entry.Args, current) {
		return nil, false
	}
	command := exec.Command(guard, entry.Args...)
	command.Env = os.Environ()
	for key, value := range entry.Env {
		command.Env = append(command.Env, key+"="+value)
	}
	return command, true
}

// serveAfterSessionEnd answers the editor after the proxy ended its session
// for a central change: every request gets message, until a new thread
// (session/new or session/load) finds the editor entry set up again; that
// thread and every later frame go to the guard the entry names now.
func serveAfterSessionEnd(editor io.Reader, out io.Writer, initialize []byte, message string, relaunch func() (*exec.Cmd, bool)) error {
	reader := bufio.NewReaderSize(editor, 64<<10)
	for {
		line, readErr := reader.ReadBytes('\n')
		frame := bytes.TrimSpace(line)
		if msg, err := acp.ParseMessage(frame); len(frame) > 0 && err == nil && msg.IsRequest() {
			reason := message
			if (msg.Method == "session/new" || msg.Method == "session/load") && len(initialize) > 0 {
				if command, ok := relaunch(); ok {
					done, err := spliceRelaunchedGuard(command, reader, out, initialize, frame)
					if done {
						return err
					}
					reason = message + " (the new DefenseClaw guard did not start: " + err.Error() + ")"
				}
			}
			if _, err := out.Write(append(acp.ErrorResponse(msg.ID, -32001, reason), '\n')); err != nil {
				return err
			}
		}
		if readErr != nil {
			return nil
		}
	}
}

// spliceRelaunchedGuard starts command, initializes it with the editor's
// initialize request, hands it first and then joins it to the editor. done
// is false, with the reason, when the guard did not initialize.
func spliceRelaunchedGuard(command *exec.Cmd, editor io.Reader, out io.Writer, initialize, first []byte) (done bool, err error) {
	stdin, err := command.StdinPipe()
	if err != nil {
		return false, err
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return false, err
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		return false, err
	}
	answers := bufio.NewReaderSize(stdout, 64<<10)
	answered := make(chan error, 1)
	go func() {
		line, readErr := answers.ReadBytes('\n')
		if readErr != nil {
			answered <- errors.New("it exited before it answered")
			return
		}
		var response struct {
			Error *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(bytes.TrimSpace(line), &response) != nil {
			answered <- errors.New("its answer was not ACP JSON-RPC")
			return
		}
		if response.Error != nil {
			answered <- errors.New(response.Error.Message)
			return
		}
		answered <- nil
	}()
	_, writeErr := stdin.Write(append(append([]byte(nil), initialize...), '\n'))
	if writeErr == nil {
		timer := time.NewTimer(relaunchInitWait)
		select {
		case writeErr = <-answered:
		case <-timer.C:
			writeErr = fmt.Errorf("it did not answer within %s", relaunchInitWait)
		}
		timer.Stop()
	}
	if writeErr != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		return false, writeErr
	}
	if _, err := stdin.Write(append(append([]byte(nil), first...), '\n')); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		return false, err
	}
	go func() {
		_, _ = io.Copy(stdin, editor)
		_ = stdin.Close()
	}()
	_, copyErr := io.Copy(out, answers)
	waitErr := command.Wait()
	if waitErr != nil {
		return true, waitErr
	}
	return true, copyErr
}
