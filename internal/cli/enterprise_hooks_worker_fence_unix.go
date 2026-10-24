// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/agentprocess"
)

// A per-user foreign-cleanup worker runs as the user and cannot take its
// account's removal lock, rotate the record key or write the ledger. It asks
// the guardian over two pipes right before each removal to open its commit
// (beginEnterpriseForeignHookRemoval: the lock, the key rotation and the
// first record), and hands that removal back once it is done: the guardian
// records it again and lets go of the lock before the worker reads on. A
// scan, a cleanup that finds nothing to remove, and every other task of the
// worker (VS Code Local files, leftover and personal Claude Code targets,
// block records), never holds the lock, so neither the gateway's exchanges
// nor another account's cleanup waits on them.
const (
	// enterpriseHookWorkerFenceGrantFD carries the guardian's replies.
	enterpriseHookWorkerFenceGrantFD = 3
	// enterpriseHookWorkerFenceAskFD carries the worker's requests.
	enterpriseHookWorkerFenceAskFD = 4
	// enterpriseHookWorkerFenceMessageLimit bounds one message: a commit
	// names at most 32 paths of at most 512 bytes (boundedStrings).
	enterpriseHookWorkerFenceMessageLimit = 64 << 10
	// enterpriseHookWorkerFenceLockLimit bounds the removals one connector's
	// cleanup takes the fence for. Past it, the rest of its hooks stay in
	// place and reported, and the guard keeps denying them.
	enterpriseHookWorkerFenceLockLimit = 256

	enterpriseHookWorkerFenceOpLock   = "lock"
	enterpriseHookWorkerFenceOpCommit = "commit"
)

type enterpriseHookWorkerFenceAsk struct {
	Op        string   `json:"op"`
	Connector string   `json:"connector"`
	Paths     []string `json:"paths,omitempty"`
	Removed   []string `json:"removed,omitempty"`
}

type enterpriseHookWorkerFenceReply struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// enterpriseForeignHookFenceSession is the guardian's side of one worker's
// removal commits. A connector of the job opens a commit for each removal,
// one removal at a time, and that removal's commit records it and lets go
// of the account's lock.
type enterpriseForeignHookFenceSession struct {
	stderr        io.Writer
	account, home string
	allowed       map[string]bool

	mu        sync.Mutex
	tx        *enterpriseForeignHookRemovalTx
	holder    string
	locks     map[string]int
	committed map[string]map[string]bool
}

func newEnterpriseForeignHookFenceSession(cleanups []enterpriseHookWorkerForeignCleanup, stderr io.Writer, account, home string) *enterpriseForeignHookFenceSession {
	allowed := map[string]bool{}
	for _, cleanup := range cleanups {
		if name := enterpriseHookWorkerFenceConnector(cleanup.Connector); name != "" {
			allowed[name] = true
		}
	}
	return &enterpriseForeignHookFenceSession{stderr: stderr, account: account, home: home, allowed: allowed, locks: map[string]int{}, committed: map[string]map[string]bool{}}
}

func enterpriseHookWorkerFenceConnector(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// lock opens the commit of one removal of connector's files paths, within
// ctx (the worker's own timeout).
func (s *enterpriseForeignHookFenceSession) lock(ctx context.Context, connector string, paths []string) error {
	name := enterpriseHookWorkerFenceConnector(connector)
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case !s.allowed[name]:
		return fmt.Errorf("connector %q is not part of this cleanup", boundedString(connector, 64))
	case s.tx != nil:
		return fmt.Errorf("the %s cleanup already holds the account's removal lock", s.holder)
	case s.locks[name] >= enterpriseHookWorkerFenceLockLimit:
		return fmt.Errorf("the %s cleanup took the account's removal lock %d times", name, enterpriseHookWorkerFenceLockLimit)
	case len(paths) == 0:
		return errors.New("a removal names no file")
	}
	tx, err := beginEnterpriseForeignHookRemoval(ctx, s.stderr, s.account, s.home, name, boundedStrings(paths, 32))
	if err != nil {
		return err
	}
	s.tx, s.holder = tx, name
	s.locks[name]++
	return nil
}

// commit records the removal that holds the lock again, then lets go of it.
func (s *enterpriseForeignHookFenceSession) commit(connector string, removed []string) error {
	name := enterpriseHookWorkerFenceConnector(connector)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tx == nil || s.holder != name {
		return fmt.Errorf("the %s cleanup does not hold the account's removal lock", boundedString(name, 64))
	}
	removed = boundedStrings(removed, 32)
	tx := s.tx
	s.tx, s.holder = nil, ""
	err := tx.commit(removed)
	if s.committed[name] == nil {
		s.committed[name] = map[string]bool{}
	}
	for _, path := range tx.paths {
		s.committed[name][path] = true
	}
	return err
}

// uncommitted lists the files of removed that no commit of connector
// recorded.
func (s *enterpriseForeignHookFenceSession) uncommitted(connector string, removed []string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	committed := s.committed[enterpriseHookWorkerFenceConnector(connector)]
	var out []string
	for _, path := range removed {
		if !committed[path] {
			out = append(out, path)
		}
	}
	return out
}

// release ends a commit the worker opened and never committed (it failed
// or timed out after its lock), with the mark of now.
func (s *enterpriseForeignHookFenceSession) release() { s.releaseAt(agentprocess.Now()) }

// releaseAt is release with mark, taken when the worker ended: every
// process that may have loaded a file the worker changed started before it.
func (s *enterpriseForeignHookFenceSession) releaseAt(mark string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tx != nil {
		tx, name := s.tx, s.holder
		s.tx, s.holder = nil, ""
		_ = tx.commitAt(mark, nil)
		if s.committed[name] == nil {
			s.committed[name] = map[string]bool{}
		}
		for _, path := range tx.paths {
			s.committed[name][path] = true
		}
	}
}

// serve answers the worker's requests read from asks until the pipe ends,
// a request is malformed or ctx is done.
func (s *enterpriseForeignHookFenceSession) serve(ctx context.Context, asks io.Reader, replies io.Writer) {
	scanner := bufio.NewScanner(asks)
	scanner.Buffer(make([]byte, 0, 4096), enterpriseHookWorkerFenceMessageLimit)
	for scanner.Scan() {
		var ask enterpriseHookWorkerFenceAsk
		decoder := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&ask); err != nil {
			_ = writeEnterpriseHookWorkerFenceMessage(replies, enterpriseHookWorkerFenceReply{Error: "malformed fence request"})
			return
		}
		var err error
		switch ask.Op {
		case enterpriseHookWorkerFenceOpLock:
			err = s.lock(ctx, ask.Connector, ask.Paths)
		case enterpriseHookWorkerFenceOpCommit:
			err = s.commit(ask.Connector, ask.Removed)
		default:
			err = fmt.Errorf("unknown fence request %q", boundedString(ask.Op, 32))
		}
		reply := enterpriseHookWorkerFenceReply{OK: err == nil}
		if err != nil {
			reply.Error = boundedString(err.Error(), 512)
		}
		if writeEnterpriseHookWorkerFenceMessage(replies, reply) != nil {
			return
		}
	}
}

func writeEnterpriseHookWorkerFenceMessage(w io.Writer, message any) error {
	data, err := json.Marshal(message)
	if err != nil {
		return err
	}
	_, err = w.Write(append(data, '\n'))
	return err
}

// attachEnterpriseHookWorkerFence gives cmd the fence pipes when request
// carries a fence session and serves them until the returned function is
// called, after the worker has ended. That function waits for a request in
// progress (a ledger commit) to finish.
func attachEnterpriseHookWorkerFence(ctx context.Context, cmd *exec.Cmd, request enterpriseHookWorkerRequest) (func(), error) {
	session := request.cleanupFence
	if session == nil {
		return func() {}, nil
	}
	grantRead, grantWrite, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("foreign-hook cleanup fence pipe: %w", err)
	}
	askRead, askWrite, err := os.Pipe()
	if err != nil {
		_ = grantRead.Close()
		_ = grantWrite.Close()
		return nil, fmt.Errorf("foreign-hook cleanup fence pipe: %w", err)
	}
	// ExtraFiles[i] is the worker's descriptor 3+i.
	cmd.ExtraFiles = []*os.File{grantRead, askWrite}
	serveCtx, cancel := context.WithCancel(ctx)
	served := make(chan struct{})
	go func() {
		defer close(served)
		session.serve(serveCtx, askRead, grantWrite)
	}()
	return func() {
		cancel()
		_ = askRead.Close()
		<-served
		_ = grantWrite.Close()
		_ = grantRead.Close()
		_ = askWrite.Close()
	}, nil
}

// enterpriseHookWorkerFencePipe is the worker's side
// (enterpriseForeignHookCleanupFence): lock before each removal, commit
// once it is done.
type enterpriseHookWorkerFencePipe struct {
	replies *bufio.Scanner
	asks    io.Writer
}

// openEnterpriseHookWorkerFencePipe takes the fence pipes the guardian
// passed. They are kept from any process the worker starts.
func openEnterpriseHookWorkerFencePipe() (*enterpriseHookWorkerFencePipe, error) {
	files := make([]*os.File, 0, 2)
	for _, fd := range []int{enterpriseHookWorkerFenceGrantFD, enterpriseHookWorkerFenceAskFD} {
		file := os.NewFile(uintptr(fd), "foreign-hook-cleanup-fence")
		info, err := file.Stat()
		if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
			return nil, errors.New("the guardian passed no foreign-hook cleanup fence pipe")
		}
		syscall.CloseOnExec(fd)
		files = append(files, file)
	}
	replies := bufio.NewScanner(files[0])
	replies.Buffer(make([]byte, 0, 1024), enterpriseHookWorkerFenceMessageLimit)
	return &enterpriseHookWorkerFencePipe{replies: replies, asks: files[1]}, nil
}

func (p *enterpriseHookWorkerFencePipe) exchange(ask enterpriseHookWorkerFenceAsk) error {
	if err := writeEnterpriseHookWorkerFenceMessage(p.asks, ask); err != nil {
		return fmt.Errorf("foreign-hook cleanup fence: %w", err)
	}
	if !p.replies.Scan() {
		return errors.New("foreign-hook cleanup fence: the guardian did not answer")
	}
	var reply enterpriseHookWorkerFenceReply
	if err := json.Unmarshal(p.replies.Bytes(), &reply); err != nil {
		return fmt.Errorf("foreign-hook cleanup fence: %w", err)
	}
	if !reply.OK {
		return fmt.Errorf("foreign-hook cleanup fence: %s", firstNonEmpty(reply.Error, "refused"))
	}
	return nil
}

func (p *enterpriseHookWorkerFencePipe) lock(connector string, paths []string) error {
	return p.exchange(enterpriseHookWorkerFenceAsk{Op: enterpriseHookWorkerFenceOpLock, Connector: connector, Paths: boundedStrings(paths, 32)})
}

func (p *enterpriseHookWorkerFencePipe) commit(connector string, removed []string) error {
	return p.exchange(enterpriseHookWorkerFenceAsk{Op: enterpriseHookWorkerFenceOpCommit, Connector: connector, Removed: boundedStrings(removed, 32)})
}
