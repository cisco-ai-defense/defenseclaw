// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package bridgeowner owns one private helper's protocol pipes. It confers no
// policy authority and does not discover, install or start a helper process.
package bridgeowner

import (
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeproto"
)

var (
	ErrClosed       = errors.New("private sandbox helper closed")
	ErrBackpressure = errors.New("private sandbox helper output backpressure")
	ErrCleanup      = errors.New("private sandbox helper cleanup failed")
	ErrPeer         = errors.New("private sandbox helper reported failure")
)

// Custody is implemented by the trusted native launcher that already owns the
// helper and its entire workload tree. StopAndWait must end and observe those
// exact native resources within ctx, independently of protocol cooperation or
// pipe-drain workers. A PID, successful protocol Destroyed frame or closed pipe
// is insufficient. An error retains the launcher's cleanup responsibility.
type Custody interface {
	StopAndWait(context.Context) error
}

// Pipes transfer exclusive ownership of the parent ends of private, deadline-
// capable OS pipes. Input carries host commands; Output carries peer frames.
// Diagnostics is drained without retaining or logging its bytes. No stream may
// alias another. Custody is required even for a helper that exits normally.
type Pipes struct {
	Input, Output, Diagnostics *os.File
	Custody                    Custody
}

type Limits struct {
	WriteTimeout   time.Duration
	CleanupTimeout time.Duration
}

// Command omits owner-assigned sequence, request and binding fields. Send
// serializes their assignment, state admission and complete frame encoding.
type Command struct {
	Kind bridgeproto.Kind
	Plan *bridgeproto.Preparation
	Data *bridgeproto.Data
	Size *bridgeproto.Size
}

// Owner uses fixed-capacity queues and one decoder, diagnostic drainer and
// cleanup worker. Call Receive promptly; a full event queue terminates the
// owned helper rather than blocking its output indefinitely.
type Owner struct {
	writeMu      sync.Mutex
	sequence     uint64
	request      uint64
	binding      bridgeproto.Binding
	conversation *bridgeproto.Conversation
	encoder      *bridgeproto.Encoder
	pipes        Pipes
	limits       Limits
	deadline     time.Time
	parent       context.Context
	events       chan bridgeproto.Frame
	done         chan struct{}
	stopOnce     sync.Once
	workers      sync.WaitGroup
	mu           sync.Mutex
	stopping     bool
	err          error
	stopParent   func() bool
}

// New requires a bounded owner context and already-established native custody.
// A nonnil returned Owner owns pipe closure and custody even when err is nonnil.
// On a nil return ownership stays with the caller. No helper executable or
// confidential policy is accepted from the wire. The context covers preparation
// and execution; include the admitted execution timeout in its absolute deadline.
func New(ctx context.Context, binding bridgeproto.Binding, pipes Pipes, limits Limits) (*Owner, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || time.Until(deadline) <= 0 || time.Until(deadline) > 24*time.Hour ||
		pipes.Input == nil || pipes.Output == nil || pipes.Diagnostics == nil || absentCustody(pipes.Custody) ||
		pipes.Input == pipes.Output || pipes.Input == pipes.Diagnostics || pipes.Output == pipes.Diagnostics {
		return nil, ErrClosed
	}
	if limits.WriteTimeout <= 0 || limits.WriteTimeout > 30*time.Second || limits.CleanupTimeout <= 0 || limits.CleanupTimeout > 30*time.Second {
		return nil, ErrClosed
	}
	conversation, err := bridgeproto.NewConversation(binding)
	if err != nil {
		return nil, err
	}
	identities := map[uintptr]bool{}
	var nativeIDs []uintptr
	for _, file := range []*os.File{pipes.Input, pipes.Output, pipes.Diagnostics} {
		// Fd can change a Unix pipe's blocking mode. Inspect its identity through
		// RawConn instead, keeping Go's deadline-capable pipe ownership intact.
		conn, err := file.SyscallConn()
		if err != nil {
			return nil, ErrClosed
		}
		var id uintptr
		if conn.Control(func(fd uintptr) { id = fd }) != nil || identities[id] {
			return nil, ErrClosed
		}
		identities[id] = true
		nativeIDs = append(nativeIDs, id)
	}
	if err := distinctPipeObjects([]*os.File{pipes.Input, pipes.Output, pipes.Diagnostics}, nativeIDs); err != nil {
		return nil, err
	}
	o := &Owner{binding: binding, conversation: conversation, pipes: pipes, limits: limits, deadline: deadline,
		encoder: bridgeproto.NewEncoder(pipes.Input), events: make(chan bridgeproto.Frame, 32), done: make(chan struct{}), parent: ctx}
	// Deadline support is mandatory: ordinary files, borrowed stdio and handles
	// that could leave a synchronous writer stuck do not qualify as peer pipes.
	for _, f := range []*os.File{pipes.Input, pipes.Output, pipes.Diagnostics} {
		info, statErr := f.Stat()
		if statErr != nil || info.Mode()&os.ModeNamedPipe == 0 || f.SetDeadline(deadline) != nil {
			o.stop(ErrClosed)
			return o, ErrClosed
		}
	}
	o.workers.Add(2)
	go o.readFrames()
	go o.drainDiagnostics()
	o.stopParent = context.AfterFunc(ctx, func() { o.stop(ctx.Err()) })
	if err := ctx.Err(); err != nil {
		o.stop(err)
		return o, err
	}
	return o, nil
}

func absentCustody(custody Custody) bool {
	if custody == nil {
		return true
	}
	value := reflect.ValueOf(custody)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	}
	return false
}

func (o *Owner) isStopping() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.stopping
}

func (o *Owner) initialized() bool {
	return o != nil && o.parent != nil && o.conversation != nil && o.encoder != nil && o.done != nil
}

func (o *Owner) Send(ctx context.Context, command Command) (uint64, error) {
	if !o.initialized() {
		return 0, ErrClosed
	}
	// Cancellation also closes the writer when this caller is waiting for the
	// serialized command slot; no per-call blocked I/O goroutine is created.
	stopCancel := context.AfterFunc(ctx, func() { o.stop(ctx.Err()) })
	defer stopCancel()
	o.writeMu.Lock()
	defer o.writeMu.Unlock()
	if err := ctx.Err(); err != nil {
		o.stop(err)
		return 0, err
	}
	if err := o.parent.Err(); err != nil {
		o.stop(err)
		return 0, err
	}
	if o.isStopping() {
		return 0, ErrClosed
	}
	frame := bridgeproto.Frame{Version: bridgeproto.Version, Sequence: o.sequence + 1, Request: o.request + 1,
		Binding: o.binding, Kind: command.Kind, Plan: command.Plan, Data: command.Data, Size: command.Size}
	if err := frame.Validate(); err != nil {
		o.stop(err)
		return 0, err
	}
	frame.Plan, frame.Data, frame.Size = clonePlan(frame.Plan), cloneData(frame.Data), cloneSize(frame.Size)
	if err := o.conversation.Host(frame); err != nil {
		o.stop(err)
		return 0, err
	}
	deadline := minDeadline(time.Now().Add(o.limits.WriteTimeout), o.deadline)
	if callerDeadline, ok := ctx.Deadline(); ok {
		deadline = minDeadline(deadline, callerDeadline)
	}
	if err := o.pipes.Input.SetWriteDeadline(deadline); err != nil {
		o.stop(err)
		return 0, err
	}
	if err := o.encoder.Encode(frame); err != nil {
		o.stop(err)
		return 0, err
	}
	o.sequence, o.request = frame.Sequence, frame.Request
	return frame.Request, nil
}

func minDeadline(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func cloneSize(size *bridgeproto.Size) *bridgeproto.Size {
	if size == nil {
		return nil
	}
	copy := *size
	return &copy
}

func cloneData(data *bridgeproto.Data) *bridgeproto.Data {
	if data == nil {
		return nil
	}
	copy := *data
	copy.Bytes = append([]byte(nil), data.Bytes...)
	return &copy
}

func clonePlan(plan *bridgeproto.Preparation) *bridgeproto.Preparation {
	if plan == nil {
		return nil
	}
	copy := *plan
	copy.Argv = slices.Clone(plan.Argv)
	copy.Environment = slices.Clone(plan.Environment)
	copy.Filesystem.Read = slices.Clone(plan.Filesystem.Read)
	copy.Filesystem.Write = slices.Clone(plan.Filesystem.Write)
	copy.Filesystem.Deny = slices.Clone(plan.Filesystem.Deny)
	copy.Terminal = cloneSize(plan.Terminal)
	return &copy
}

func (o *Owner) readFrames() {
	defer o.workers.Done()
	decoder := bridgeproto.NewDecoder(o.pipes.Output)
	for {
		frame, err := decoder.Decode()
		if err != nil {
			o.stop(err)
			return
		}
		if err := o.conversation.Bridge(frame); err != nil {
			o.stop(err)
			return
		}
		select {
		case o.events <- frame:
		default:
			o.stop(ErrBackpressure)
			return
		}
		if frame.Kind == bridgeproto.Failed {
			o.stop(ErrPeer)
			return
		}
		if frame.Kind == bridgeproto.Destroyed {
			o.stop(nil)
			return
		}
	}
}

func (o *Owner) drainDiagnostics() {
	defer o.workers.Done()
	// Diagnostics can contain private backend information. Discard it; never
	// put it in errors, event payloads or ordinary operator logs.
	n, err := io.Copy(io.Discard, io.LimitReader(o.pipes.Diagnostics, (64<<10)+1))
	if n > 64<<10 {
		o.stop(ErrBackpressure)
		return
	}
	if err != nil {
		o.stop(ErrClosed)
	}
}

func (o *Owner) stop(cause error) {
	o.stopOnce.Do(func() {
		o.mu.Lock()
		o.stopping, o.err = true, cause
		o.mu.Unlock()
		// OS pipe closure interrupts every reader/writer before native cleanup.
		_ = o.pipes.Input.Close()
		_ = o.pipes.Output.Close()
		_ = o.pipes.Diagnostics.Close()
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), o.limits.CleanupTimeout)
			defer cancel()
			cleanupErr := o.pipes.Custody.StopAndWait(ctx)
			o.workers.Wait()
			o.mu.Lock()
			if cleanupErr != nil {
				o.err = errors.Join(o.err, ErrCleanup)
			}
			o.mu.Unlock()
			close(o.done)
		}()
	})
}

// Receive drains already-admitted frames before returning the final owner
// error. A Destroyed frame alone is not native cleanup success; Close must also
// complete without error before the caller releases its session reservation.
func (o *Owner) Receive(ctx context.Context) (bridgeproto.Frame, error) {
	if !o.initialized() {
		return bridgeproto.Frame{}, ErrClosed
	}
	check := func() error {
		if err := ctx.Err(); err != nil {
			o.stop(err)
			return err
		}
		if err := o.parent.Err(); err != nil {
			o.stop(err)
			return err
		}
		return nil
	}
	if err := check(); err != nil {
		return bridgeproto.Frame{}, err
	}
	select {
	case frame := <-o.events:
		if err := check(); err != nil {
			return bridgeproto.Frame{}, err
		}
		return frame, nil
	default:
	}
	select {
	case frame := <-o.events:
		if err := check(); err != nil {
			return bridgeproto.Frame{}, err
		}
		return frame, nil
	case <-ctx.Done():
		o.stop(ctx.Err())
		return bridgeproto.Frame{}, ctx.Err()
	case <-o.done:
		select {
		case frame := <-o.events:
			if err := check(); err != nil {
				return bridgeproto.Frame{}, err
			}
			return frame, nil
		default:
		}
		o.mu.Lock()
		defer o.mu.Unlock()
		if o.err != nil {
			return bridgeproto.Frame{}, o.err
		}
		return bridgeproto.Frame{}, io.EOF
	}
}

// Close ends the owned helper even if protocol preparation or launch failed.
// Its context bounds waiting, never substitutes for native cleanup. A timeout
// returns ErrCleanup and the native launcher must retain its resources.
func (o *Owner) Close(ctx context.Context) error {
	if !o.initialized() {
		return ErrClosed
	}
	o.stop(nil)
	if o.stopParent != nil {
		o.stopParent()
	}
	select {
	case <-ctx.Done():
		return errors.Join(ErrCleanup, ctx.Err())
	case <-o.done:
		o.mu.Lock()
		defer o.mu.Unlock()
		return o.err
	}
}
