// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package refusalpipe

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// ImpersonateNamedPipeClient is not exported by golang.org/x/sys/windows.
var procImpersonateNamedPipeClient = windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateNamedPipeClient")

const (
	// serverInstances bounds concurrent clients; a slow client holds one
	// instance for at most serverReadTimeout.
	serverInstances   = 4
	serverReadTimeout = time.Second
	// clientRights is what any authenticated account may open the pipe
	// with: FILE_READ_DATA (the receipt), FILE_WRITE_DATA,
	// FILE_READ_ATTRIBUTES and SYNCHRONIZE, never FILE_CREATE_PIPE_INSTANCE
	// (FILE_APPEND_DATA), so no account can serve an instance of the
	// gateway's pipe.
	clientRights = "0x00100083"
	// receiptTimeout bounds the write of a receipt a client does not read.
	receiptTimeout = time.Second
)

// Receipt is the one byte the server writes once it has read a report and
// named its sender. A client that closed its end at once after the write
// lost about one report in ten: the server then read or identified a client
// that was gone (GAP-2639). The client waits for it before closing.
var Receipt = []byte{1}

// Serve accepts refusal reports on PipeName until ctx ends. handle gets the
// SID of the account whose token connected, read from the pipe client token,
// and the decoded report. A report from a token that is not a user account
// (AccountSID), or that does not decode, is dropped.
func Serve(ctx context.Context, handle func(sid string, report Report)) error {
	return serve(ctx, PipeName, handle)
}

func serve(ctx context.Context, pipeName string, handle func(sid string, report Report)) error {
	security, err := pipeSecurity()
	if err != nil {
		return err
	}
	slots := make(chan struct{}, serverInstances)
	// Return only once every accepted client has been handled, so a stop
	// that drains the audit afterwards sees its report (GAP-1253). A
	// handler holds its slot for at most serverReadTimeout plus handle.
	defer func() {
		for range serverInstances {
			slots <- struct{}{}
		}
	}()
	first := true
	for {
		select {
		case <-ctx.Done():
			return nil
		case slots <- struct{}{}:
		}
		pipe, err := createPipe(pipeName, security, first)
		if err != nil {
			<-slots
			// The first instance fails when another process created the
			// name first; never serve under a name someone else owns.
			return fmt.Errorf("create refusal pipe %s: %w", pipeName, err)
		}
		first = false
		if _, err := overlapped(ctx, 0, pipe, func(_ *uint32, o *windows.Overlapped) error {
			err := windows.ConnectNamedPipe(pipe, o)
			if errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
				return nil
			}
			return err
		}); err != nil {
			_ = windows.CloseHandle(pipe)
			<-slots
			if ctx.Err() != nil {
				return nil
			}
			continue
		}
		go func() {
			defer func() { <-slots }()
			defer windows.CloseHandle(pipe)
			defer windows.DisconnectNamedPipe(pipe)
			sid, report, ok := receive(ctx, pipe)
			if ok {
				handle(sid, report)
			}
		}()
	}
}

// receive reads one report and identifies its sender.
func receive(ctx context.Context, pipe windows.Handle) (string, Report, bool) {
	buffer := make([]byte, MaxMessageBytes+1)
	count, err := overlapped(ctx, serverReadTimeout, pipe, func(done *uint32, o *windows.Overlapped) error {
		return windows.ReadFile(pipe, buffer, done, o)
	})
	if err != nil || count == 0 || count > MaxMessageBytes {
		return "", Report{}, false
	}
	report, err := Decode(buffer[:count])
	if err != nil {
		return "", Report{}, false
	}
	sid, err := clientSID(pipe)
	if err != nil || !AccountSID(sid) {
		return "", Report{}, false
	}
	_, _ = overlapped(ctx, receiptTimeout, pipe, func(done *uint32, o *windows.Overlapped) error {
		return windows.WriteFile(pipe, Receipt, done, o)
	})
	return sid, report, true
}

// clientSID returns the user SID of the pipe client's token. It
// impersonates on a goroutine of its own, locked to its OS thread: if
// RevertToSelf fails, the goroutine exits still locked and the runtime
// discards the thread instead of reusing an impersonating one.
func clientSID(pipe windows.Handle) (string, error) {
	type result struct {
		sid string
		err error
	}
	done := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		if ok, _, callErr := procImpersonateNamedPipeClient.Call(uintptr(pipe)); ok == 0 {
			runtime.UnlockOSThread()
			done <- result{err: callErr}
			return
		}
		var token windows.Token
		openErr := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token)
		if err := windows.RevertToSelf(); err != nil {
			if openErr == nil {
				_ = token.Close()
			}
			done <- result{err: err}
			return
		}
		runtime.UnlockOSThread()
		if openErr != nil {
			// An anonymous client cannot be identified.
			done <- result{err: openErr}
			return
		}
		defer token.Close()
		user, err := token.GetTokenUser()
		if err != nil || user == nil || user.User.Sid == nil {
			done <- result{err: errors.New("refusal pipe client token has no user")}
			return
		}
		done <- result{sid: user.User.Sid.String()}
	}()
	r := <-done
	return r.sid, r.err
}

type security struct {
	descriptor *windows.SECURITY_DESCRIPTOR
	attributes windows.SecurityAttributes
}

// pipeSecurity gives SYSTEM, the gateway's own account and the gateway
// service SID full access and every authenticated account clientRights.
//
// The gateway service runs with a write-restricted token (service SID type
// RESTRICTED): creating a further instance of an existing pipe is a write,
// so it also needs an ACE for the service SID. Without one, every instance
// after the first was refused (Access is denied): serve gave up, waited 5 s
// and started over, and the reports sent in between were lost (GAP-2639).
func pipeSecurity() (*security, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return nil, errors.New("resolve the gateway process account")
	}
	descriptor, err := windows.SecurityDescriptorFromString(pipeSDDL(user.User.Sid.String()))
	if err != nil {
		return nil, fmt.Errorf("build refusal pipe security descriptor: %w", err)
	}
	return &security{
		descriptor: descriptor,
		attributes: windows.SecurityAttributes{
			Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
			SecurityDescriptor: descriptor,
		},
	}, nil
}

// pipeSDDL is the refusal pipe's security descriptor for the gateway
// process account owner.
func pipeSDDL(owner string) string {
	service := managed.WindowsServiceSIDString(managed.StandaloneWindowsGatewaySvc)
	return "O:" + owner + "D:P(A;;GA;;;SY)(A;;GA;;;" + owner + ")(A;;GA;;;" + service + ")(A;;" + clientRights + ";;;AU)"
}

func createPipe(name string, s *security, first bool) (windows.Handle, error) {
	pointer, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	flags := uint32(windows.PIPE_ACCESS_DUPLEX | windows.FILE_FLAG_OVERLAPPED)
	if first {
		flags |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE
	}
	handle, err := windows.CreateNamedPipe(
		pointer,
		flags,
		windows.PIPE_TYPE_MESSAGE|windows.PIPE_READMODE_MESSAGE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS,
		serverInstances,
		uint32(len(Receipt)),
		MaxMessageBytes,
		0,
		&s.attributes,
	)
	runtime.KeepAlive(s.descriptor)
	return handle, err
}

// overlapped runs one overlapped operation until it completes, ctx ends or
// timeout (when non-zero) passes, cancelling it in the last two cases.
func overlapped(
	ctx context.Context,
	timeout time.Duration,
	handle windows.Handle,
	operation func(*uint32, *windows.Overlapped) error,
) (uint32, error) {
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(event)
	o := &windows.Overlapped{HEvent: event}
	var count uint32
	err = operation(&count, o)
	if err == nil {
		return count, nil
	}
	if !errors.Is(err, windows.ERROR_IO_PENDING) {
		return 0, err
	}
	var deadline <-chan time.Time
	if timeout > 0 {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		deadline = timer.C
	}
	for {
		wait, waitErr := windows.WaitForSingleObject(event, 25)
		if waitErr == nil && wait == windows.WAIT_OBJECT_0 {
			err = windows.GetOverlappedResult(handle, o, &count, false)
			runtime.KeepAlive(o)
			return count, err
		}
		cancel := waitErr != nil
		if !cancel {
			select {
			case <-ctx.Done():
				cancel = true
			case <-deadline:
				cancel = true
			default:
			}
		}
		if cancel {
			_ = windows.CancelIoEx(handle, o)
			_ = windows.GetOverlappedResult(handle, o, &count, true)
			runtime.KeepAlive(o)
			if waitErr != nil {
				return 0, waitErr
			}
			return 0, errors.New("refusal pipe operation cancelled")
		}
	}
}
