// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package refusalpipe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/windows"
)

// ownStatusClientPipeName is the pipe OwnStatus opens; a test seam.
var ownStatusClientPipeName = OwnStatusPipeName

const (
	// ownStatusAnswerTimeout bounds the client's wait for the answer: the
	// gateway names the account and reads the audit store
	// (coworkaudit.QueryTimeout) first.
	ownStatusAnswerTimeout = 15 * time.Second
	// ownStatusWriteTimeout bounds the server's write of the answer and its
	// wait for the client to close its end.
	ownStatusWriteTimeout = 2 * time.Second
)

// ServeOwnStatus answers own-status requests on OwnStatusPipeName until ctx
// ends. answer gets the SID of the account whose token connected, read from
// the pipe client token, and returns that account's own state as JSON; an
// empty answer sends nothing. A request that is not OwnStatusRequest, or
// from a token that is not a user account (AccountSID), gets no answer.
func ServeOwnStatus(ctx context.Context, answer func(sid string) []byte) error {
	return serveOwnStatus(ctx, OwnStatusPipeName, answer)
}

func serveOwnStatus(ctx context.Context, pipeName string, answer func(sid string) []byte) error {
	return serveInstances(ctx, pipeName, MaxOwnStatusBytes, func(ctx context.Context, pipe windows.Handle) {
		answerOwnStatus(ctx, pipe, answer)
	})
}

// answerOwnStatus reads one request, names its sender and writes the answer.
func answerOwnStatus(ctx context.Context, pipe windows.Handle, answer func(sid string) []byte) {
	request := make([]byte, len(OwnStatusRequest)+1)
	count, err := overlapped(ctx, serverReadTimeout, pipe, func(done *uint32, o *windows.Overlapped) error {
		return windows.ReadFile(pipe, request, done, o)
	})
	if err != nil || string(request[:count]) != OwnStatusRequest {
		return
	}
	sid, err := clientSID(pipe)
	if err != nil || !AccountSID(sid) {
		return
	}
	body := answer(sid)
	if len(body) == 0 || len(body) > MaxOwnStatusBytes {
		return
	}
	if _, err := overlapped(ctx, ownStatusWriteTimeout, pipe, func(done *uint32, o *windows.Overlapped) error {
		return windows.WriteFile(pipe, body, done, o)
	}); err != nil {
		return
	}
	// DisconnectNamedPipe drops what the client has not read yet, so wait,
	// bounded, for the client to read the answer and close its end.
	var closed [1]byte
	_, _ = overlapped(ctx, ownStatusWriteTimeout, pipe, func(done *uint32, o *windows.Overlapped) error {
		return windows.ReadFile(pipe, closed[:], done, o)
	})
}

// OwnStatus asks the gateway service for the calling account's own
// protection state and returns its JSON answer. It writes the request only
// when the pipe server is the running gateway service process, and lets the
// server identify, but never impersonate, the calling account
// (SECURITY_IDENTIFICATION). The request names no account: the gateway
// answers for the token that connected.
func OwnStatus(ctx context.Context) ([]byte, error) {
	handle, err := dial(ctx, ownStatusClientPipeName)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(handle)
	request := []byte(OwnStatusRequest)
	written, err := overlapped(ctx, clientReceiptTimeout, handle, func(done *uint32, o *windows.Overlapped) error {
		return windows.WriteFile(handle, request, done, o)
	})
	if err != nil {
		return nil, err
	}
	if int(written) != len(request) {
		return nil, errors.New("the own-status request was not written whole")
	}
	answer := make([]byte, 0, 4096)
	chunk := make([]byte, 4096)
	deadline := time.Now().Add(ownStatusAnswerTimeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, errors.New("the gateway service sent no answer in time")
		}
		count, err := overlapped(ctx, remaining, handle, func(done *uint32, o *windows.Overlapped) error {
			return windows.ReadFile(handle, chunk, done, o)
		})
		answer = append(answer, chunk[:count]...)
		if len(answer) > MaxOwnStatusBytes {
			return nil, fmt.Errorf("the gateway service's answer is larger than %d bytes", MaxOwnStatusBytes)
		}
		if len(answer) > 0 && json.Valid(answer) {
			return answer, nil
		}
		if err != nil {
			if errors.Is(err, windows.ERROR_BROKEN_PIPE) || errors.Is(err, windows.ERROR_PIPE_NOT_CONNECTED) {
				return nil, errors.New("the gateway service closed the pipe without an answer")
			}
			return nil, err
		}
	}
}
