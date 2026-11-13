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
	// excludedAnswerTimeout bounds the hook's wait for the exclusion answer,
	// which the gateway reads from memory; a call waits this long at most.
	excludedAnswerTimeout = 3 * time.Second
	// ownStatusWriteTimeout bounds the server's write of the answer and its
	// wait for the client to close its end.
	ownStatusWriteTimeout = 2 * time.Second
)

// ServeOwnStatus answers requests on OwnStatusPipeName until ctx ends. answer
// gets the SID of the account whose token connected, read from the pipe client
// token, and returns that account's own state as JSON; an empty answer sends
// nothing. excluded answers ExcludedRequest the same way: whether the current
// machine policy excludes that account from enrollment. A request that is
// neither of the two, or from a token that is not a user account
// (AccountSID), gets no answer.
func ServeOwnStatus(ctx context.Context, answer func(sid string) []byte, excluded func(sid string) bool) error {
	return ServeOwn(ctx, OwnAnswers{Status: answer, Excluded: excluded})
}

// OwnAnswers are the answers of the own-status pipe, each for the SID of
// the account whose token connected. A nil answer leaves that request
// unanswered.
type OwnAnswers struct {
	Status   func(sid string) []byte
	Excluded func(sid string) bool
	// Routing answers RoutingRequest: the caller's own routing read of path
	// (ValidRoutingReadPath), as RoutingAnswer JSON.
	Routing func(sid, path string) []byte
}

// ServeOwn answers every own-status pipe request kind until ctx ends.
func ServeOwn(ctx context.Context, answers OwnAnswers) error {
	return serveOwn(ctx, OwnStatusPipeName, answers)
}

func serveOwnStatus(ctx context.Context, pipeName string, answer func(sid string) []byte, excluded func(sid string) bool) error {
	return serveOwn(ctx, pipeName, OwnAnswers{Status: answer, Excluded: excluded})
}

func serveOwn(ctx context.Context, pipeName string, answers OwnAnswers) error {
	return serveInstances(ctx, pipeName, MaxOwnStatusBytes, func(ctx context.Context, pipe windows.Handle) {
		answerPipeRequest(ctx, pipe, answers)
	})
}

// answerPipeRequest reads one request, names its sender and writes the answer.
func answerPipeRequest(ctx context.Context, pipe windows.Handle, answers OwnAnswers) {
	request := make([]byte, MaxRoutingRequestBytes+1)
	count, err := overlapped(ctx, serverReadTimeout, pipe, func(done *uint32, o *windows.Overlapped) error {
		return windows.ReadFile(pipe, request, done, o)
	})
	if err != nil || int(count) > MaxRoutingRequestBytes {
		return
	}
	kind := string(request[:count])
	routingPath, isRouting := ParseRoutingRequest(request[:count])
	if kind != OwnStatusRequest && kind != ExcludedRequest && !isRouting {
		return
	}
	sid, err := clientSID(pipe)
	if err != nil || !AccountSID(sid) {
		return
	}
	var body []byte
	limit := MaxOwnStatusBytes
	switch {
	case kind == ExcludedRequest:
		if answers.Excluded == nil {
			return
		}
		body = ExcludedAnswer(answers.Excluded(sid))
	case isRouting:
		if answers.Routing == nil {
			return
		}
		body, limit = answers.Routing(sid, routingPath), MaxRoutingAnswerBytes
	default:
		if answers.Status == nil {
			return
		}
		body = answers.Status(sid)
	}
	if len(body) == 0 || len(body) > limit {
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
	return askGateway(ctx, OwnStatusRequest, ownStatusAnswerTimeout, MaxOwnStatusBytes)
}

// OwnRouting asks the gateway service for the calling account's own routing
// read of path (ValidRoutingReadPath: its decisions and budgets only, the way
// the managed hook socket answers on Linux and macOS) and returns the HTTP
// status and JSON body the routing API gave.
func OwnRouting(ctx context.Context, path string) (int, []byte, error) {
	request, err := RoutingRequest(path)
	if err != nil {
		return 0, nil, err
	}
	answer, err := askGateway(ctx, string(request), ownStatusAnswerTimeout, MaxRoutingAnswerBytes)
	if err != nil {
		return 0, nil, err
	}
	return ParseRoutingAnswer(answer)
}

// AccountExcluded asks the running gateway service whether the machine
// policy it holds now excludes the calling account from enrollment
// (exclude_users). The gateway names the account from the pipe client token
// and judges it against its current configuration, which a standard account
// cannot read, so nothing the account can write or hold open decides the
// answer. Any failure, a gateway that is not running, a slow or malformed
// answer, is an error, and an error is never an exclusion.
func AccountExcluded(ctx context.Context) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, excludedAnswerTimeout)
	defer cancel()
	answer, err := askGateway(ctx, ExcludedRequest, excludedAnswerTimeout, MaxOwnStatusBytes)
	if err != nil {
		return false, err
	}
	return ParseExcludedAnswer(answer)
}

// askGateway writes request on the own-status pipe and returns the JSON
// answer, bounded by timeout.
func askGateway(ctx context.Context, request string, timeout time.Duration, limit int) ([]byte, error) {
	handle, err := dial(ctx, ownStatusClientPipeName)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(handle)
	message := []byte(request)
	written, err := overlapped(ctx, clientReceiptTimeout, handle, func(done *uint32, o *windows.Overlapped) error {
		return windows.WriteFile(handle, message, done, o)
	})
	if err != nil {
		return nil, err
	}
	if int(written) != len(message) {
		return nil, errors.New("the gateway request was not written whole")
	}
	answer := make([]byte, 0, 4096)
	chunk := make([]byte, 4096)
	deadline := time.Now().Add(timeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, errors.New("the gateway service sent no answer in time")
		}
		count, err := overlapped(ctx, remaining, handle, func(done *uint32, o *windows.Overlapped) error {
			return windows.ReadFile(handle, chunk, done, o)
		})
		answer = append(answer, chunk[:count]...)
		if len(answer) > limit {
			return nil, fmt.Errorf("the gateway service's answer is larger than %d bytes", limit)
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
