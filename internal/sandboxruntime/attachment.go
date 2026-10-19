// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sandboxruntime

import (
	"context"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// AttachController is optional on the existing manager. Attach atomically claims
// the one consumer of an already admitted, launched process, verifies the entire
// owned identity using name plus immutable SessionID, and admits current policy.
// It never executes the supplied name or launches/restarts a command. No provider
// should expose this interface until its concrete stream transport is qualified.
// ctx bounds admission only. A successful attachment is owned by the manager;
// canceling this completed admission context must not terminate its lifetime.
type AttachController interface {
	Attach(context.Context, string, sandboxapi.AttachRequest) (Attachment, error)
}

// Attachment exchanges bounded frames with an existing process. Send and Receive
// must honor ctx and use cancellable owned transports; wrapping arbitrary blocking
// io.Reader/io.Writer in orphanable goroutines does not satisfy this contract.
// There is one concurrent sender and receiver. Close cancels the owned operation,
// joins its workers and independently observes native cleanup within ctx. A failed
// close retains the manager's exact custody; a socket close is never cleanup proof.
// The manager lifetime bounds ownership independently of an HTTP request. Request
// cancellation/disconnection must abort partial Attach and end this attachment.
type Attachment interface {
	Send(context.Context, sandboxapi.AttachInput) error
	Receive(context.Context) (sandboxapi.AttachEvent, error)
	Close(context.Context) error
}
