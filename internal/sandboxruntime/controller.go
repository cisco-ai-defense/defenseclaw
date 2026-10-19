// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package sandboxruntime defines the shared sandbox control-plane contract.
package sandboxruntime

import (
	"context"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// Controller is the sandbox manager behind the sandbox REST API
// (/api/v1/sandbox/...). The OpenShell manager implements this contract for
// both per-user gateways and managed per-user sandbox daemons.
// Errors are *sandboxapi.Error; anything else is reported as internal.
type Controller interface {
	Status(ctx context.Context) (*sandboxapi.Status, error)
	List(ctx context.Context) ([]sandboxapi.Sandbox, error)
	Get(ctx context.Context, name string) (*sandboxapi.Sandbox, error)
	Create(ctx context.Context, req sandboxapi.CreateRequest) (*sandboxapi.Sandbox, error)
	Delete(ctx context.Context, name string, req sandboxapi.DeleteRequest) (*sandboxapi.DeleteResponse, error)
	Stop(ctx context.Context, name string) (*sandboxapi.Sandbox, error)
	Start(ctx context.Context, name string, req sandboxapi.StartRequest) (*sandboxapi.Sandbox, error)
	Undo(ctx context.Context, name string, req sandboxapi.UndoRequest) (*sandboxapi.UndoResponse, error)
	Review(ctx context.Context, name string, req sandboxapi.ReviewRequest) (*sandboxapi.ReviewResponse, error)
	// Accept records that the user kept the changes on top of a stopped
	// mounted sandbox's snapshot, so its next start takes a new one.
	Accept(ctx context.Context, name string, req sandboxapi.AcceptRequest) (*sandboxapi.Sandbox, error)
	// RunLog returns the log of the latest detached run the daemon kept
	// when it stopped the sandbox (its last lines lines; 0: all of it).
	RunLog(ctx context.Context, name string, lines int) (*sandboxapi.RunLog, error)
	// Destinations returns what the sandbox reached or tried to reach, by
	// host and kind (model provider, shadow AI, ...).
	Destinations(ctx context.Context, name string) (*sandboxapi.Destinations, error)
	// ReportWorkspace records a copy-mode workspace step the CLI ran.
	ReportWorkspace(ctx context.Context, name string, report sandboxapi.WorkspaceReport) error
	// Discover runs the AI discovery of a ready sandbox now.
	Discover(ctx context.Context, name string) (*sandboxapi.DiscoveryResult, error)
	// Processes returns a sandbox's process tree (empty while it is off).
	Processes(ctx context.Context, name string) (*sandboxapi.ProcessList, error)
	Approvals(ctx context.Context, sandbox string) ([]sandboxapi.Approval, error)
	DecideApproval(ctx context.Context, id string, d sandboxapi.ApprovalDecision) (*sandboxapi.ApprovalResult, error)
	Unblock(ctx context.Context, req sandboxapi.UnblockRequest) (*sandboxapi.UnblockResponse, error)
	Explain(ctx context.Context, req sandboxapi.ExplainRequest) (*sandboxapi.Explain, error)
	// PolicyTest judges destinations with a sandbox's egress policy.
	PolicyTest(ctx context.Context, req sandboxapi.PolicyTestRequest) (*sandboxapi.PolicyTestResult, error)
	// ActivitySince returns buffered activity after since.
	ActivitySince(since uint64, sandbox string) []sandboxapi.ActivityEvent
	// SubscribeActivity returns buffered activity after since and a
	// channel of later events; cancel ends the subscription. ok is false
	// when too many streams are open.
	SubscribeActivity(since uint64, sandbox string) (backlog []sandboxapi.ActivityEvent, events <-chan sandboxapi.ActivityEvent, cancel func(), ok bool)
}
