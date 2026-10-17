// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package ipc

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	pb "github.com/defenseclaw/defenseclaw/proto/defenseclaw/secureclient/v1"
)

func runningManagedHealth() *gateway.SidecarHealth {
	h := gateway.NewSidecarHealth()
	h.SetGateway(gateway.StateRunning, "", nil)
	h.SetAPI(gateway.StateRunning, "", nil)
	h.SetGuardrail(gateway.StateRunning, "", nil)
	return h
}

// Managed inspection failing open used to leave the Secure Client GUI at
// READY; it now reports DEGRADED with a reason the UI can show.
func TestCurrentHealthReportsManagedInspectionUnavailable(t *testing.T) {
	h := runningManagedHealth()
	svc := &service{health: h, version: "test"}
	if got := svc.currentHealth(); got.Availability != pb.ServiceAvailability_SERVICE_AVAILABILITY_READY || got.AvailabilityReason != "" {
		t.Fatalf("healthy snapshot = %v/%q, want READY with no reason", got.Availability, got.AvailabilityReason)
	}

	h.SetManagedInspection(false, "managed cloud token unavailable", config.AIDUnavailableActionAllow)
	got := svc.currentHealth()
	if got.Availability != pb.ServiceAvailability_SERVICE_AVAILABILITY_DEGRADED ||
		got.AvailabilityReason != availabilityReasonInspectionUnavailableAllowing {
		t.Fatalf("fail-open snapshot = %v/%q, want DEGRADED/%s", got.Availability, got.AvailabilityReason,
			availabilityReasonInspectionUnavailableAllowing)
	}

	h.SetManagedInspection(true, "", config.AIDUnavailableActionAllow)
	if got := svc.currentHealth(); got.Availability != pb.ServiceAvailability_SERVICE_AVAILABILITY_READY {
		t.Fatalf("recovered snapshot = %v, want READY", got.Availability)
	}

	h.SetGuardrail(gateway.StateError, "managed_enterprise requires managed-cloud support", nil)
	got = svc.currentHealth()
	if got.Availability != pb.ServiceAvailability_SERVICE_AVAILABILITY_DEGRADED ||
		got.AvailabilityReason != availabilityReasonGuardrailError {
		t.Fatalf("guardrail error snapshot = %v/%q, want DEGRADED/%s", got.Availability, got.AvailabilityReason,
			availabilityReasonGuardrailError)
	}
}

type recordingHealthStream struct {
	grpc.ServerStream
	ctx  context.Context
	sent chan *pb.HealthSnapshot
}

func (s *recordingHealthStream) Context() context.Context { return s.ctx }

func (s *recordingHealthStream) Send(snapshot *pb.HealthSnapshot) error {
	s.sent <- snapshot
	return nil
}

func receiveHealth(t *testing.T, stream *recordingHealthStream) *pb.HealthSnapshot {
	t.Helper()
	select {
	case snapshot := <-stream.sent:
		return snapshot
	case <-time.After(5 * time.Second):
		t.Fatal("no health snapshot sent")
		return nil
	}
}

// A reason-only change (allowing → blocking) is a new message: the UI text
// differs even though availability stays DEGRADED.
func TestGetHealthStreamsReasonChanges(t *testing.T) {
	h := runningManagedHealth()
	h.SetManagedInspection(false, "token unavailable", config.AIDUnavailableActionAllow)
	svc := &service{health: h, version: "test", healthWait: 10 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := &recordingHealthStream{ctx: ctx, sent: make(chan *pb.HealthSnapshot, 8)}
	done := make(chan error, 1)
	go func() { done <- svc.GetHealth(&pb.GetHealthRequest{}, stream) }()

	first := receiveHealth(t, stream)
	if first.AvailabilityReason != availabilityReasonInspectionUnavailableAllowing {
		t.Fatalf("first reason = %q", first.AvailabilityReason)
	}
	h.SetManagedInspection(false, "token unavailable", config.AIDUnavailableActionBlock)
	second := receiveHealth(t, stream)
	if second.Availability != pb.ServiceAvailability_SERVICE_AVAILABILITY_DEGRADED ||
		second.AvailabilityReason != availabilityReasonInspectionUnavailableBlocking {
		t.Fatalf("second snapshot = %v/%q, want DEGRADED/%s", second.Availability, second.AvailabilityReason,
			availabilityReasonInspectionUnavailableBlocking)
	}
	cancel()
	<-done
}
