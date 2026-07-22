// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package ipc

import (
	"strings"
	"time"

	"google.golang.org/grpc"

	"github.com/defenseclaw/defenseclaw/internal/gateway"
	pb "github.com/defenseclaw/defenseclaw/proto/defenseclaw/secureclient/v1"
)

// service implements the three server-streaming RPCs defined by the
// AVC contract. Backed by SidecarHealth for GetHealth, audit.Store
// for GetStatsSnapshot, and the local broadcast for
// WatchNotifications.
type service struct {
	pb.UnimplementedDefenseClawSecureClientServiceServer

	health     *gateway.SidecarHealth
	statsSrc   statsSource
	bcast      *broadcast
	version    string
	nowFn      func() time.Time
	statsPoll  time.Duration
	healthWait time.Duration

	// logf receives structured log lines. Nil is treated as "do not
	// log"; the server wiring supplies a non-nil callback in
	// production so operators see stats-source errors in
	// gateway.log without them ever landing on the wire.
	logf func(format string, args ...any)
}

// GetHealth streams health snapshots per the contract: the first
// message is the current state; subsequent messages are sent when
// the mapped ServiceAvailability changes. Sends are debounced by
// healthWait so a flapping SetGateway does not storm the client.
func (s *service) GetHealth(req *pb.GetHealthRequest, stream grpc.ServerStreamingServer[pb.HealthSnapshot]) error {
	ctx := stream.Context()
	notify, cancel := s.health.Subscribe()
	defer cancel()

	last := s.currentHealth()
	if err := stream.Send(last); err != nil {
		return err
	}

	debounce := time.NewTimer(0)
	if !debounce.Stop() {
		<-debounce.C
	}
	defer debounce.Stop()

	pending := false
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case _, ok := <-notify:
			if !ok {
				return nil
			}
			if !pending {
				debounce.Reset(s.healthWait)
				pending = true
			}
		case <-debounce.C:
			pending = false
			cur := s.currentHealth()
			if cur.Availability != last.Availability {
				if err := stream.Send(cur); err != nil {
					return err
				}
				last = cur
			}
		}
	}
}

// GetStatsSnapshot streams aggregate counters. First message is
// immediate; subsequent messages are sent when any counter changes
// (or availability transitions) at a 2s poll cadence. Errors from
// the underlying counter source are logged locally and surfaced on
// the wire as availability=ERROR — never as a gRPC error, per the
// v1 contract's availability-enum design.
func (s *service) GetStatsSnapshot(req *pb.GetStatsSnapshotRequest, stream grpc.ServerStreamingServer[pb.StatsSnapshot]) error {
	ctx := stream.Context()

	last, err := snapshotStats(s.statsSrc)
	if err != nil {
		s.logStatsError(err)
	}
	if err := stream.Send(last); err != nil {
		return err
	}

	ticker := time.NewTicker(s.statsPoll)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			cur, err := snapshotStats(s.statsSrc)
			if err != nil {
				s.logStatsError(err)
			}
			if statsChanged(last, cur) {
				if err := stream.Send(cur); err != nil {
					return err
				}
				last = cur
			}
		}
	}
}

func (s *service) logStatsError(err error) {
	if s.logf == nil || err == nil {
		return
	}
	s.logf("stats source error: %v", err)
}

// WatchNotifications streams user-visible notifications. On
// subscribe, retained HISTORY / TRANSIENT_AND_HISTORY records that
// have not yet been fully delivered are replayed; TRANSIENT-only
// records are not.
//
// After every successful stream.Send the handler acks the record's
// sequence back to the broadcast. That ack is what lets the broadcast
// drop the record from the retained ring (deliver-and-forget). A
// disconnected client cannot ack — its cancel closure releases the
// pending marker but does not count as delivery, so the record stays
// retained for the next subscriber. See the contract on
// broadcast.subscribe / broadcast.ackSubscriber for the full
// eviction rules.
func (s *service) WatchNotifications(req *pb.WatchNotificationsRequest, stream grpc.ServerStreamingServer[pb.NotificationRecord]) error {
	ctx := stream.Context()
	ch, ack, cancel := s.bcast.subscribe()
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case rec, ok := <-ch:
			if !ok {
				return nil
			}
			if err := stream.Send(rec); err != nil {
				return err
			}
			// stream.Send returned nil — the record is on the wire.
			// Ack so the broadcast can evict from the retained ring
			// once every currently-live subscriber has done the same.
			// The ack itself is bounded and non-blocking; a slow
			// broadcast lock cannot wedge this stream.
			ack(rec.Sequence)
		}
	}
}

// currentHealth composes the wire HealthSnapshot from the internal
// SidecarHealth. version is a static, safe string ("v1.2.3" or
// "dev") — we tolerate an empty version by omitting the field
// rather than sending a placeholder that AVC might try to display.
func (s *service) currentHealth() *pb.HealthSnapshot {
	snap := s.health.Snapshot()
	return &pb.HealthSnapshot{
		SchemaVersion:      schemaVersion,
		Availability:       mapHealth(snap),
		DefenseClawVersion: strings.TrimSpace(s.version),
	}
}
