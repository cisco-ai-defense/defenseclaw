//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sort"

	"github.com/defenseclaw/defenseclaw/internal/sensor/acquire"
	"github.com/defenseclaw/defenseclaw/internal/sensor/kernelpolicy"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
	"github.com/defenseclaw/defenseclaw/internal/sensor/tetragon"
	pb "github.com/defenseclaw/defenseclaw/third_party/tetragon/api/v1/tetragon"
)

// This file fills the hooks main.go leaves for the kernel-policy reconciler
// (kernelPolicy): it connects the reconciler to the helper's Tetragon client,
// the event stream and the broker's kernel_status reply.
func init() {
	kernelPolicy = kernelPolicyHooks{start: startKernelPolicy, cleanup: cleanupKernelPolicy}
}

// policyDialer opens one short session per call, scoped to what the mode may
// do: ScopePolicy to load and change policies (observe and enforce), the
// list-and-delete scope for the retire step and the cleanup. Event streaming
// is a session of its own (tetragon.NewDialer).
func policyDialer(scope tetragon.Scope) kernelpolicy.DialFunc {
	return func(ctx context.Context) (kernelpolicy.Client, func(), error) {
		client, err := tetragon.Dial(ctx, tetragon.DialOptions{Scope: scope})
		if err != nil {
			return nil, nil, err
		}
		return policyClient{client: client}, func() { _ = client.Close() }, nil
	}
}

func startKernelPolicy(ctx context.Context, input kernelPolicyInput) kernelPolicyRuntime {
	intent := kernelPolicyIntent(input.Lookup, input.Logger)
	scope := tetragon.ScopeCleanup
	if intent.Mode.LoadsPolicies() {
		scope = tetragon.ScopePolicy
	}
	controller := kernelPolicyStart(ctx, input.Logger, input.Lookup, policyDialer(scope), input.Manifest)
	return kernelPolicyRuntime{
		OwnObservePolicy: func(name string) bool { return controller.OwnsPolicy(name, kernelpolicy.FamilyObserve) },
		Status: func(context.Context) (acquire.KernelStatus, error) {
			return kernelStatusOf(controller.Status(), intent.Mode), nil
		},
		Tap: hitTap(controller),
		Stream: func(connected bool) {
			controller.SetStream(connected)
			if connected {
				// A new session may mean Tetragon restarted and dropped the
				// policies added over gRPC: look at once.
				controller.Nudge()
			}
		},
	}
}

func cleanupKernelPolicy(ctx context.Context, out io.Writer, logger *slog.Logger) error {
	code := kernelPolicyCleanup(ctx, logger, out, kernelpolicy.DefaultDirs(), policyDialer(tetragon.ScopeCleanup), false)
	if code != cleanupOK {
		return fmt.Errorf("tetragon cleanup incomplete (exit %d)", code)
	}
	return nil
}

// hitSink is the part of the controller the event tap feeds.
type hitSink interface {
	RecordHit(kernelpolicy.Hit)
	RecordLoss()
}

// hitTap counts the events of DefenseClaw's own controls policies (the
// controller keeps only exact names it loaded) and the loss signals, from the
// stream the helper can vouch for. It must not block.
func hitTap(sink hitSink) func(plane.KernelBatch) {
	return func(batch plane.KernelBatch) {
		if batch.ThrottleStart || batch.Dropped > 0 {
			sink.RecordLoss()
		}
		for _, event := range batch.Events {
			if event.Policy == "" || event.UID == nil {
				continue
			}
			sink.RecordHit(kernelpolicy.Hit{
				Policy: event.Policy, UID: *event.UID, Path: event.Path, Binary: event.Exe, At: event.At,
			})
		}
	}
}

// kernelStatusOf is the broker's kernel_status reply: uids and counters and
// nothing a user did (no path, no command line). The root CLI reads the full
// state from the helper's files.
func kernelStatusOf(state kernelpolicy.State, mode kernelpolicy.Mode) acquire.KernelStatus {
	if !mode.LoadsPolicies() {
		return acquire.KernelStatus{
			Available: false, Mode: string(mode),
			Reason: "mode " + string(mode) + ": the helper only retires policies it recorded",
		}
	}
	status := acquire.KernelStatus{
		Available:    true,
		Mode:         state.Effective,
		KernelPolicy: state.KernelPolicy,
		Applied:      state.InSync,
		Warnings:     append([]string(nil), state.Warnings...),
		Counters:     map[string]int64{},
	}
	if status.Mode == "" {
		status.Mode = string(mode)
	}
	if !state.UpdatedAt.IsZero() {
		status.UpdatedUnixNano = state.UpdatedAt.UnixNano()
	}
	status.Tetragon = &acquire.KernelTetragon{
		Version: state.Tetragon.Version, PID: state.Tetragon.PID, Connected: state.Tetragon.Reachable,
		KeepSensorsOnExit: state.Tetragon.KeepSensorsOnExit, LSM: state.Tetragon.LSM,
	}
	for _, policy := range state.Policies {
		status.Policies = append(status.Policies, acquire.KernelPolicyStatus{
			Name: policy.Name, Family: string(policy.Family), Mode: string(policy.ObservedMode),
			State: string(policy.State), Error: policy.Error, Recorded: true,
		})
	}
	var wouldBlock, blocked int64
	for _, user := range state.UIDs {
		entry := acquire.KernelUserStatus{
			UID: user.UID, Mode: userMode(user.State), Connectors: user.Connectors, Reason: user.Reason,
			Ready:          user.NeededSeconds == 0 || user.CoveredSeconds >= user.NeededSeconds,
			CoveredSeconds: user.CoveredSeconds, BurnInSeconds: user.NeededSeconds,
		}
		if record := state.BurnIn.UIDs[fmt.Sprint(user.UID)]; record != nil {
			entry.Hits = map[string]int64{}
			for control, stats := range record.WouldBlock {
				entry.Hits[control] += int64(stats.Count)
				wouldBlock += int64(stats.Count)
			}
			for _, stats := range record.Blocked {
				blocked += int64(stats.Count)
			}
		}
		status.Users = append(status.Users, entry)
	}
	status.Counters["would_block"], status.Counters["blocked"] = wouldBlock, blocked
	status.Counters["roots_anchored"] = int64(state.Roots.Anchored)
	status.Counters["roots_over_limit"] = int64(state.Roots.OverLimit)
	for _, observed := range state.Roots.Observed {
		status.Counters["observed_not_enforced"] += int64(observed.Count)
	}
	if pause := state.Pause; pause != nil {
		switch {
		case pause.Pause != nil:
			status.Pause = &acquire.KernelPause{
				UntilReboot: pause.Pause.UntilReboot, SetByUID: pause.Pause.SetByUID, Reason: pause.Pause.Reason,
			}
			if !pause.Pause.UntilReboot {
				status.Pause.UntilUnixNano = pause.Pause.Until.UnixNano()
			}
			status.Pause.SetAtUnixNano = pause.Pause.SetAt.UnixNano()
		case pause.Invalid != "":
			status.Pause = &acquire.KernelPause{Reason: "pause file untrusted: " + pause.Invalid}
		}
	}
	for family := range state.Overrides {
		status.Overrides = append(status.Overrides, string(family))
	}
	sort.Strings(status.Overrides)
	for _, change := range state.Changes {
		status.Changes = append(status.Changes, acquire.KernelChange{
			Seq: change.Seq, AtUnixNano: change.At.UnixNano(), Event: change.Event, Policy: change.Policy,
			Family: string(change.Family), Mode: string(change.Mode), State: change.State, UID: change.UID, Reason: change.Reason,
		})
	}
	return status
}

func userMode(state string) string {
	switch state {
	case kernelpolicy.UIDEnforcing:
		return "enforce"
	case kernelpolicy.UIDBurnIn:
		return "burnin"
	case kernelpolicy.UIDInactive:
		return "observe_only"
	}
	return "monitor"
}

// policyClient adapts the helper's checked Tetragon session to the
// reconciler's Client.
type policyClient struct {
	client *tetragon.Client
}

func (c policyClient) Agent(ctx context.Context) (kernelpolicy.Agent, error) {
	agent := kernelpolicy.Agent{Version: c.client.Version().Raw, PID: c.client.Info().PID}
	if agent.Version == "" {
		agent.Version = c.client.Version().String()
	}
	// Tetragon 1.6 has no GetInfo: the probes stay unknown, which caps
	// enforcement and (by version) observe.
	if info, err := c.client.GetInfo(ctx); err == nil {
		agent.LSM, agent.LSMKnown = info.Probe("lsm")
		agent.KeepSensorsOnExit, agent.KeepSensorsOnExitKnown = info.KeepSensorsOnExit()
	}
	return agent, nil
}

func (c policyClient) ListTracingPolicies(ctx context.Context) ([]kernelpolicy.LoadedPolicy, error) {
	listed, err := c.client.ListPolicies(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]kernelpolicy.LoadedPolicy, 0, len(listed))
	for _, policy := range listed {
		out = append(out, loadedPolicy(policy))
	}
	return out, nil
}

func loadedPolicy(policy *pb.TracingPolicyStatus) kernelpolicy.LoadedPolicy {
	return kernelpolicy.LoadedPolicy{
		Name:  policy.GetName(),
		Mode:  kernelpolicy.LoadedMode(tetragon.PolicyMode(policy.GetMode())),
		State: kernelpolicy.LoadedState(tetragon.PolicyState(policy.GetState())),
		Error: policy.GetError(),
	}
}

func (c policyClient) AddTracingPolicy(ctx context.Context, document []byte) error {
	_, err := c.client.AddPolicy(ctx, document)
	return err
}

func (c policyClient) DeleteTracingPolicy(ctx context.Context, name string) error {
	return c.client.DeletePolicy(ctx, name)
}

func (c policyClient) ConfigureTracingPolicy(ctx context.Context, name string, mode kernelpolicy.PolicyMode) error {
	target := pb.TracingPolicyMode_TP_MODE_MONITOR
	if mode == kernelpolicy.PolicyEnforce {
		target = pb.TracingPolicyMode_TP_MODE_ENFORCE
	}
	return c.client.ConfigurePolicy(ctx, name, target, nil)
}
