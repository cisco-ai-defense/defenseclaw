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
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"

	"github.com/defenseclaw/defenseclaw/internal/envvars"
	"github.com/defenseclaw/defenseclaw/internal/sensor/acquire"
	"github.com/defenseclaw/defenseclaw/internal/sensor/kernelpolicy"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
	"github.com/defenseclaw/defenseclaw/internal/sensor/tetragon"
	pb "github.com/defenseclaw/defenseclaw/third_party/tetragon/api/v1/tetragon"
)

// This file connects the kernel-policy reconciler to the helper's Tetragon
// client, the event stream and the broker's kernel_status reply.

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

// startKernelPolicy runs the kernel-policy reconciler for the helper's
// lifetime and returns the event stream's Tetragon wiring: the drop-in's
// mode, the event dialer (none in off) and the hooks that feed the
// reconciler and answer kernel_status. The drop-in is read once, here.
func startKernelPolicy(ctx context.Context, logger *slog.Logger, homes []string, manifest string) *acquire.TetragonConfig {
	intent := kernelPolicyIntent(envvars.Lookup, logger)
	scope := tetragon.ScopeCleanup
	if intent.Mode.LoadsPolicies() {
		scope = tetragon.ScopePolicy
	}
	controller := kernelPolicyStart(ctx, logger, intent, policyDialer(scope), manifest)
	config := &acquire.TetragonConfig{
		Mode:             string(intent.Mode),
		OwnObservePolicy: func(name string) bool { return controller.OwnsPolicy(name, kernelpolicy.FamilyObserve) },
		KernelStatus: func(context.Context) (acquire.KernelStatus, error) {
			return kernelStatusOf(controller.Status(), intent.Mode), nil
		},
		Tap: hitTap(controller),
		Stream: func(state plane.StreamState) {
			controller.NoteStream(kernelpolicy.StreamStatus{
				Connected: state.Connected, Version: state.Version, PID: state.PID, Reason: state.Reason,
			})
		},
	}
	if intent.Mode != kernelpolicy.ModeOff {
		config.Dial = tetragon.NewDialer(tetragon.DialerConfig{Homes: homes, BinDir: helperBinDir()})
	}
	return config
}

func cleanupKernelPolicy(ctx context.Context, out io.Writer, logger *slog.Logger) error {
	return cleanupResult(kernelPolicyCleanup(ctx, logger, out, kernelpolicy.DefaultDirs(), policyDialer(tetragon.ScopeCleanup)))
}

// cleanupResult turns kernelPolicyCleanup's exit code into the command's
// result, keeping the code: the lifecycle tells "Tetragon did not answer"
// (3) from a failed cleanup (1).
func cleanupResult(code int) error {
	switch code {
	case cleanupOK:
		return nil
	case cleanupUnreachable:
		return &exitError{code: code, err: errors.New("tetragon cleanup incomplete: Tetragon is not reachable")}
	default:
		return &exitError{code: code, err: fmt.Errorf("tetragon cleanup incomplete (exit %d)", code)}
	}
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
//
// In off and consume no reconciler runs (Available is false), but the reply
// still names what the retire step has not removed yet, with its warnings and
// change records: that is how the gateway reports orphaned policies and
// emits the removals.
func kernelStatusOf(state kernelpolicy.State, mode kernelpolicy.Mode) acquire.KernelStatus {
	if !mode.LoadsPolicies() {
		status := acquire.KernelStatus{
			Available: false, Mode: string(mode), KernelPolicy: state.KernelPolicy,
			Reason:   "mode " + string(mode) + ": the helper only retires policies it recorded",
			Warnings: append([]string(nil), state.Warnings...),
		}
		if !state.UpdatedAt.IsZero() {
			status.UpdatedUnixNano = state.UpdatedAt.UnixNano()
		}
		if mode == kernelpolicy.ModeConsume {
			status.Tetragon = &acquire.KernelTetragon{
				Version: state.Tetragon.Version, PID: state.Tetragon.PID, Connected: state.Tetragon.Reachable,
			}
		}
		for _, name := range state.Loaded {
			family, _ := kernelpolicy.FamilyOfName(name)
			status.Policies = append(status.Policies, acquire.KernelPolicyStatus{Name: name, Family: string(family), Recorded: true})
		}
		status.Changes = kernelChanges(state.Changes)
		return status
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
	status.Changes = kernelChanges(state.Changes)
	return status
}

// kernelChanges is the change ring as the gateway drains it.
func kernelChanges(changes []kernelpolicy.Change) []acquire.KernelChange {
	var out []acquire.KernelChange
	for _, change := range changes {
		out = append(out, acquire.KernelChange{
			Seq: change.Seq, AtUnixNano: change.At.UnixNano(), Event: change.Event, Policy: change.Policy,
			Family: string(change.Family), Mode: string(change.Mode), State: change.State, UID: change.UID, Reason: change.Reason,
		})
	}
	return out
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
