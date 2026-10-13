// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package kernelpolicy

import (
	"context"
	"errors"
	"fmt"
)

// Client is the part of Tetragon's FineGuidanceSensors API the reconciler
// and the cleanup use. The sensor helper's Tetragon client implements it over
// the verified unix socket (internal/sensor/tetragon); tests use a fake.
// Nothing in this package dials: the caller hands over a connection that
// already passed the endpoint trust checks.
type Client interface {
	// Agent is GetVersion and, on 1.7.x, GetInfo (probes, configuration).
	Agent(ctx context.Context) (Agent, error)
	ListTracingPolicies(ctx context.Context) ([]LoadedPolicy, error)
	// AddTracingPolicy loads one TracingPolicy YAML document. The mode is
	// carried in the YAML (spec.options policy-mode), so a policy is never
	// loaded enforcing and then flipped.
	AddTracingPolicy(ctx context.Context, yaml []byte) error
	DeleteTracingPolicy(ctx context.Context, name string) error
	// ConfigureTracingPolicy sets the mode of a loaded policy in place.
	ConfigureTracingPolicy(ctx context.Context, name string, mode PolicyMode) error
}

// LoadedMode is a mode Tetragon reports. Anything but enforce counts as not
// enforcing, including a mode this build does not know.
type LoadedMode string

const (
	LoadedUnknown     LoadedMode = "unknown"
	LoadedEnforce     LoadedMode = "enforce"
	LoadedMonitor     LoadedMode = "monitor"
	LoadedMonitorOnly LoadedMode = "monitor_only"
)

// Enforcing reports whether Tetragon applies Override actions.
func (m LoadedMode) Enforcing() bool { return m == LoadedEnforce }

// LoadedState mirrors TracingPolicyState.
type LoadedState string

const (
	StateUnknown   LoadedState = "unknown"
	StateEnabled   LoadedState = "enabled"
	StateDisabled  LoadedState = "disabled"
	StateLoadError LoadedState = "load_error"
	StateError     LoadedState = "error"
	StateLoading   LoadedState = "loading"
	StateUnloading LoadedState = "unloading"
)

// LoadedPolicy is one entry of ListTracingPolicies.
type LoadedPolicy struct {
	Name  string      `json:"name"`
	Mode  LoadedMode  `json:"mode"`
	State LoadedState `json:"state"`
	Error string      `json:"error,omitempty"`
}

// Agent describes the Tetragon the helper reached.
type Agent struct {
	Version string `json:"version,omitempty"`
	// PID is the Tetragon pid named by tetragon-info.json and checked against
	// the socket peer. A change means Tetragon restarted and dropped every
	// policy added over gRPC.
	PID int `json:"pid,omitempty"`
	// LSMKnown and LSM come from the GetInfo probes (1.7.x).
	LSMKnown bool `json:"lsm_known,omitempty"`
	LSM      bool `json:"lsm,omitempty"`
	// KeepSensorsOnExitKnown is false when GetInfo's configuration was
	// unreadable; that caps enforcement exactly like a true value.
	KeepSensorsOnExitKnown bool `json:"keep_sensors_on_exit_known,omitempty"`
	KeepSensorsOnExit      bool `json:"keep_sensors_on_exit,omitempty"`
}

// supportsPolicies reports whether DefenseClaw may load policies: observe and
// enforce need 1.7.x (GetInfo, TP_MODE_MONITOR_ONLY, and the lowest schema
// the policies are rendered for).
func (a Agent) supportsPolicies() bool {
	var major, minor int
	version := a.Version
	if len(version) > 0 && version[0] == 'v' {
		version = version[1:]
	}
	if _, err := fmt.Sscanf(version, "%d.%d", &major, &minor); err != nil {
		return false
	}
	return major == 1 && minor == 7
}

// RPC names, for the allowlist and its test.
const (
	RPCAgent     = "GetVersion/GetInfo"
	RPCList      = "ListTracingPolicies"
	RPCAdd       = "AddTracingPolicy"
	RPCDelete    = "DeleteTracingPolicy"
	RPCConfigure = "ConfigureTracingPolicy"
)

// AllowedRPCs is the per-mode allowlist of Tetragon calls this package may
// make (GetEvents is the event source's). It is pinned by a test against a
// fake that fails on any other call.
func AllowedRPCs(mode Mode) []string {
	switch mode {
	case ModeOff:
		return []string{RPCList, RPCDelete}
	case ModeConsume:
		return []string{RPCAgent, RPCList, RPCDelete}
	case ModeObserve, ModeEnforce:
		return []string{RPCAgent, RPCList, RPCAdd, RPCDelete, RPCConfigure}
	}
	return nil
}

// ErrRPCNotAllowed is returned when a mode would need a call its allowlist
// does not hold.
var ErrRPCNotAllowed = errors.New("kernelpolicy: Tetragon call not allowed in this mode")

// guardedClient enforces the per-mode allowlist inside this package, on top
// of the Tetragon client's own: Delete only reaches a name that both has the
// DefenseClaw shape and that mayTouch (the helper's own record) admits.
type guardedClient struct {
	inner    Client
	allowed  map[string]bool
	mayTouch func(name string) bool
}

func guard(inner Client, mode Mode, mayTouch func(string) bool) guardedClient {
	allowed := map[string]bool{}
	for _, rpc := range AllowedRPCs(mode) {
		allowed[rpc] = true
	}
	return guardedClient{inner: inner, allowed: allowed, mayTouch: mayTouch}
}

func (g guardedClient) check(rpc string) error {
	if !g.allowed[rpc] {
		return fmt.Errorf("%w: %s", ErrRPCNotAllowed, rpc)
	}
	return nil
}

func (g guardedClient) Agent(ctx context.Context) (Agent, error) {
	if err := g.check(RPCAgent); err != nil {
		return Agent{}, err
	}
	return g.inner.Agent(ctx)
}

func (g guardedClient) ListTracingPolicies(ctx context.Context) ([]LoadedPolicy, error) {
	if err := g.check(RPCList); err != nil {
		return nil, err
	}
	return g.inner.ListTracingPolicies(ctx)
}

func (g guardedClient) AddTracingPolicy(ctx context.Context, yaml []byte) error {
	if err := g.check(RPCAdd); err != nil {
		return err
	}
	return g.inner.AddTracingPolicy(ctx, yaml)
}

func (g guardedClient) DeleteTracingPolicy(ctx context.Context, name string) error {
	if err := g.check(RPCDelete); err != nil {
		return err
	}
	if !IsDefenseClawName(name) || g.mayTouch == nil || !g.mayTouch(name) {
		return fmt.Errorf("%w: %s %q is not a name this helper recorded", ErrRPCNotAllowed, RPCDelete, name)
	}
	return g.inner.DeleteTracingPolicy(ctx, name)
}

func (g guardedClient) ConfigureTracingPolicy(ctx context.Context, name string, mode PolicyMode) error {
	if err := g.check(RPCConfigure); err != nil {
		return err
	}
	if !IsDefenseClawName(name) || g.mayTouch == nil || !g.mayTouch(name) {
		return fmt.Errorf("%w: %s %q is not a name this helper recorded", ErrRPCNotAllowed, RPCConfigure, name)
	}
	return g.inner.ConfigureTracingPolicy(ctx, name, mode)
}
