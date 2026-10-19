// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeowner"
	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeproto"
)

var lifecycleCases = []string{"wait-timeout", "wait-cancel", "tree-cancel"}

// Counts describe only the three fixed public synthetic writers in role order.
// No process ID, pathname or arbitrary guest data belongs in this evidence.
type treeHeartbeatEvidence struct {
	Before        [3]uint64 `json:"before"`
	Progressed    [3]uint64 `json:"progressed"`
	Terminal      [3]uint64 `json:"terminal"`
	StableSamples int       `json:"stable_samples"`
}

func validSuite(suite string) bool {
	return suite == "baseline" || suite == "lifecycle" || suite == claudeVersionSuite
}

func casesForSuite(suite string) ([]string, error) {
	if suite == claudeVersionSuite {
		return []string{claudeVersionSuite}, nil
	}
	if suite == "baseline" {
		return append([]string{}, fixedCases...), nil
	}
	if suite == "lifecycle" {
		return append([]string{}, lifecycleCases...), nil
	}
	return nil, errors.New("unknown fixed contributor suite")
}

func lifecyclePlan(mode string) (bridgeproto.Preparation, error) {
	plan, _ := fixedPlan("exit23", "")
	switch mode {
	case "wait-timeout", "wait-cancel":
		plan.Argv[1] = "wait"
	case "tree-cancel":
		plan.Argv[1] = "tree-parent"
	default:
		return plan, errors.New("unknown fixed lifecycle case")
	}
	if mode != "wait-timeout" {
		plan.TimeoutMS = 15000
	}
	return plan, plan.Validate()
}

// Markers are an exact bounded set, never process IDs or lifecycle authority.
// Children may print their three complete lines in any order or frame chunks.
func lifecycleMarkers(mode, output string) (bool, error) {
	if mode != "tree-cancel" {
		const marker = "FIXED_NATIVE_WAIT_READY\n"
		if !strings.HasPrefix(marker, output) {
			return false, errors.New("fixed wait marker differs")
		}
		return output == marker, nil
	}
	want := map[string]bool{
		"FIXED_NATIVE_TREE_READY tree-parent":     false,
		"FIXED_NATIVE_TREE_READY tree-child":      false,
		"FIXED_NATIVE_TREE_READY tree-grandchild": false,
	}
	lines := strings.Split(output, "\n")
	for _, line := range lines[:len(lines)-1] {
		seen, ok := want[line]
		if !ok || seen {
			return false, errors.New("fixed tree marker differs or repeats")
		}
		want[line] = true
	}
	partial := lines[len(lines)-1]
	if partial != "" {
		for line, seen := range want {
			if !seen && strings.HasPrefix(line, partial) {
				return false, nil
			}
		}
		return false, errors.New("fixed tree marker prefix differs")
	}
	for _, seen := range want {
		if !seen {
			return false, nil
		}
	}
	return true, nil
}

// beforeCancel is only the held-work tree-file observer. It neither starts nor
// stops a process. Native ownership stays in the existing protocol Session.
func exerciseLifecycle(ctx context.Context, owner protocolOwner, binding bridgeproto.Binding, plan bridgeproto.Preparation, mode string, beforeCancel, beforeDestroy func(context.Context) error) (result caseResult, resultErr error) {
	result.Mode = mode
	var stdout, stderr bytes.Buffer
	defer func() {
		result.OutputBytes, result.StderrBytes = stdout.Len(), stderr.Len()
		result.StderrReason, result.StderrErrno = fixedStderrReason(stderr.Bytes())
		var failure fixedPeerFailure
		if errors.As(resultErr, &failure) {
			result.PeerFailure = string(failure)
		}
	}()
	if mode != "wait-timeout" && mode != "wait-cancel" && mode != "tree-cancel" {
		return result, errors.New("unknown fixed lifecycle case")
	}
	result.ProtocolStage = "prepare_send"
	prepare, err := owner.Send(ctx, bridgeowner.Command{Kind: bridgeproto.Prepare, Plan: &plan})
	if err != nil {
		return result, err
	}
	result.ProtocolStage = "prepare_reply"
	if err := expectReply(ctx, owner, binding, prepare, bridgeproto.Prepared); err != nil {
		return result, err
	}
	result.Prepared = true
	result.ProtocolStage = "launch_send"
	launch, err := owner.Send(ctx, bridgeowner.Command{Kind: bridgeproto.Launch})
	if err != nil {
		return result, err
	}
	result.ProtocolStage = "launch_reply"
	if err := expectReply(ctx, owner, binding, launch, bridgeproto.Started); err != nil {
		return result, err
	}
	result.Started = true
	started := time.Now()
	if _, err := owner.Send(ctx, bridgeowner.Command{Kind: bridgeproto.InputEOF}); err != nil {
		return result, err
	}
	if _, err := owner.Send(ctx, bridgeowner.Command{Kind: bridgeproto.Wait}); err != nil {
		return result, err
	}
	result.ProtocolStage = "lifecycle_output_and_exit"
	exited := false
	for count := 0; count < 256; count++ {
		frame, err := owner.Receive(ctx)
		if err != nil {
			return result, err
		}
		if frame.Validate() != nil || frame.Binding != binding || frame.Request != launch {
			return result, errors.New("fixed lifecycle event binding differed")
		}
		switch frame.Kind {
		case bridgeproto.Output:
			if stdout.Len()+stderr.Len()+len(frame.Data.Bytes) > outputLimit {
				return result, errors.New("fixed lifecycle aggregate output exceeded")
			}
			if frame.Data.Stream == "stderr" {
				_, _ = stderr.Write(frame.Data.Bytes)
				return result, errors.New("fixed lifecycle stderr was nonempty")
			}
			_, _ = stdout.Write(frame.Data.Bytes)
			ready, err := lifecycleMarkers(mode, stdout.String())
			if err != nil {
				return result, err
			}
			result.PayloadMarker = ready
			if ready && mode != "wait-timeout" && !result.CancelSent {
				if mode == "tree-cancel" {
					if beforeCancel == nil {
						return result, errors.New("fixed tree file observer missing")
					}
					checkCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
					err := beforeCancel(checkCtx)
					cancel()
					if err != nil {
						return result, err
					}
					result.TreeReady, result.TreeProgress = true, true
				}
				// Cancel must precede the 15s native plan deadline comfortably.
				// Late readiness is a failed experiment, never a timeout waiver.
				if time.Since(started) >= 5*time.Second {
					return result, errors.New("fixed cancellation readiness was late")
				}
				if _, err := owner.Send(ctx, bridgeowner.Command{Kind: bridgeproto.Cancel}); err != nil {
					return result, err
				}
				result.CancelSent = true
			}
		case bridgeproto.Failed:
			return result, fixedPeerFailure(frame.Failure.Code)
		case bridgeproto.Exited:
			result.ExitCode, result.TimedOut = frame.Result.ExitCode, frame.Result.TimedOut
			if !result.PayloadMarker || frame.Result.ExitCode != -1 || frame.Result.TimedOut != (mode == "wait-timeout") || frame.Result.Truncated || mode != "wait-timeout" && !result.CancelSent {
				return result, errors.New("fixed lifecycle terminal result differed")
			}
			// Pinned peer emits Exited only after native try_wait and both
			// native stdout/stderr EOFs, before host outer cleanup is invoked.
			result.NativeTerminal, exited = true, true
		default:
			return result, errors.New("unexpected fixed lifecycle event")
		}
		if exited {
			break
		}
	}
	if !exited {
		return result, errors.New("fixed lifecycle event count exceeded")
	}
	if mode == "tree-cancel" {
		if beforeDestroy == nil {
			return result, errors.New("fixed post-terminal tree observer missing")
		}
		result.ProtocolStage = "tree_stability_before_destroy"
		observeCtx, cancel := context.WithTimeout(ctx, time.Second)
		err := beforeDestroy(observeCtx)
		cancel()
		if err != nil {
			return result, err
		}
		result.TreeStable = true
	}
	result.ProtocolStage = "destroy"
	destroy, err := owner.Send(ctx, bridgeowner.Command{Kind: bridgeproto.Destroy})
	if err != nil {
		return result, err
	}
	if err := expectReply(ctx, owner, binding, destroy, bridgeproto.Destroyed); err != nil {
		return result, err
	}
	result.Destroyed, result.ProtocolStage = true, "complete"
	return result, nil
}
