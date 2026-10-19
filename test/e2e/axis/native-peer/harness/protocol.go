// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeowner"
	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeproto"
)

const sentinel = "fixed-public-native-peer-canary\n"
const fixedInput = "fixed-public-input\x00\xff\n"
const outputLimit = 64 << 10

var fixedCases = []string{"argv", "stdio", "exit23", "boundaries"}

func fixedPlan(mode, outside string) (bridgeproto.Preparation, error) {
	plan := bridgeproto.Preparation{Backend: "bubblewrap", Argv: []string{"/.defenseclaw/payload", mode},
		Environment: []bridgeproto.Variable{{Name: "HOME", Value: "/home"}, {Name: "TMPDIR", Value: "/tmp"}, {Name: "DC_AXIS_FIXED_PAYLOAD", Value: "fixed-private-v1"}},
		Workdir:     "/work", Filesystem: bridgeproto.Filesystem{Read: []string{"/readonly"}, Write: []string{"/work", "/home", "/tmp"}, Deny: []string{}},
		Offline: true, TimeoutMS: 5000, OutputLimit: outputLimit}
	switch mode {
	case "argv":
		plan.Argv = append(plan.Argv, "", "a b", "a\"b", "tail\\", "λ-雪;$()`&|<>*?", "quoted space\\")
	case "boundaries":
		if !fixedOutside(outside) {
			return plan, errors.New("invalid fixed outside fixture identity")
		}
		plan.Argv = append(plan.Argv, outside)
	case "stdio", "exit23":
	default:
		return plan, errors.New("unknown contributor case")
	}
	return plan, plan.Validate()
}

func fixedOutside(value string) bool {
	const prefix, suffix = "/tmp/dc-axis-native-peer-", "/outside"
	if !strings.HasPrefix(value, prefix) || !strings.HasSuffix(value, suffix) {
		return false
	}
	id := strings.TrimSuffix(strings.TrimPrefix(value, prefix), suffix)
	return len(id) == 32 && strings.Trim(id, "0123456789abcdef") == ""
}

// Digests correlate this fixed contributor experiment only. They are neither
// a production ExecutionPolicy nor a translated PolicyReceipt/capability claim.
func fixedBinding(session, fixtureIdentity string, plan bridgeproto.Preparation, receipt artifactReceipt) (bridgeproto.Binding, error) {
	if len(receipt.Images) != 3 {
		return bridgeproto.Binding{}, errors.New("fixed artifact identity missing")
	}
	preparation, err := bridgeproto.PreparationDigest(plan)
	if err != nil {
		return bridgeproto.Binding{}, err
	}
	artifacts, err := json.Marshal(receipt)
	if err != nil {
		return bridgeproto.Binding{}, err
	}
	policy := "sha256:" + digestBytes([]byte(receipt.Scope+"\x00strict-sparse-readonly-root-offline-no-broker-no-hooks\x00"+preparation))
	runtime := "sha256:" + digestBytes(artifacts)
	harness := "sha256:" + receipt.Images[2].SHA
	full := session + "\x00" + fixtureIdentity + "\x00" + policy + "\x00" + runtime + "\x00" + harness
	b := bridgeproto.Binding{SessionID: session, SessionDigest: "sha256:" + digestBytes([]byte(full)), PolicyDigest: policy, RuntimeDigest: runtime, HarnessDigest: harness, PreparationHash: preparation}
	return b, b.Validate()
}

type protocolOwner interface {
	Send(context.Context, bridgeowner.Command) (uint64, error)
	Receive(context.Context) (bridgeproto.Frame, error)
}

type caseResult struct {
	Mode           string                 `json:"mode"`
	Passed         bool                   `json:"passed"`
	Prepared       bool                   `json:"prepared"`
	Started        bool                   `json:"started"`
	PayloadMarker  bool                   `json:"fixed_payload_marker_observed"`
	VersionOutput  bool                   `json:"claude_version_output_observed,omitempty"`
	ExitCode       int32                  `json:"exit_code"`
	Destroyed      bool                   `json:"destroyed"`
	NativeCleanup  bool                   `json:"native_cleanup_observed"`
	OutputBytes    int                    `json:"output_bytes"`
	StderrBytes    int                    `json:"stderr_bytes"`
	StderrReason   string                 `json:"stderr_reason"`
	StderrErrno    string                 `json:"stderr_errno"`
	Error          string                 `json:"error,omitempty"`
	ProtocolStage  string                 `json:"protocol_stage,omitempty"`
	PeerFailure    string                 `json:"peer_failure,omitempty"`
	TimedOut       bool                   `json:"timed_out"`
	CancelSent     bool                   `json:"cancel_sent"`
	TreeReady      bool                   `json:"tree_ready_files_verified,omitempty"`
	TreeProgress   bool                   `json:"tree_heartbeat_progress_observed,omitempty"`
	TreeStable     bool                   `json:"tree_heartbeat_stable_before_destroy,omitempty"`
	NativeTerminal bool                   `json:"native_terminal_before_outer_cleanup,omitempty"`
	TreeHeartbeats *treeHeartbeatEvidence `json:"tree_heartbeat_samples,omitempty"`
}

type fixedPeerFailure string

func (e fixedPeerFailure) Error() string { return string(e) }

func expectReply(ctx context.Context, owner protocolOwner, binding bridgeproto.Binding, request uint64, kind bridgeproto.Kind) error {
	frame, err := owner.Receive(ctx)
	if err != nil {
		return err
	}
	if frame.Validate() == nil && frame.Binding == binding && frame.Request == request && frame.Kind == bridgeproto.Failed {
		return fixedPeerFailure(frame.Failure.Code)
	}
	if frame.Validate() != nil || frame.Binding != binding || frame.Request != request || frame.Kind != kind {
		return errors.New("fixed protocol reply or binding differed")
	}
	return nil
}

func exercise(ctx context.Context, owner protocolOwner, binding bridgeproto.Binding, plan bridgeproto.Preparation, mode string) (result caseResult, resultErr error) {
	result.Mode = mode
	wantExit := int32(23)
	if mode == claudeVersionSuite {
		wantExit = 0
	}
	var stdout, stderr bytes.Buffer
	defer func() {
		// Retain counts and a closed diagnostic category even when a failed
		// exit or protocol reply prevents the exact success-stream checks.
		// Raw native bytes, paths and environment never enter these fields.
		result.OutputBytes, result.StderrBytes = stdout.Len(), stderr.Len()
		result.StderrReason, result.StderrErrno = fixedStderrReason(stderr.Bytes())
		var failure fixedPeerFailure
		if errors.As(resultErr, &failure) {
			result.PeerFailure = string(failure)
		}
	}()
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
	result.ProtocolStage = "input_and_wait"
	if mode == "stdio" {
		if _, err := owner.Send(ctx, bridgeowner.Command{Kind: bridgeproto.Input, Data: &bridgeproto.Data{Stream: "stdin", Bytes: []byte(fixedInput)}}); err != nil {
			return result, err
		}
	}
	if _, err := owner.Send(ctx, bridgeowner.Command{Kind: bridgeproto.InputEOF}); err != nil {
		return result, err
	}
	if _, err := owner.Send(ctx, bridgeowner.Command{Kind: bridgeproto.Wait}); err != nil {
		return result, err
	}
	result.ProtocolStage = "output_and_exit"
	exited := false
	for count := 0; count < 256; count++ {
		frame, err := owner.Receive(ctx)
		if err != nil {
			return result, err
		}
		if frame.Validate() != nil || frame.Binding != binding || frame.Request != launch {
			return result, errors.New("fixed output/result binding differed")
		}
		switch frame.Kind {
		case bridgeproto.Output:
			if stdout.Len()+stderr.Len()+len(frame.Data.Bytes) > min(outputLimit, int(plan.OutputLimit)) {
				return result, errors.New("fixed output exceeded aggregate bound")
			}
			if frame.Data.Stream == "stdout" {
				_, _ = stdout.Write(frame.Data.Bytes)
			} else {
				_, _ = stderr.Write(frame.Data.Bytes)
			}
		case bridgeproto.Failed:
			return result, fixedPeerFailure(frame.Failure.Code)
		case bridgeproto.Exited:
			result.ExitCode = frame.Result.ExitCode
			if frame.Result.ExitCode != wantExit || frame.Result.TimedOut || frame.Result.Truncated {
				return result, errors.New("fixed exit/timeout/truncation differed")
			}
			exited = true
		default:
			return result, errors.New("unexpected fixed execution event")
		}
		if exited {
			break
		}
	}
	if !exited {
		return result, errors.New("fixed event count exceeded")
	}
	want, wantErr := map[string]string{"argv": "FIXED_NATIVE_ARGV\n", "stdio": "FIXED_NATIVE_INPUT_READY\nFIXED_NATIVE_INPUT_EOF\n", "exit23": "FIXED_NATIVE_EXIT23\n", "boundaries": "FIXED_NATIVE_BOUNDARIES\n"}[mode], ""
	if mode == "stdio" {
		wantErr = "FIXED_NATIVE_STDERR\n"
	}
	if mode == claudeVersionSuite {
		want = claudeVersionOutput
	}
	if stdout.String() != want || stderr.String() != wantErr {
		return result, errors.New("fixed byte streams differed")
	}
	if mode == claudeVersionSuite {
		result.VersionOutput, result.NativeTerminal = true, true
	} else {
		result.PayloadMarker = true
	}
	result.ProtocolStage = "destroy"
	destroy, err := owner.Send(ctx, bridgeowner.Command{Kind: bridgeproto.Destroy})
	if err != nil {
		return result, err
	}
	if err := expectReply(ctx, owner, binding, destroy, bridgeproto.Destroyed); err != nil {
		return result, err
	}
	result.Destroyed = true
	result.ProtocolStage = "complete"
	return result, nil // native Close success remains independently mandatory
}

// fixedStderrReason is diagnostic only: it never authorizes execution or turns
// a failed case into a pass. Only validated, aggregate-bounded protocol output
// reaches it. Inspect a bounded first line, emit fixed vocabulary, and discard
// every dynamic suffix (including paths, IDs and OS text).
func fixedStderrReason(stderr []byte) (string, string) {
	if len(stderr) == 0 {
		return "none", "none"
	}
	line := stderr[:min(len(stderr), 4096)]
	if end := bytes.IndexByte(line, '\n'); end >= 0 {
		line = line[:end]
	}
	if bytes.HasPrefix(line, []byte("FIXED_NATIVE_FAILURE ")) {
		code := string(bytes.TrimPrefix(line, []byte("FIXED_NATIVE_FAILURE ")))
		switch code {
		case "selector", "cwd", "fixture", "environment_count", "extra_environment", "missing_environment", "arguments", "literal_argv", "outside_fixture", "input_bytes_or_eof", "timeout_not_enforced", "private_root_readonly", "readonly_positive", "private_write_fixture", "write_positive", "readonly_denial", "outside_read_denial", "outside_write_denial", "offline_socket_denial", "offline_socketpair_denial", "tree_setsid_precondition", "tree_setsid_denial", "tree_spawn", "tree_heartbeat_create", "tree_ready_write", "tree_heartbeat_write", "tree_cleanup_not_enforced":
			return "payload_" + code, "none"
		default:
			return "payload_unclassified", "none"
		}
	}
	if bytes.HasPrefix(line, []byte("runtime: failed to create new OS thread")) {
		return "go_runtime_thread", "none"
	}
	if bytes.HasPrefix(line, []byte("runtime:")) || bytes.HasPrefix(line, []byte("fatal error:")) || bytes.HasPrefix(line, []byte("panic:")) {
		return "go_runtime_failure", "none"
	}
	if !bytes.HasPrefix(line, []byte("bwrap: ")) {
		return "unclassified", "none"
	}
	message := bytes.TrimPrefix(line, []byte("bwrap: "))
	code := "bwrap_unclassified"
	for _, category := range []struct {
		prefix string
		code   string
	}{
		{"setting up uid map", "bwrap_uid_map"},
		{"setting up gid map", "bwrap_gid_map"},
		{"error writing to setgroups", "bwrap_setgroups"},
		{"open /proc/", "bwrap_proc_lookup"},
		{"Creating new namespace failed", "bwrap_namespace_create"},
		{"Can't read /proc/sys/kernel/overflow", "bwrap_overflow_ids"},
		{"Can't parse /proc/sys/kernel/overflow", "bwrap_overflow_ids"},
		{"Owned source mount cloning failed", "bwrap_owned_clone"},
		{"Owned detached mount attributes failed", "bwrap_owned_attributes"},
		{"Owned mount attachment failed", "bwrap_owned_attach"},
		{"Owned image", "bwrap_owned_image"},
		{"Private owned image", "bwrap_owned_image"},
		{"Namespace-local owned source", "bwrap_owned_local_source"},
		{"Original owned source", "bwrap_owned_source"},
		{"Private owned source", "bwrap_owned_local_source"},
		{"Owned source", "bwrap_owned_source"},
		{"Can't inspect original owned source", "bwrap_owned_source"},
		{"Can't inspect owned source", "bwrap_owned_source"},
		{"Can't read owned source", "bwrap_owned_source"},
		{"Can't retain original source", "bwrap_owned_source"},
		{"Can't retain namespace-local source", "bwrap_owned_local_source"},
		{"Owned readonly root", "bwrap_owned_root"},
		{"Can't make private owned root readonly", "bwrap_owned_root"},
		{"Owned FD mount", "bwrap_owned_setup"},
		{"Owned setup", "bwrap_owned_setup"},
		{"Can't retain new private owned destination root", "bwrap_owned_setup"},
		{"Can't ", "bwrap_setup"},
		{"Failed to ", "bwrap_setup"},
		{"setting up newroot bind", "bwrap_setup"},
		{"pivot_root", "bwrap_setup"},
		{"chdir ", "bwrap_setup"},
		{"execvp ", "bwrap_exec"},
		{"prctl(PR_SET_SECCOMP)", "bwrap_seccomp"},
	} {
		if bytes.HasPrefix(message, []byte(category.prefix)) {
			code = category.code
			break
		}
	}
	errno := "none"
	for _, candidate := range []struct{ suffix, code string }{
		{": Operation not permitted", "eperm"}, {": Permission denied", "eacces"},
		{": Invalid argument", "einval"}, {": No such file or directory", "enoent"},
		{": Function not implemented", "enosys"}, {": Read-only file system", "erofs"},
		{": Resource temporarily unavailable", "eagain"}, {": No space left on device", "enospc"},
	} {
		if bytes.HasSuffix(message, []byte(candidate.suffix)) {
			errno = candidate.code
			break
		}
	}
	return code, errno
}

func caseError(result *caseResult, err error) {
	result.Passed = err == nil && result.NativeCleanup
	if err != nil {
		result.Error = fmt.Sprintf("fixed_%s_failed", result.Mode)
	}
}
