// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeowner"
	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeproto"
)

func TestLifecycleSuiteAndPlansAreClosedAndBaselineUnchanged(t *testing.T) {
	baseline, err := casesForSuite("baseline")
	if err != nil || !slices.Equal(baseline, []string{"argv", "stdio", "exit23", "boundaries"}) {
		t.Fatal("baseline cases changed")
	}
	for _, mode := range lifecycleCases {
		plan, err := lifecyclePlan(mode)
		if err != nil || plan.Validate() != nil || plan.Argv[0] != "/.defenseclaw/payload" || len(plan.Argv) != 2 || plan.Terminal != nil || !plan.Offline || plan.OutputLimit != outputLimit {
			t.Fatal("lifecycle plan escaped fixed offline image contract")
		}
		wantMode, wantLimit := "wait", uint32(15000)
		if mode == "tree-cancel" {
			wantMode = "tree-parent"
		}
		if mode == "wait-timeout" {
			wantLimit = 5000
		}
		if plan.Argv[1] != wantMode || plan.TimeoutMS != wantLimit {
			t.Fatal("lifecycle selector/deadline changed")
		}
	}
	for _, name := range []string{"", "auto", "tree-parent", "../../anything"} {
		if _, err := casesForSuite(name); err == nil {
			t.Fatal("arbitrary suite admitted")
		}
		if _, err := lifecyclePlan(name); err == nil {
			t.Fatal("arbitrary lifecycle payload admitted")
		}
	}
	opts, err := workerOptions([]string{"--receipt", "missing", "--evidence", "missing", "--suite", "lifecycle"})
	if err != nil || opts.suite != "lifecycle" {
		t.Fatal("fixed internal worker suite was lost")
	}
	for _, args := range [][]string{{"--receipt", "missing", "--evidence", "missing", "--suite", "arbitrary"}, {"--receipt", "missing", "--evidence", "missing", "--command", "anything"}} {
		if _, err := workerOptions(args); err == nil {
			t.Fatal("internal worker accepted arbitrary selector")
		}
	}
	if _, err := parseOptions([]string{"--run-fixed", "--receipt", "missing", "--evidence", "missing", "--suite", "arbitrary"}); err == nil {
		t.Fatal("public wrapper accepted an arbitrary suite")
	}
	for _, code := range []string{"tree_setsid_precondition", "tree_setsid_denial"} {
		if reason, errno := fixedStderrReason([]byte("FIXED_NATIVE_FAILURE " + code + "\n")); reason != "payload_"+code || errno != "none" {
			t.Fatal("new payload refusal lost its closed diagnostic category")
		}
	}
}

func TestLifecycleMarkersRequireExactUniqueSetDespiteChunkOrder(t *testing.T) {
	text := "FIXED_NATIVE_TREE_READY tree-grandchild\nFIXED_NATIVE_TREE_READY tree-parent\nFIXED_NATIVE_TREE_READY tree-child\n"
	for i := 0; i <= len(text); i++ {
		ready, err := lifecycleMarkers("tree-cancel", text[:i])
		if err != nil || ready != (i == len(text)) {
			t.Fatalf("valid arbitrary frame boundary refused at %d", i)
		}
	}
	for _, bad := range []string{text + "extra\n", text + "FIXED_NATIVE_TREE_READY tree-child\n", strings.Replace(text, "tree-parent", "tree-other", 1), "\n"} {
		if _, err := lifecycleMarkers("tree-cancel", bad); err == nil {
			t.Fatal("unexpected/duplicate tree marker accepted")
		}
	}
	if ready, err := lifecycleMarkers("wait-timeout", ""); err != nil || ready {
		t.Fatal("empty stream proved payload readiness")
	}
}

type lifecycleFakeOwner struct {
	fakeOwner
	missing bool
	launch  uint64
}

func (f *lifecycleFakeOwner) Send(_ context.Context, command bridgeowner.Command) (uint64, error) {
	f.sent = append(f.sent, command)
	request := uint64(len(f.sent))
	switch command.Kind {
	case bridgeproto.Prepare:
		f.emit(bridgeproto.Prepared, request, nil, nil)
	case bridgeproto.Launch:
		f.launch = request
		f.emit(bridgeproto.Started, request, nil, nil)
		if !f.missing {
			output := "FIXED_NATIVE_WAIT_READY\n"
			if f.mode == "tree-cancel" {
				output = "FIXED_NATIVE_TREE_READY tree-child\nFIXED_NATIVE_TREE_READY tree-grandchild\nFIXED_NATIVE_TREE_READY tree-parent\n"
			}
			for _, chunk := range []string{output[:4], output[4:]} {
				f.emit(bridgeproto.Output, request, &bridgeproto.Data{Stream: "stdout", Bytes: []byte(chunk)}, nil)
			}
		}
	case bridgeproto.Wait:
		if f.mode == "wait-timeout" || f.missing {
			f.emit(bridgeproto.Exited, f.launch, nil, &bridgeproto.Result{ExitCode: -1, TimedOut: f.mode == "wait-timeout"})
		}
	case bridgeproto.Cancel:
		f.emit(bridgeproto.Exited, f.launch, nil, &bridgeproto.Result{ExitCode: -1})
	case bridgeproto.Destroy:
		f.emit(bridgeproto.Destroyed, request, nil, nil)
	}
	return request, nil
}

func TestLifecycleProtocolCorrelatesTimeoutCancelAndSeparateCleanup(t *testing.T) {
	for _, mode := range lifecycleCases {
		plan, _ := lifecyclePlan(mode)
		binding, _ := fixedBinding("fixed-lifecycle", "fixed-held-identity", plan, syntheticRegistry(t).Receipt)
		owner := &lifecycleFakeOwner{fakeOwner: fakeOwner{binding: binding, mode: mode}}
		observed := false
		before := func(context.Context) error {
			if slices.ContainsFunc(owner.sent, func(c bridgeowner.Command) bool { return c.Kind == bridgeproto.Cancel }) {
				t.Fatal("cancel preceded live tree file observation")
			}
			observed = true
			return nil
		}
		stable := false
		beforeDestroy := func(context.Context) error {
			if slices.ContainsFunc(owner.sent, func(c bridgeowner.Command) bool { return c.Kind == bridgeproto.Destroy }) {
				t.Fatal("Destroy preceded post-terminal tree observation")
			}
			stable = true
			return nil
		}
		result, err := exerciseLifecycle(context.Background(), owner, binding, plan, mode, before, beforeDestroy)
		if err != nil || !result.Prepared || !result.Started || !result.PayloadMarker || !result.Destroyed || !result.NativeTerminal || result.ExitCode != -1 || result.TimedOut != (mode == "wait-timeout") || result.CancelSent != (mode != "wait-timeout") || result.NativeCleanup || result.Passed {
			t.Fatalf("lifecycle protocol substituted for native cleanup: %+v %v", result, err)
		}
		if observed != (mode == "tree-cancel") || result.TreeReady != observed || result.TreeProgress != observed || result.TreeStable != stable || stable != observed {
			t.Fatal("protocol fabricated a held-file or post-terminal observation")
		}
		want := []bridgeproto.Kind{bridgeproto.Prepare, bridgeproto.Launch, bridgeproto.InputEOF, bridgeproto.Wait}
		if mode != "wait-timeout" {
			want = append(want, bridgeproto.Cancel)
		}
		want = append(want, bridgeproto.Destroy)
		var got []bridgeproto.Kind
		for _, command := range owner.sent {
			got = append(got, command.Kind)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatal("lifecycle command ordering changed")
		}
	}
}

func TestLifecycleProtocolRefusesUnreadyWrongExitAndMissingTreeObserver(t *testing.T) {
	for _, bad := range []string{"missing-marker", "wrong-timeout", "wrong-exit", "truncated", "wrong-binding", "wrong-request", "stderr"} {
		plan, _ := lifecyclePlan("wait-timeout")
		binding, _ := fixedBinding("fixed-lifecycle", "fixed-held-identity", plan, syntheticRegistry(t).Receipt)
		owner := &lifecycleFakeOwner{fakeOwner: fakeOwner{binding: binding, mode: "wait-timeout"}, missing: bad == "missing-marker"}
		owner.mutate = func(frame *bridgeproto.Frame) {
			if frame.Kind == bridgeproto.Output && bad == "stderr" {
				frame.Data.Stream = "stderr"
			}
			if frame.Kind != bridgeproto.Exited {
				return
			}
			switch bad {
			case "wrong-timeout":
				frame.Result.TimedOut = false
			case "wrong-exit":
				frame.Result.ExitCode = 0
			case "truncated":
				frame.Result.Truncated = true
			case "wrong-binding":
				frame.Binding.SessionID = "different-fixed-session"
			case "wrong-request":
				frame.Request++
			}
		}
		result, err := exerciseLifecycle(context.Background(), owner, binding, plan, "wait-timeout", nil, nil)
		if err == nil || result.Passed || result.NativeCleanup || result.NativeTerminal {
			t.Fatalf("invalid lifecycle observation accepted: %s", bad)
		}
	}
	plan, _ := lifecyclePlan("tree-cancel")
	binding, _ := fixedBinding("fixed-tree", "held", plan, syntheticRegistry(t).Receipt)
	for _, before := range []func(context.Context) error{nil, func(context.Context) error { return errors.New("fixed observation refusal") }} {
		owner := &lifecycleFakeOwner{fakeOwner: fakeOwner{binding: binding, mode: "tree-cancel"}}
		result, err := exerciseLifecycle(context.Background(), owner, binding, plan, "tree-cancel", before, nil)
		if err == nil || result.CancelSent || result.TreeProgress || result.Destroyed {
			t.Fatal("missing/failed held tree observation still sent cancellation")
		}
	}
	for _, observe := range []func(context.Context) error{nil, func(context.Context) error { return errors.New("fixed stability refusal") }} {
		owner := &lifecycleFakeOwner{fakeOwner: fakeOwner{binding: binding, mode: "tree-cancel"}}
		result, err := exerciseLifecycle(context.Background(), owner, binding, plan, "tree-cancel", func(context.Context) error { return nil }, observe)
		if err == nil || !result.CancelSent || !result.NativeTerminal || result.TreeStable || result.Destroyed || slices.ContainsFunc(owner.sent, func(c bridgeowner.Command) bool { return c.Kind == bridgeproto.Destroy }) {
			t.Fatal("missing/failed post-terminal observation was concealed by Destroy")
		}
	}
}
