// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
)

func TestClaudeVersionDriverAdmissionCannotReuseBaselineWrapper(t *testing.T) {
	args := []string{"--run-fixed", "--suite", claudeVersionSuite, "--receipt", "missing", "--evidence", "missing"}
	for _, admission := range []wrapperAdmission{{VersionOnly: true}, {Reviewed: true, SHA: strings.Repeat("a", 64), Size: 128}} {
		called := false
		_, _, err := execute(args, admission, func(context.Context, options, wrapperAdmission, map[string]any, *cleanupOwner) error {
			called = true
			return nil
		})
		if err == nil || called {
			t.Fatal("version reached metadata/native worker without its separate wrapper admission")
		}
	}
	called := false
	_, _, err := execute(args, versionAdmission, func(_ context.Context, opts options, admission wrapperAdmission, record map[string]any, owner *cleanupOwner) error {
		called = true
		if opts.suite != claudeVersionSuite || admission != versionAdmission || owner == nil || record["execution_performed"] != false {
			t.Fatal("version identity changed before fake runner")
		}
		return nil
	})
	if err != nil || !called {
		t.Fatal("reviewed version admission did not reach injected fake runner")
	}
	if admissionForArgs(args) != versionAdmission || receiptForSuite(claudeVersionSuite) == receiptForSuite("baseline") || scopeForSuite(claudeVersionSuite) == scopeForSuite("lifecycle") {
		t.Fatal("distinct version identity lost")
	}
}

func TestClaudeVersionDriverSourcesAwaitNativeWait(t *testing.T) {
	failed := errors.New("owned wait unavailable")
	native := &fakeCustody{retryErr: failed}
	owner := &cleanupOwner{pending: []retainedSession{native}}
	closes := 0
	if owner.releaseResource(func() error { closes++; return nil }) != nil || closes != 0 {
		t.Fatal("loader released before wait")
	}
	if owner.retry() == nil || closes != 0 {
		t.Fatal("failed wait released loader")
	}
	native.retryErr = nil
	if owner.retry() != nil || closes != 1 || len(owner.heldResources) != 0 {
		t.Fatal("successful native wait did not release exact source")
	}
	parent, root, loader := new(os.File), new(os.File), new(os.File)
	if !slices.Equal(versionFixtureInputs(parent, root, nil), []*os.File{parent, root}) || !slices.Equal(versionFixtureInputs(parent, root, loader), []*os.File{parent, root, loader}) || 3+5+len(versionFixtureInputs(parent, root, loader))-1 != 10 {
		t.Fatal("driver loader FD10 handoff changed")
	}
}
