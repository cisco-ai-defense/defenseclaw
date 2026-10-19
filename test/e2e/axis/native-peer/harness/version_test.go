// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeowner"
	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeproto"
)

func TestClaudeVersionFixtureEntriesRequireBoundedDirectoryEnd(t *testing.T) {
	for _, test := range []struct {
		name       string
		withLoader bool
		entries    []string
		accepted   bool
	}{
		{"empty-baseline", false, nil, true},
		{"single-loader", true, []string{claudeLoaderLeaf}, true},
		{"missing-loader", true, nil, false},
		{"loader-in-baseline", false, []string{claudeLoaderLeaf}, false},
		{"wrong-leaf", true, []string{"other"}, false},
		{"extra-entry", true, []string{claudeLoaderLeaf, "extra"}, false},
		{"many-entries", true, []string{claudeLoaderLeaf, "extra", "third"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			for _, name := range test.entries {
				if err := os.WriteFile(filepath.Join(root, name), []byte("public inert fixture entry"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			directory, err := os.Open(root)
			if err != nil {
				t.Fatal(err)
			}
			defer directory.Close()
			if err := verifyInitialFixtureEntries(directory, test.withLoader); (err == nil) != test.accepted {
				t.Fatalf("initial fixture admission = %v, want accepted=%v", err, test.accepted)
			}
		})
	}
}

func TestClaudeVersionSourcesRemainHeldUntilNativeWaitAndClose(t *testing.T) {
	waitErr, closeErr := errors.New("native wait unavailable"), errors.New("source close uncertain")
	session := &fakeSession{closeErr: waitErr, retryErr: waitErr}
	owner := &cleanupOwner{pending: []retainedSession{session}}
	closes := 0
	close := func() error { closes++; return closeErr }
	if owner.releaseResource(close) != nil || closes != 0 || len(owner.heldResources) != 1 {
		t.Fatal("source released before native wait")
	}
	if owner.retry() == nil || closes != 0 {
		t.Fatal("failed native wait released source")
	}
	session.retryErr = nil
	if !errors.Is(owner.retry(), closeErr) || closes != 1 || len(owner.pending) != 0 || len(owner.heldResources) != 1 {
		t.Fatal("uncertain source close lost custody")
	}
}

func TestClaudeVersionWorkerFileTableIsAnExactTail(t *testing.T) {
	parent, root, loader := new(os.File), new(os.File), new(os.File)
	base := versionFixtureInputs(parent, root, nil)
	version := versionFixtureInputs(parent, root, loader)
	if !slices.Equal(base, []*os.File{parent, root}) || !slices.Equal(version, []*os.File{parent, root, loader}) || 3+4+len(version)-1 != 9 {
		t.Fatal("worker loader FD slot changed")
	}
}

func TestClaudeVersionRegistryIsSeparateAndClosedOverReviewedInputs(t *testing.T) {
	r := fixedClaudeVersionRegistry()
	if r.validate() != nil || !r.supportsSuite(claudeVersionSuite) || r.supportsSuite("baseline") || r.supportsSuite("lifecycle") || liveRegistry.supportsSuite(claudeVersionSuite) {
		t.Fatal("version registry crossed suite authority")
	}
	// Reconstruct the exact externally reviewed JSON, rather than blessing a
	// caller digest. Canonical indentation/order is part of this fixed receipt.
	data, err := json.MarshalIndent(r.Receipt, "", "  ")
	data = append(data, '\n')
	if err != nil || digestBytes(data) != r.ReceiptSHA {
		t.Fatal("version typed receipt differs from reviewed bytes")
	}
	for _, change := range []string{"vendor", "signer", "loader", "size", "scope"} {
		v := fixedClaudeVersionRegistry()
		switch change {
		case "vendor":
			v.Receipt.Images[2].SHA = liveRegistry.Receipt.Images[2].SHA
		case "signer":
			v.Receipt.ClaudeVersion.Signer = "another-signer"
		case "loader":
			v.Receipt.Loader.SHA = v.Receipt.Images[0].SHA
		case "size":
			v.Receipt.Images[2].Size++
		case "scope":
			v.Receipt.Scope = harnessScope
		}
		if v.validate() == nil {
			t.Fatalf("changed %s input accepted", change)
		}
	}
	called := false
	args := []string{"--run-fixed", "--suite", claudeVersionSuite, "--receipt", "missing", "--evidence", "missing"}
	_, _, err = executeWithRegistry(args, liveRegistry, func(context.Context, options, reviewedRegistry, map[string]any, *cleanupOwner) error {
		called = true
		return nil
	})
	if err == nil || called {
		t.Fatal("baseline registry reached version supervisor")
	}
}

func TestClaudeVersionPlanIsLiteralOfflineAndHasOnlyTwoLibraryFiles(t *testing.T) {
	plan, err := claudeVersionPlan()
	if err != nil || plan.Validate() != nil || !plan.Offline || plan.Terminal != nil || plan.TimeoutMS != 10000 || plan.OutputLimit != 4096 {
		t.Fatal("version plan escaped fixed bounded headless offline scope")
	}
	if !slices.Equal(plan.Argv, []string{"/.defenseclaw/payload", "--version"}) || plan.Workdir != "/work" {
		t.Fatal("version plan changed its fixed command")
	}
	want := bridgeproto.Filesystem{Read: []string{"/lib/ld-musl-x86_64.so.1", "/lib/libc.musl-x86_64.so.1"},
		Write: []string{"/work", "/home", "/tmp"}, Deny: []string{}}
	if !reflect.DeepEqual(plan.Filesystem, want) || len(plan.Environment) != 2 || len(claudeVersionOutput) != 22 {
		t.Fatal("version scope acquired additional roots or environment")
	}
}

type versionFakeOwner struct{ fakeOwner }

func (f *versionFakeOwner) Send(_ context.Context, command bridgeowner.Command) (uint64, error) {
	f.sent = append(f.sent, command)
	request := uint64(len(f.sent))
	switch command.Kind {
	case bridgeproto.Prepare:
		f.emit(bridgeproto.Prepared, request, nil, nil)
	case bridgeproto.Launch:
		f.emit(bridgeproto.Started, request, nil, nil)
		// Deliberately split the exact output across protocol frames.
		for _, part := range []string{claudeVersionOutput[:3], claudeVersionOutput[3:]} {
			f.emit(bridgeproto.Output, request, &bridgeproto.Data{Stream: "stdout", Bytes: []byte(part)}, nil)
		}
		f.emit(bridgeproto.Exited, request, nil, &bridgeproto.Result{ExitCode: 0})
	case bridgeproto.Destroy:
		f.emit(bridgeproto.Destroyed, request, nil, nil)
	}
	return request, nil
}

func TestClaudeVersionObservationUsesBoundProtocolAndExactBytes(t *testing.T) {
	plan, err := claudeVersionPlan()
	if err != nil {
		t.Fatal(err)
	}
	binding, err := fixedBinding("synthetic-version", "synthetic-held-fixture", plan, syntheticRegistry(t).Receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"none", "bytes", "stderr", "exit", "timeout", "truncated", "binding", "request"} {
		t.Run(mutation, func(t *testing.T) {
			owner := &versionFakeOwner{fakeOwner: fakeOwner{binding: binding}}
			owner.mutate = func(frame *bridgeproto.Frame) {
				if frame.Kind == bridgeproto.Output {
					switch mutation {
					case "bytes":
						frame.Data.Bytes = []byte("different")
					case "stderr":
						frame.Data.Stream = "stderr"
					case "binding":
						frame.Binding.SessionID = "another-session"
					case "request":
						frame.Request++
					}
				}
				if frame.Kind == bridgeproto.Exited {
					switch mutation {
					case "exit":
						frame.Result.ExitCode = 23
					case "timeout":
						frame.Result.TimedOut = true
					case "truncated":
						frame.Result.Truncated = true
					}
				}
			}
			result, err := exercise(context.Background(), owner, binding, plan, claudeVersionSuite)
			if mutation != "none" {
				if err == nil || result.VersionOutput || result.Destroyed {
					t.Fatal("invalid version observation passed")
				}
				return
			}
			if err != nil || !result.Prepared || !result.Started || !result.VersionOutput || !result.Destroyed || !result.NativeTerminal || result.OutputBytes != 22 || result.StderrBytes != 0 || result.PayloadMarker || result.NativeCleanup {
				t.Fatalf("exact protocol observation = %+v, %v", result, err)
			}
			for _, command := range owner.sent {
				if command.Kind == bridgeproto.Input || command.Kind == bridgeproto.Cancel || command.Kind == bridgeproto.Resize {
					t.Fatal("version observation issued an unrelated control")
				}
			}
		})
	}
}
