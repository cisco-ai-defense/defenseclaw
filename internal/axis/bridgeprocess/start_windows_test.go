// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package bridgeprocess

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeowner"
	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeproto"
)

func TestWindowsStartAndOrdinarySealImageRefuseBeforeResourceOwnership(t *testing.T) {
	if image, err := SealImage(context.Background(), nil, ""); image != nil || !errors.Is(err, ErrUnavailable) {
		t.Fatal("ordinary Windows SealImage acquired authority")
	}
	bounded, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	canceled, cancelAlready := context.WithCancel(bounded)
	cancelAlready()
	plan, binding, _ := windowsBootstrapFixture(0, 0)
	for _, test := range []struct {
		ctx    context.Context
		inputs Inputs
	}{
		{nil, Inputs{}}, {context.Background(), Inputs{}}, {canceled, Inputs{}},
		{bounded, Inputs{Bubblewrap: &Image{}}},
	} {
		session, err := Start(test.ctx, binding, plan, test.inputs, bridgeowner.Limits{WriteTimeout: time.Second, CleanupTimeout: time.Second})
		if session != nil || !errors.Is(err, ErrAdmission) {
			t.Fatal("rejected Windows admission allocated a native owner")
		}
	}
}

// All tests here are pure/fake: no process, Job, token query, filesystem,
// native image query, pipe or sandbox is created. Native tests are separate
// reviewed work after the matching Windows Rust peer/transport exists.
func TestWindowsBeforeResumeRequiresJobAndExactImage(t *testing.T) {
	for _, refusal := range []string{"job", "image", "closed", "resume", ""} {
		t.Run("refusal_"+refusal, func(t *testing.T) {
			var observed []string
			step := func(name string) func() error {
				return func() error {
					observed = append(observed, name)
					if name == refusal || name == "resume" && refusal == "closed" {
						return bridgeowner.ErrClosed
					}
					return nil
				}
			}
			err := windowsBeforeResume(step("job"), step("image"), step("resume"))
			if (err != nil) != (refusal != "") {
				t.Fatal("refusal was not preserved")
			}
			expected := "job,image,resume"
			if refusal == "job" {
				expected = "job"
			}
			if refusal == "image" {
				expected = "job,image"
			}
			if strings.Join(observed, ",") != expected {
				t.Fatal("identity/Job failure reached a later operation")
			}
		})
	}
}

func TestWindowsPendingCreationCleanupLatchesAndRespectsContext(t *testing.T) {
	custody := &windowsCustody{starting: true, serial: make(chan struct{}, 1), launchDone: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := custody.StopAndWait(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("pending creation ignored cleanup deadline")
	}
	if !custody.closed || custody.complete {
		t.Fatal("cleanup lost the late-creation latch or fabricated completion")
	}
	select {
	case <-custody.launchDone:
		t.Fatal("pending kernel creation was relabeled done")
	default:
	}
}

func TestWindowsCloseOrCancelBetweenImageProofAndResumeNeverResumes(t *testing.T) {
	for _, reason := range []string{"close", "cancel"} {
		t.Run(reason, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			custody := &windowsCustody{}
			resumed := false
			err := windowsBeforeResume(func() error { return nil }, func() error {
				if reason == "cancel" {
					cancel()
				} else {
					custody.mu.Lock()
					custody.closed = true
					custody.mu.Unlock()
				}
				return nil
			}, func() error {
				return custody.resumeIfOpen(ctx, func() error { resumed = true; return nil })
			})
			if !errors.Is(err, bridgeowner.ErrClosed) || resumed {
				t.Fatal("late closed/canceled custody reached native resume")
			}
		})
	}
}

func TestWindowsClosedBeforeCreationCannotResumeOrAcquireAuthority(t *testing.T) {
	custody := &windowsCustody{serial: make(chan struct{}, 1), launchDone: make(chan struct{})}
	if err := custody.StopAndWait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := custody.begin(context.Background(), windowsPeerLaunch{}); !errors.Is(err, bridgeowner.ErrClosed) {
		t.Fatal("closed custody admitted late creation")
	}
	if !custody.closed || !custody.complete || custody.starting || custody.process != 0 {
		t.Fatal("late creation changed closed ownership")
	}
}

func TestWindowsLateChildCloseUncertaintyCannotBecomeCleanupSuccess(t *testing.T) {
	// A protocol cancellation may finish pre-creation cleanup before begin
	// rejects its not-yet-transferred child duplicates. A later failed close
	// remains uncertain even though native process/Job cleanup already finished.
	custody := &windowsCustody{complete: true, uncertain: true, serial: make(chan struct{}, 1), launchDone: make(chan struct{})}
	if err := custody.StopAndWait(context.Background()); !errors.Is(err, bridgeowner.ErrCleanup) {
		t.Fatal("late close uncertainty was relabeled complete")
	}
}

func windowsBootstrapFixture(read, write int) (bridgeproto.Preparation, bridgeproto.Binding, []windowsCapability) {
	plan := bridgeproto.Preparation{Backend: "windows_psec", Argv: []string{`C:\.defenseclaw\payload.exe`, "", "雪", "&|<>$"}, Environment: []bridgeproto.Variable{},
		Workdir: `C:\work`, Offline: true, TimeoutMS: 1000, OutputLimit: 4096,
		Filesystem: bridgeproto.Filesystem{Read: []string{}, Write: []string{}, Deny: []string{}}}
	for i := range read {
		plan.Filesystem.Read = append(plan.Filesystem.Read, fmt.Sprintf(`C:\read\fixed-%03d`, i))
	}
	for i := range write {
		plan.Filesystem.Write = append(plan.Filesystem.Write, fmt.Sprintf(`C:\write\fixed-%03d`, i))
	}
	hash := "sha256:" + strings.Repeat("1", 64)
	binding := bridgeproto.Binding{SessionID: "fixed", SessionDigest: hash, PolicyDigest: hash, RuntimeDigest: hash, HarnessDigest: hash}
	binding.PreparationHash, _ = bridgeproto.PreparationDigest(plan)
	caps := make([]windowsCapability, 2+read+write)
	for index := range caps {
		role := windowsCapabilityWrite
		if index == 0 {
			role = windowsCapabilityPayload
		} else if index == 1 {
			role = windowsCapabilityCWD
		} else if index < 2+read {
			role = windowsCapabilityRead
		}
		caps[index] = windowsCapability{role: role, directory: index > 0, inherited: uint64(index + 64), id: windowsImageID{Volume: 1, File: [16]byte{byte(index + 1), byte((index + 1) >> 8)}}}
	}
	return plan, binding, caps
}

func TestWindowsCapabilityPrefixIsFixedBoundedAndContainsOnlyInheritedObjects(t *testing.T) {
	plan, binding, caps := windowsBootstrapFixture(256, 256)
	encoded, err := encodeWindowsCapabilities(plan, binding, caps)
	if err != nil || len(encoded) != windowsCapabilityMaximum || len(windowsCapabilityMagic) != 16 {
		t.Fatal("maximum fixed capability table failed")
	}
	if string(encoded[:16]) != windowsCapabilityMagic || binary.BigEndian.Uint16(encoded[16:18]) != 1 || binary.BigEndian.Uint16(encoded[18:20]) != 514 ||
		binary.BigEndian.Uint16(encoded[20:22]) != 256 || binary.BigEndian.Uint16(encoded[22:24]) != 256 {
		t.Fatal("header count/version mismatch")
	}
	for index, cap := range caps {
		record := encoded[windowsCapabilityHeader+index*windowsCapabilityRecord:][:windowsCapabilityRecord]
		if record[0] != cap.role || !bytes.Equal(record[2:8], make([]byte, 6)) || binary.BigEndian.Uint64(record[8:16]) != cap.inherited ||
			binary.BigEndian.Uint64(record[16:24]) != cap.id.Volume || !bytes.Equal(record[24:40], cap.id.File[:]) {
			t.Fatal("capability role/handle/identity changed")
		}
	}
	for _, value := range []string{"C:\\", "payload.exe", "Environment", "PolicyDigest", "snow"} {
		if bytes.Contains(encoded, []byte(value)) {
			t.Fatal("unexpected string in handle capability prefix")
		}
	}
}

func TestWindowsCapabilityPrefixRefusesCorrelationCountRoleAndHandleSubstitution(t *testing.T) {
	for _, mutation := range []string{"binding", "count", "role", "duplicate", "zero", "pseudo", "kind", "identity"} {
		t.Run(mutation, func(t *testing.T) {
			plan, binding, caps := windowsBootstrapFixture(1, 1)
			switch mutation {
			case "binding":
				binding.PreparationHash = "sha256:" + strings.Repeat("2", 64)
			case "count":
				caps = caps[:len(caps)-1]
			case "role":
				caps[2].role = windowsCapabilityWrite
			case "duplicate":
				caps[2].inherited = caps[1].inherited
			case "zero":
				caps[2].inherited = 0
			case "pseudo":
				caps[2].inherited = ^uint64(0)
			case "kind":
				caps[1].directory = false
			case "identity":
				caps[2].id = windowsImageID{}
			}
			if _, err := encodeWindowsCapabilities(plan, binding, caps); !errors.Is(err, ErrAdmission) {
				t.Fatal("substituted capability prefix was admitted")
			}
		})
	}
}
