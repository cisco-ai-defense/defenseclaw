// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package bridgeprocess

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeowner"
	"golang.org/x/sys/unix"
)

func inertImageBytes() []byte {
	// Deliberately incomplete ELF; this is not executable code. These tests
	// never invoke Start, a native helper or a sandbox.
	data := make([]byte, 128)
	copy(data, "\x7fELF\x02\x01")
	data[18] = 62
	return data
}

func TestSealedImageCopyIsIndependentOfSourceNameAndOffset(t *testing.T) {
	data := inertImageBytes()
	name := filepath.Join(t.TempDir(), "inert-image")
	if err := os.WriteFile(name, data, 0600); err != nil {
		t.Fatal(err)
	}
	source, err := os.OpenFile(name, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if _, err := source.Seek(17, 0); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(data)
	image, err := SealImage(context.Background(), source, "sha256:"+hex.EncodeToString(hash[:]))
	if err != nil {
		t.Fatal(err)
	}
	defer image.Close()
	if offset, err := source.Seek(0, 1); err != nil || offset != 17 {
		t.Fatal("copy changed source offset")
	}
	if _, err := source.WriteAt([]byte("changed"), 0); err != nil {
		t.Fatal(err)
	}
	duplicate, err := image.duplicate()
	if err != nil {
		t.Fatal(err)
	}
	defer duplicate.Close()
	got := make([]byte, len(data))
	if n, err := duplicate.ReadAt(got, 0); err != nil || n != len(got) || !bytes.Equal(got, data) {
		t.Fatal("sealed copy followed a changed source")
	}
	if _, err := duplicate.WriteAt([]byte("changed"), 0); !errors.Is(err, unix.EPERM) {
		t.Fatalf("immutable image accepted write: %v", err)
	}
	if err := image.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := image.duplicate(); !errors.Is(err, ErrAdmission) {
		t.Fatal("closed image reopened by name")
	}
	if _, err := duplicate.ReadAt(got, 0); err != nil {
		t.Fatal("closing original revoked its already-owned duplicate")
	}
}

func TestImageRefusesWrongDigestAndCanceledCopy(t *testing.T) {
	name := filepath.Join(t.TempDir(), "inert-image")
	if err := os.WriteFile(name, inertImageBytes(), 0600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	for _, digest := range []string{"", "sha256:" + string(bytes.Repeat([]byte("A"), 64)), "sha256:" + string(bytes.Repeat([]byte("a"), 64))} {
		if image, err := SealImage(context.Background(), source, digest); image != nil || err == nil {
			t.Fatal("invalid image digest admitted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	hash := sha256.Sum256(inertImageBytes())
	if image, err := SealImage(ctx, source, "sha256:"+hex.EncodeToString(hash[:])); image != nil || err == nil {
		t.Fatal("canceled image copy admitted")
	}
}

func TestCleanupBeforeCreationPermanentlyRefusesLateStart(t *testing.T) {
	custody := &namespaceCustody{pidfd: -1, done: make(chan struct{})}
	if err := custody.StopAndWait(context.Background()); err != nil {
		t.Fatal(err)
	}
	command := &exec.Cmd{Path: "/__must_never_execute__"}
	pidfd := -1
	if err := custody.start(context.Background(), command, &pidfd, nil); !errors.Is(err, bridgeowner.ErrClosed) || command.Process != nil {
		t.Fatalf("cleanup allowed a late native start: %v", err)
	}
	if err := custody.StopAndWait(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRejectedExecPreparationClosesPendingCustody(t *testing.T) {
	custody := &namespaceCustody{pidfd: -1, done: make(chan struct{})}
	// Cmd.Err fails in Go before any fork/exec. This exercises the pending
	// ownership failure path without constructing a process or namespace.
	command := &exec.Cmd{Path: "/__must_never_execute__", Err: errors.New("fixed preflight refusal")}
	pidfd := -1
	if err := custody.start(context.Background(), command, &pidfd, nil); !errors.Is(err, ErrUnavailable) || command.Process != nil {
		t.Fatalf("missing creation failure: %v", err)
	}
	if err := custody.StopAndWait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !custody.closed || custody.started {
		t.Fatal("failed creation retained open admission")
	}
}

func TestPendingKernelStartDoesNotBlockCleanupDeadline(t *testing.T) {
	// Model a start in the kernel without constructing a process. Closing
	// admission must return the context error rather than wait on its mutex
	// or falsely report native completion. The native start owner is retained.
	custody := &namespaceCustody{pidfd: -1, done: make(chan struct{}), starting: true}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := custody.StopAndWait(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("pending start cleanup: %v", err)
	}
	if !custody.closed || custody.complete {
		t.Fatal("pending start cleanup lost ownership or claimed completion")
	}
	select {
	case <-custody.done:
		t.Fatal("unobserved native completion was synthesized")
	default:
	}
}
