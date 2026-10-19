// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package bridgeprocess

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"golang.org/x/sys/windows"
)

// These native tests use the current test image only as read-only PE input.
// All mappings/writes concern a fresh private COPY; no image is executed or
// passed to LoadLibrary and no child, process token or PSEC is created here.
func windowsImageFixture(t *testing.T) (root *os.File, directory string, source *os.File, expected string) {
	t.Helper()
	base := t.TempDir()
	directory = filepath.Join(base, "fixed-private-image-root")
	if _, err := safefile.CreatePrivateDirectory(directory); err != nil {
		t.Fatal(err)
	}
	root, err := os.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	name, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	info, err := original.Stat()
	if err != nil || info.Size() > 64<<20 {
		t.Fatal("fixed current test image exceeds fixture bound")
	}
	source, err = os.OpenFile(filepath.Join(base, "fixed-public-source-copy.exe"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = source.Close() })
	hash := sha256.New()
	if n, err := io.Copy(io.MultiWriter(source, hash), io.NewSectionReader(original, 0, info.Size())); err != nil || n != info.Size() {
		t.Fatal("copy current test image as inert fixture")
	}
	if err := source.Sync(); err != nil {
		t.Fatal(err)
	}
	return root, directory, source, "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func windowsImageEmpty(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatal("owned image copy cleanup did not complete")
	}
}

func TestWindowsImageOwnedCopyIgnoresSourceWritableViewAndPreservesOffset(t *testing.T) {
	root, directory, source, expected := windowsImageFixture(t)
	section, err := windows.CreateFileMapping(windows.Handle(source.Fd()), nil, windows.PAGE_READWRITE, 0, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(section)
	view, err := windows.MapViewOfFile(section, windows.FILE_MAP_READ|windows.FILE_MAP_WRITE, 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.UnmapViewOfFile(view)
	// Close the original writer while a writable view remains, then pass an
	// independently opened read-only source. A held original alone would not
	// protect it from this preexisting mapping; SealImageIn must make a copy.
	sourceName := source.Name()
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	source, err = os.Open(sourceName)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if _, err := source.Seek(17, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	image, err := SealImageIn(context.Background(), source, expected, root)
	if err != nil {
		if image != nil {
			_ = image.Close()
		}
		t.Fatal(err)
	}
	defer image.Close()
	if offset, err := source.Seek(0, io.SeekCurrent); err != nil || offset != 17 {
		t.Fatal("constructor changed caller source offset")
	}
	sourceID, err := windowsImageMetadata(source, false)
	if err != nil {
		t.Fatal(err)
	}
	imageID, err := windowsImageMetadata(image.file, false)
	if err != nil || sourceID == imageID {
		t.Fatal("immutable image reused the caller's file object")
	}
	// The fixture source's unused DOS-stub byte changes only after the copy is
	// admitted. The retained writable source view remains live through checks.
	var original [1]byte
	if n, err := source.ReadAt(original[:], 32); err != nil || n != 1 {
		t.Fatal("read the inert source copy's control byte")
	}
	altered := original[0] ^ 0x01
	var written uintptr
	if err := windows.WriteProcessMemory(windows.CurrentProcess(), view+32, &altered, 1, &written); err != nil || written != 1 {
		t.Fatal("write exactly one byte in the self-owned writable source mapping")
	}
	defer func() {
		var restored uintptr
		if err := windows.WriteProcessMemory(windows.CurrentProcess(), view+32, &original[0], 1, &restored); err != nil || restored != 1 {
			t.Error("restore the self-owned inert source mapping control byte")
		}
	}()
	if err := windows.FlushViewOfFile(view, 64); err != nil {
		t.Fatal(err)
	}
	var changed [1]byte
	if n, err := source.ReadAt(changed[:], 32); err != nil || n != 1 || changed[0] == original[0] {
		t.Fatal("source writable mapping positive control did not change its copy")
	}
	info, _ := image.file.Stat()
	if err := windowsImageDigest(context.Background(), image.file, info.Size(), expected); err != nil {
		t.Fatal("owned image followed source writable mapping")
	}
	if _, err := image.file.WriteAt([]byte("x"), 32); err == nil {
		t.Fatal("published image retained write access")
	}
	if mapping, err := windows.CreateFileMapping(windows.Handle(image.file.Fd()), nil, windows.PAGE_READWRITE, 0, 0, nil); err == nil {
		_ = windows.CloseHandle(mapping)
		t.Fatal("published image admitted a writable mapping")
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	if err := image.Close(); err != nil {
		t.Fatal(err)
	}
	windowsImageEmpty(t, directory)
}

func TestWindowsImageCloseRetainsOwnershipUntilDuplicatesRelease(t *testing.T) {
	root, directory, source, expected := windowsImageFixture(t)
	image, err := SealImageIn(context.Background(), source, expected, root)
	if err != nil {
		if image != nil {
			_ = image.Close()
		}
		t.Fatal(err)
	}
	defer image.Close()
	duplicate, err := image.duplicate()
	if err != nil {
		t.Fatal(err)
	}
	defer duplicate.Close()
	if err := image.Close(); !errors.Is(err, errWindowsImageCleanup) {
		t.Fatal("live strict duplicate did not preserve retryable cleanup")
	}
	if late, err := image.duplicate(); late != nil || !errors.Is(err, ErrAdmission) {
		t.Fatal("closed admission reopened while cleanup was pending")
	}
	var header [2]byte
	if n, err := duplicate.ReadAt(header[:], 0); err != nil || n != 2 || string(header[:]) != "MZ" {
		t.Fatal("cleanup invalidated a consumer's owned duplicate")
	}
	if err := duplicate.Close(); err != nil {
		t.Fatal(err)
	}
	if err := image.Close(); err != nil {
		t.Fatal("exact cleanup could not retry after consumer release")
	}
	if err := image.Close(); err != nil {
		t.Fatal("completed cleanup is not idempotent")
	}
	windowsImageEmpty(t, directory)
}

func TestWindowsImageCleanupNeverRecursivelyDeletesUnexpectedChildren(t *testing.T) {
	root, directory, source, expected := windowsImageFixture(t)
	image, err := SealImageIn(context.Background(), source, expected, root)
	if err != nil {
		if image != nil {
			_ = image.Close()
		}
		t.Fatal(err)
	}
	defer image.Close()
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 || !entries[0].IsDir() || !strings.HasPrefix(entries[0].Name(), "axis-image-") {
		t.Fatal("missing unique constructor-owned directory")
	}
	canary := filepath.Join(directory, entries[0].Name(), "fixed-unrelated-public.txt")
	if err := os.WriteFile(canary, []byte("fixed public data"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := image.Close(); !errors.Is(err, errWindowsImageCleanup) {
		t.Fatal("nonempty owned directory was treated as complete cleanup")
	}
	if raw, err := os.ReadFile(canary); err != nil || string(raw) != "fixed public data" {
		t.Fatal("cleanup traversed an unowned child")
	}
	if err := os.Remove(canary); err != nil {
		t.Fatal(err)
	}
	if err := image.Close(); err != nil {
		t.Fatal(err)
	}
	windowsImageEmpty(t, directory)
}

func TestWindowsImageRefusesWrongDigestAndCancelledAdmissionWithoutResidue(t *testing.T) {
	root, directory, source, expected := windowsImageFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, candidate := range []struct {
		ctx    context.Context
		digest string
	}{{context.Background(), ""}, {context.Background(), "sha256:" + strings.Repeat("A", 64)},
		{context.Background(), "sha256:" + strings.Repeat("0", 64)}, {ctx, expected}} {
		image, err := SealImageIn(candidate.ctx, source, candidate.digest, root)
		if image != nil || err == nil {
			if image != nil {
				_ = image.Close()
			}
			t.Fatal("invalid or cancelled construction admitted or lost cleanup")
		}
		windowsImageEmpty(t, directory)
	}
}

type windowsImageCancelWriter struct {
	bytes.Buffer
	cancel context.CancelFunc
}

func (writer *windowsImageCancelWriter) Write(data []byte) (int, error) {
	count, err := writer.Buffer.Write(data)
	writer.cancel()
	return count, err
}

func TestWindowsImageCopyObservesCancellationBetweenBoundedChunks(t *testing.T) {
	data := bytes.Repeat([]byte("fixed public bytes"), 8192)
	digest := sha256.Sum256(data)
	expected := "sha256:" + hex.EncodeToString(digest[:])
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	writer := &windowsImageCancelWriter{cancel: cancel}
	if err := windowsImageCopy(ctx, bytes.NewReader(data), writer, int64(len(data)), expected); !errors.Is(err, context.Canceled) {
		t.Fatal("copy ignored cancellation after its first bounded write")
	}
	if writer.Len() != 64<<10 {
		t.Fatal("copy continued writing after cancellation")
	}
}

func TestWindowsImageCleanupUncertaintyIsStickyAndNeverRetriesNativeClose(t *testing.T) {
	for _, failure := range []string{"view", "section"} {
		t.Run(failure, func(t *testing.T) {
			unmapCalls, closeCalls := 0, 0
			state := &windowsImageState{view: 1, section: 2,
				unmap: func(uintptr) error {
					unmapCalls++
					if failure == "view" {
						return errors.New("fixed failure")
					}
					return nil
				},
				closeSection: func(windows.Handle) error {
					closeCalls++
					if failure == "section" {
						return errors.New("fixed failure")
					}
					return nil
				}}
			image := &Image{cleanup: state.close}
			if file, err := image.duplicate(); file != nil || !errors.Is(err, ErrAdmission) {
				t.Fatal("cleanup-only image carried launch authority")
			}
			for attempt := 0; attempt < 2; attempt++ {
				if err := image.Close(); !errors.Is(err, errWindowsImageCleanup) {
					t.Fatal("native cleanup failure became successful completion")
				}
			}
			if unmapCalls != 1 || closeCalls != 1 || !state.uncertain || state.empty() {
				t.Fatal("uncertain native close was retried or forgotten")
			}
		})
	}
}
