// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package safefile

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
)

func TestHashCaptureHashesWholeStreamAndRetainsExactBound(t *testing.T) {
	body := []byte("\xef\xbb\xbf---\r\nauthor: Example Team\r\n---\r\n" + strings.Repeat("benign runbook line\n", 5000))
	for _, keep := range []int{0, 64 << 10, len(body)} {
		digest, captured, consumed, err := hashFileContentsCapture(bytes.NewReader(body), int64(len(body)), keep)
		if err != nil || consumed != int64(len(body)) || digest != sha256.Sum256(body) {
			t.Fatalf("keep %d: digest %x, consumed %d, error %v", keep, digest, consumed, err)
		}
		if keep == 0 {
			if captured != nil {
				t.Fatal("capture-off allocated retained bytes")
			}
		} else if !bytes.Equal(captured, body[:min(keep, len(body))]) || cap(captured) != min(keep, len(body)) {
			t.Fatalf("keep %d: wrong retained bytes or capacity %d", keep, cap(captured))
		}
	}
}

func TestHashCaptureChargesFailedReadAndExposesNoPartialBytes(t *testing.T) {
	readErr := errors.New("bounded fixture read failure")
	for _, test := range []struct {
		name   string
		reader io.Reader
		want   error
	}{
		{"early EOF", strings.NewReader("abc"), io.ErrUnexpectedEOF},
		{"read error", io.MultiReader(strings.NewReader("abc"), iotest.ErrReader(readErr)), readErr},
	} {
		t.Run(test.name, func(t *testing.T) {
			digest, retained, consumed, err := hashFileContentsCapture(test.reader, 6, 6)
			if digest != ([sha256.Size]byte{}) || retained != nil || consumed != 3 || !errors.Is(err, test.want) {
				t.Fatalf("digest %x, retained %q, consumed %d, error %v", digest, retained, consumed, err)
			}
		})
	}
}

func TestHashOpenedCaptureReadsOnceAndDoesNotExceedAllowance(t *testing.T) {
	body := []byte("---\nauthor: Example Team\n---\n" + strings.Repeat("bounded fixture\n", 6000))
	path := filepath.Join(t.TempDir(), "SKILL.md")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	digest, retained, consumed, err := HashOpenedRegularFileBoundedCapture(file, int64(len(body)), len(body))
	if err != nil || consumed != int64(len(body)) || digest != sha256.Sum256(body) || !bytes.Equal(retained, body) {
		t.Fatalf("digest %x, retained %d, consumed %d, error %v", digest, len(retained), consumed, err)
	}
	position, err := file.Seek(0, io.SeekCurrent)
	if err != nil || position != consumed {
		t.Fatalf("read position %d, consumed %d, error %v", position, consumed, err)
	}
	limited, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer limited.Close()
	digest, retained, consumed, err = HashOpenedRegularFileBoundedCapture(limited, int64(len(body)-1), len(body))
	if !errors.Is(err, ErrReadLimit) || consumed != 0 || retained != nil || digest != ([sha256.Size]byte{}) {
		t.Fatalf("over-budget read returned bytes: retained %d, consumed %d, error %v", len(retained), consumed, err)
	}
}
