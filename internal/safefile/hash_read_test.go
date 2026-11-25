// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package safefile

import (
	"crypto/sha256"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

func TestHashFileContentsChargesPartialRead(t *testing.T) {
	readErr := errors.New("read failed")
	for _, tc := range []struct {
		name   string
		reader io.Reader
		err    error
	}{
		{"early EOF", strings.NewReader("abc"), io.ErrUnexpectedEOF},
		{"read failure", io.MultiReader(strings.NewReader("abc"), iotest.ErrReader(readErr)), readErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			digest, consumed, err := hashFileContents(tc.reader, 6)
			if digest != ([sha256.Size]byte{}) || consumed != 3 || !errors.Is(err, tc.err) {
				t.Fatalf("digest %x, consumed %d, error %v", digest, consumed, err)
			}
		})
	}
}
