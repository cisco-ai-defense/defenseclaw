// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package bridgeowner

import (
	"errors"
	"os"
	"testing"
	"time"
)

func TestPipeCapabilities(t *testing.T) {
	for _, direction := range []Direction{ToPeer, FromPeer} {
		pipe, err := NewPrivatePipe(direction)
		if err != nil {
			t.Fatal(err)
		}
		defer pipe.Parent.Close()
		defer pipe.Child.Close()
		if err := pipe.Parent.SetDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		if direction == FromPeer {
			var b [1]byte
			_, err = pipe.Parent.Read(b[:])
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("read deadline: %v", err)
			}
		}
	}
}
