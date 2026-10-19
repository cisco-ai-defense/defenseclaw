// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package bridgeowner

import "os"

func distinctPipeObjects(files []*os.File, _ []uintptr) error {
	for i, file := range files {
		info, err := file.Stat()
		if err != nil {
			return ErrClosed
		}
		for _, previous := range files[:i] {
			other, err := previous.Stat()
			if err != nil || os.SameFile(info, other) {
				return ErrClosed
			}
		}
	}
	return nil
}

func newPrivatePipe(direction Direction) (PrivatePipe, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return PrivatePipe{}, err
	}
	if direction == ToPeer {
		return PrivatePipe{w, r}, nil
	}
	return PrivatePipe{r, w}, nil
}
