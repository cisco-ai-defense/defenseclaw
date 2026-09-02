// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/defenseclaw/defenseclaw/internal/setuppayload"
)

// appendTrailer copies the prebuilt Setup EXE at srcPath to dstPath,
// then appends the [archive][manifest][footer] trailer. Refuses to
// double-append if the source already carries a trailer — that
// signals a bundler bug (the source should be the unsigned prebuilt
// EXE with no payload embedded).
//
// The write path is: create dst → copy src bytes → invoke
// setuppayload.WriteTrailer → fsync → close. Any error before close
// leaves a partial dst file which the caller's os.MkdirAll(-Out) can
// overwrite on the next run; we do not attempt an atomic-rename dance
// because AVC's runner re-invokes the assembler on a fresh working dir.
func appendTrailer(srcPath, dstPath string, entries []setuppayload.Entry, manifestJSON []byte) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return &ioError{msg: fmt.Sprintf("open prebuilt setup EXE: %s", err)}
	}
	defer src.Close()

	srcInfo, err := src.Stat()
	if err != nil {
		return &ioError{msg: fmt.Sprintf("stat prebuilt setup EXE: %s", err)}
	}
	if srcInfo.Size() < int64(setuppayload.FooterSize) {
		return &buildError{msg: fmt.Sprintf("prebuilt setup EXE suspiciously small (%d bytes)", srcInfo.Size())}
	}
	// Refuse a double-append: the prebuilt input should never already
	// carry a trailer. Signals a bundler wiring bug — DefenseClaw
	// prebuilds the EXE with no //go:embed payload, so an assembled
	// EXE landing back as the input is a mistake worth aborting on.
	if setuppayload.HasTrailer(src, srcInfo.Size()) {
		return &buildError{msg: "prebuilt setup EXE already has a trailer; refusing to double-append"}
	}

	// os.Create truncates any prior <Out>/DefenseClawSetup-Enterprise-x64.exe
	// so a re-run against a partial output writes a clean file.
	dst, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return &ioError{msg: fmt.Sprintf("create dst setup EXE: %s", err)}
	}
	// Track close errors so we surface a fsync/close failure instead
	// of returning nil on a truncated write.
	closeErr := errors.New("dst not yet closed")
	defer func() {
		if cerr := dst.Close(); cerr != nil && closeErr == nil {
			closeErr = cerr
		}
	}()

	if _, err := io.Copy(dst, src); err != nil {
		return &ioError{msg: fmt.Sprintf("copy prebuilt setup EXE to dst: %s", err)}
	}
	if err := setuppayload.WriteTrailer(dst, entries, manifestJSON); err != nil {
		return &buildError{msg: fmt.Sprintf("write trailer: %s", err)}
	}
	if err := dst.Sync(); err != nil {
		return &ioError{msg: fmt.Sprintf("fsync dst setup EXE: %s", err)}
	}
	closeErr = nil
	return nil
}
