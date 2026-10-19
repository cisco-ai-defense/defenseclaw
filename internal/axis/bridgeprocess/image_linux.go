// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package bridgeprocess

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

const imageBound int64 = 512 << 20
const imageSeals = unix.F_SEAL_SEAL | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_WRITE

func sealImage(ctx context.Context, source *os.File, expected string) (*Image, error) {
	if ctx.Err() != nil || source == nil || len(expected) != 71 || !strings.HasPrefix(expected, "sha256:") {
		return nil, ErrAdmission
	}
	digest, err := hex.DecodeString(expected[7:])
	if err != nil || len(digest) != sha256.Size || strings.ToLower(expected) != expected {
		return nil, ErrAdmission
	}
	info, err := source.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 20 || info.Size() > imageBound || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		return nil, ErrAdmission
	}
	fd, err := unix.MemfdCreate("defenseclaw-admitted-image", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, ErrUnavailable
	}
	file := os.NewFile(uintptr(fd), "private-axis-image")
	accepted := false
	defer func() {
		if !accepted {
			_ = file.Close()
		}
	}()
	hash := sha256.New()
	// ReadAt leaves the caller's offset alone. The bound is fixed before the
	// copy; truncation, mutation or growth cannot create an admitted different
	// image because only the sealed copy's exact bytes and digest are accepted.
	reader := io.NewSectionReader(source, 0, info.Size())
	buffer := make([]byte, 64<<10)
	var total int64
	for total < info.Size() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, readErr := reader.Read(buffer)
		if n > 0 {
			if _, err := file.Write(buffer[:n]); err != nil {
				return nil, ErrAdmission
			}
			_, _ = hash.Write(buffer[:n])
			total += int64(n)
		}
		if readErr != nil && readErr != io.EOF || n == 0 && total != info.Size() {
			return nil, ErrAdmission
		}
	}
	if total != info.Size() || hex.EncodeToString(hash.Sum(nil)) != expected[7:] || ctx.Err() != nil {
		return nil, ErrAdmission
	}
	var header [20]byte
	if n, err := file.ReadAt(header[:], 0); err != nil || n != len(header) ||
		string(header[:6]) != "\x7fELF\x02\x01" || header[18] != 62 || header[19] != 0 {
		return nil, ErrAdmission
	}
	if file.Chmod(0500) != nil {
		return nil, ErrAdmission
	}
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, imageSeals); err != nil {
		return nil, ErrAdmission
	}
	accepted = true
	return &Image{file: file, digest: expected}, nil
}

func duplicate(file *os.File) (*os.File, error) {
	if file == nil {
		return nil, ErrAdmission
	}
	connection, err := file.SyscallConn()
	if err != nil {
		return nil, ErrAdmission
	}
	var fd int
	var nativeErr error
	err = connection.Control(func(handle uintptr) {
		fd, nativeErr = unix.FcntlInt(handle, unix.F_DUPFD_CLOEXEC, 3)
	})
	if err != nil || nativeErr != nil {
		return nil, ErrAdmission
	}
	return os.NewFile(uintptr(fd), "private-axis-capability"), nil
}

func (image *Image) duplicate() (*os.File, error) {
	if image == nil {
		return nil, ErrAdmission
	}
	image.mu.Lock()
	defer image.mu.Unlock()
	if image.file == nil || image.digest == "" {
		return nil, ErrAdmission
	}
	return duplicate(image.file)
}
