// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"bytes"
	"crypto/rand"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"
)

// All paths below this helper are fixed artifact members or newly generated
// synthetic fixture names. Relative opens walk every component without links.
func openRelative(parent *os.File, name string, flags int) (*os.File, error) {
	if parent == nil || name == "" || len(name) > 4096 || !filepath.IsLocal(name) || strings.ContainsRune(name, 0) {
		return nil, errors.New("fixed relative object refused")
	}
	parts := strings.Split(name, "/")
	if len(parts) > 16 {
		return nil, errors.New("fixed object depth refused")
	}
	fd, err := unix.FcntlInt(parent.Fd(), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return nil, err
	}
	for i, part := range parts {
		if part == "" || part == "." || part == ".." {
			_ = unix.Close(fd)
			return nil, errors.New("fixed object component refused")
		}
		access := unix.O_RDONLY | unix.O_DIRECTORY
		if i == len(parts)-1 {
			access = flags | unix.O_NONBLOCK
		}
		next, err := unix.Openat(fd, part, access|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		_ = unix.Close(fd)
		if err != nil {
			return nil, err
		}
		fd = next
	}
	return os.NewFile(uintptr(fd), "fixed-held-object"), nil
}

func openDirectory(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, errors.New("exact absolute directory refused")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	root := os.NewFile(uintptr(fd), "filesystem-root")
	defer root.Close()
	return openRelative(root, strings.TrimPrefix(path, "/"), unix.O_RDONLY|unix.O_DIRECTORY)
}

func privateDirectory(file *os.File) error {
	var stat unix.Stat_t
	if unix.Fstat(int(file.Fd()), &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0777 != 0700 {
		return errors.New("fixed owned private directory refused")
	}
	return nil
}

func boundedFile(parent *os.File, path string, maximum int64, expected string) (*os.File, []byte, error) {
	file, err := openRelative(parent, path, unix.O_RDONLY)
	if err != nil {
		return nil, nil, errors.New("reviewed fixed artifact open refused")
	}
	accepted := false
	defer func() {
		if !accepted {
			_ = file.Close()
		}
	}()
	var stat unix.Stat_t
	if unix.Fstat(int(file.Fd()), &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&06000 != 0 || stat.Nlink != 1 || stat.Size < 1 || stat.Size > maximum {
		return nil, nil, errors.New("reviewed fixed artifact type/size/link refused")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) != stat.Size || digestBytes(data) != expected {
		return nil, nil, errors.New("reviewed fixed artifact bytes differ")
	}
	accepted = true
	return file, data, nil
}

func validateStaticELF(data []byte) error {
	file, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return errors.New("fixed static ELF header refused")
	}
	defer file.Close()
	if file.Class != elf.ELFCLASS64 || file.Data != elf.ELFDATA2LSB || file.Machine != elf.EM_X86_64 || file.Type != elf.ET_EXEC || len(file.Progs) == 0 || len(file.Progs) > 128 {
		return errors.New("fixed static Linux image required")
	}
	entry := false
	for _, p := range file.Progs {
		if p.Type == elf.PT_INTERP || p.Type == elf.PT_DYNAMIC || p.Filesz > p.Memsz || p.Off > uint64(len(data)) || p.Filesz > uint64(len(data))-p.Off || p.Vaddr > ^uint64(0)-p.Memsz {
			return errors.New("dynamic or malformed static image")
		}
		entry = entry || p.Type == elf.PT_LOAD && p.Flags&elf.PF_X != 0 && file.Entry >= p.Vaddr && file.Entry-p.Vaddr < p.Filesz
	}
	if !entry {
		return errors.New("static entry outside executable file-backed segment")
	}
	return nil
}

func sealBytes(data []byte, expected string) (_ *os.File, resultErr error) {
	if len(data) < 64 || len(data) > 32<<20 || digestBytes(data) != expected || validateStaticELF(data) != nil {
		return nil, errors.New("reviewed fixed image bytes refused")
	}
	fd, err := unix.MemfdCreate("fixed-reviewed-outer-wrapper", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "fixed-reviewed-sealed-wrapper")
	accepted := false
	defer func() {
		if !accepted {
			resultErr = errors.Join(resultErr, file.Close())
		}
	}()
	if _, err := file.Write(data); err != nil {
		return nil, err
	}
	if err := file.Chmod(0500); err != nil {
		return nil, err
	}
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_SEAL|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_WRITE); err != nil {
		return nil, err
	}
	accepted = true
	return file, nil
}

// fixtureCapabilities are created by the trusted host driver before any USER
// namespace clone. The parent owner check is never inferred from overflow UID.
type fixtureCapabilities struct {
	parent, root *os.File
	loader       *os.File
	path         string
}

func (f *fixtureCapabilities) close() error {
	if f == nil {
		return nil
	}
	var errs []error
	if f.loader != nil {
		errs = append(errs, f.loader.Close())
	}
	if f.root != nil {
		errs = append(errs, f.root.Close())
	}
	if f.parent != nil {
		errs = append(errs, f.parent.Close())
	}
	return errors.Join(errs...)
}
func trustedTemporaryParent(st unix.Stat_t) bool {
	return st.Mode&unix.S_IFMT == unix.S_IFDIR && st.Uid == 0 && st.Mode&unix.S_ISVTX != 0
}

// fixtureMountStatus validates only the stable statmount MNT_BASIC prefix.
// Missing fields, an unrelated mount, or an ID mapping are refusals. This is a
// fixed contributor host-floor check, not proof for arbitrary foreign FDs.
func fixtureMountStatus(statxMask uint32, mountID uint64, response []byte) error {
	if statxMask&unix.STATX_MNT_ID_UNIQUE == 0 || mountID == 0 || len(response) < 72 ||
		binary.LittleEndian.Uint32(response[:4]) < 72 || uint64(binary.LittleEndian.Uint32(response[:4])) > uint64(len(response)) ||
		binary.LittleEndian.Uint64(response[8:16])&2 == 0 || // STATMOUNT_MNT_BASIC
		binary.LittleEndian.Uint64(response[40:48]) != mountID ||
		binary.LittleEndian.Uint64(response[64:72])&unix.MOUNT_ATTR_IDMAP != 0 {
		return errors.New("fixed creator-namespace non-idmapped source proof refused")
	}
	return nil
}

func verifyCreatorMount(file *os.File) (uint64, error) {
	if file == nil {
		return 0, errors.New("fixed source mount capability absent")
	}
	var identity unix.Statx_t
	if err := unix.Statx(int(file.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT, unix.STATX_MNT_ID_UNIQUE, &identity); err != nil {
		return 0, err
	}
	if identity.Mask&unix.STATX_MNT_ID_UNIQUE == 0 || identity.Mnt_id == 0 {
		return 0, errors.New("fixed source unique mount identity unavailable")
	}
	// Linux's version0 request is 24 bytes. An unset namespace selector means
	// this creator's CURRENT mount namespace; no foreign lookup or setns occurs.
	request := struct {
		Size, Spare uint32
		Mount, Mask uint64
	}{Size: 24, Mount: identity.Mnt_id, Mask: 2} // STATMOUNT_MNT_BASIC
	var response [512]byte
	_, _, errno := unix.Syscall6(unix.SYS_STATMOUNT, uintptr(unsafe.Pointer(&request)), uintptr(unsafe.Pointer(&response[0])), uintptr(len(response)), 0, 0, 0)
	runtime.KeepAlive(file)
	if errno != 0 {
		return 0, errno
	}
	if err := fixtureMountStatus(identity.Mask, identity.Mnt_id, response[:]); err != nil {
		return 0, err
	}
	return identity.Mnt_id, nil
}

func newHostFixture() (*fixtureCapabilities, error) {
	parent, err := openDirectory("/tmp")
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	var st unix.Stat_t
	if unix.Fstat(int(parent.Fd()), &st) != nil || !trustedTemporaryParent(st) {
		return nil, errors.New("fixed host temporary parent refused")
	}
	parentMount, err := verifyCreatorMount(parent)
	if err != nil {
		return nil, err
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	fixture, err := createHostFixtureUnder(parent, "/tmp", hex.EncodeToString(random[:]))
	if err != nil {
		return fixture, err
	}
	rootMount, err := verifyCreatorMount(fixture.root)
	if err != nil || rootMount != parentMount {
		return fixture, errors.Join(errors.New("fixed fresh root mount differs from creator parent"), err)
	}
	return fixture, nil
}
func createHostFixtureUnder(parent *os.File, displayParent, nonce string) (_ *fixtureCapabilities, resultErr error) {
	if parent == nil || len(nonce) != 32 || strings.Trim(nonce, "0123456789abcdef") != "" {
		return nil, errors.New("fixed fixture identity refused")
	}
	name := "dc-axis-native-peer-" + nonce
	if err := unix.Mkdirat(int(parent.Fd()), name, 0700); err != nil {
		return nil, err
	}
	f := &fixtureCapabilities{path: filepath.Join(displayParent, name)}
	// A partial creation is returned for exact evidence and handle cleanup; the
	// fresh task-created directory is retained on every outcome.
	fd, err := unix.FcntlInt(parent.Fd(), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return f, err
	}
	f.parent = os.NewFile(uintptr(fd), "fixed-held-host-tmp-parent")
	f.root, err = openRelative(parent, name, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return f, err
	}
	return f, privateDirectory(f.root)
}
func checkInheritedFixture(parent, root *os.File) error {
	if parent == nil || root == nil || privateDirectory(root) != nil {
		return errors.New("fixed held fixture root refused")
	}
	var st unix.Stat_t
	if unix.Fstat(int(parent.Fd()), &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&unix.S_ISVTX == 0 {
		return errors.New("fixed held fixture parent refused")
	}
	// Display strings correlate retained objects only; never reopen through them.
	var value [512]byte
	n, err := unix.Readlink("/proc/self/fd/"+fmt.Sprint(root.Fd()), value[:])
	if err != nil || n <= 0 || n >= len(value) {
		return errors.New("fixed fixture display refused")
	}
	display := string(value[:n])
	name := filepath.Base(display)
	nonce := strings.TrimPrefix(name, "dc-axis-native-peer-")
	if filepath.Dir(display) != "/tmp" || len(nonce) != 32 || strings.Trim(nonce, "0123456789abcdef") != "" || name != "dc-axis-native-peer-"+nonce {
		return errors.New("fixed fixture display refused")
	}
	observed, err := openRelative(parent, name, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return err
	}
	defer observed.Close()
	a, err := observed.Stat()
	if err != nil {
		return err
	}
	b, err := root.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(a, b) {
		return errors.New("fixed fixture held identity differs")
	}
	return nil
}
