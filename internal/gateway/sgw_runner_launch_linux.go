// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gateway

import (
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func startAdmittedSGWRunner(
	receipt *sgwModuleReceipt,
	runnerPath string,
	env []string,
	args []string,
) (*sgwAdmittedCommand, error) {
	if receipt == nil || receipt.runnerLaunch.Mode != "linux-sealed-memfd-v1" {
		return nil, errors.New("s-gw native runner launch admission is unavailable")
	}
	sourceFD, err := unix.Open(runnerPath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("open verified s-gw native runner")
	}
	source := os.NewFile(uintptr(sourceFD), runnerPath)
	if source == nil {
		_ = unix.Close(sourceFD)
		return nil, errors.New("open verified s-gw native runner")
	}
	defer source.Close()

	info, err := source.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > sgwModuleTotalBytes {
		return nil, errors.New("s-gw native runner is invalid")
	}
	memfd, err := unix.MemfdCreate(
		"defenseclaw-s-gw",
		unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING|unix.MFD_EXEC,
	)
	if errors.Is(err, unix.EINVAL) {
		// MFD_EXEC arrived in Linux 6.3. Older supported kernels create
		// executable memfds by default and reject the unknown flag.
		memfd, err = unix.MemfdCreate(
			"defenseclaw-s-gw",
			unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING,
		)
	}
	if err != nil {
		return nil, errors.New("create sealed s-gw runner image")
	}
	image := os.NewFile(uintptr(memfd), "defenseclaw-s-gw")
	if image == nil {
		_ = unix.Close(memfd)
		return nil, errors.New("create sealed s-gw runner image")
	}
	defer image.Close()

	digest := sha256.New()
	written, err := io.Copy(io.MultiWriter(image, digest), io.LimitReader(source, sgwModuleTotalBytes+1))
	if err != nil || written != info.Size() || written > sgwModuleTotalBytes ||
		hex.EncodeToString(digest.Sum(nil)) != receipt.Runner.SHA256 {
		return nil, errors.New("s-gw native runner integrity check failed")
	}
	if err := unix.Fchmod(memfd, 0o500); err != nil {
		return nil, errors.New("seal s-gw runner image")
	}
	seals := unix.F_SEAL_SEAL | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_WRITE
	if _, err := unix.FcntlInt(uintptr(memfd), unix.F_ADD_SEALS, seals); err != nil {
		return nil, errors.New("seal s-gw runner image")
	}
	observed, err := unix.FcntlInt(uintptr(memfd), unix.F_GET_SEALS, 0)
	if err != nil || observed&seals != seals {
		return nil, errors.New("verify sealed s-gw runner image")
	}
	if _, err := image.Seek(0, io.SeekStart); err != nil {
		return nil, errors.New("prepare sealed s-gw runner image")
	}
	if err := validateSGWLinuxDependencies(image, receipt.Target); err != nil {
		return nil, err
	}

	cmd := exec.Command("/proc/self/fd/3", args...)
	cmd.Args[0] = filepath.Base(runnerPath)
	cmd.Dir = receipt.PackageRoot
	cmd.Env = append([]string(nil), env...)
	cmd.ExtraFiles = []*os.File{image}
	return startSGWCommand(cmd)
}

func validateSGWLinuxDependencies(file *os.File, target string) error {
	binary, err := elf.NewFile(file)
	if err != nil {
		return errors.New("s-gw native runner is not a valid ELF image")
	}
	defer binary.Close()
	wantMachine := elf.EM_AARCH64
	interpreters := map[string]struct{}{
		"/lib/ld-linux-aarch64.so.1":                   {},
		"/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1": {},
	}
	if strings.HasSuffix(target, "-x64") {
		wantMachine = elf.EM_X86_64
		interpreters = map[string]struct{}{
			"/lib64/ld-linux-x86-64.so.2":                {},
			"/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2": {},
		}
	}
	if binary.Machine != wantMachine || (binary.Type != elf.ET_EXEC && binary.Type != elf.ET_DYN) {
		return errors.New("s-gw native runner ELF identity is invalid")
	}
	if paths, err := binary.DynString(elf.DT_RPATH); err != nil || len(paths) != 0 {
		return errors.New("s-gw native runner carries an unsafe ELF RPATH")
	}
	if paths, err := binary.DynString(elf.DT_RUNPATH); err != nil || len(paths) != 0 {
		return errors.New("s-gw native runner carries an unsafe ELF RUNPATH")
	}
	for _, tag := range []elf.DynTag{
		elf.DT_CONFIG,
		elf.DT_DEPAUDIT,
		elf.DT_AUDIT,
		elf.DT_AUXILIARY,
		elf.DT_FILTER,
	} {
		values, err := binary.DynValue(tag)
		if err != nil || len(values) != 0 {
			return errors.New("s-gw native runner carries an unsafe ELF loader directive")
		}
	}
	libraries, err := binary.ImportedLibraries()
	if err != nil {
		return errors.New("inspect s-gw native runner dependencies")
	}
	for _, library := range libraries {
		if library == "" || filepath.Base(library) != library || strings.ContainsAny(library, "/\\\x00") {
			return errors.New("s-gw native runner dependency is unsafe")
		}
	}
	for _, program := range binary.Progs {
		if program.Type != elf.PT_INTERP {
			continue
		}
		if program.Filesz == 0 || program.Filesz > 4096 {
			return errors.New("s-gw native runner interpreter is invalid")
		}
		raw := make([]byte, program.Filesz)
		if _, err := program.ReadAt(raw, 0); err != nil {
			return errors.New("read s-gw native runner interpreter")
		}
		interpreter := strings.TrimSuffix(string(raw), "\x00")
		if _, ok := interpreters[interpreter]; !ok {
			return errors.New("s-gw native runner interpreter is not system-owned")
		}
	}
	return nil
}
