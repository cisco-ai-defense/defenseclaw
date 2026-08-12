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

//go:build windows

package gateway

import (
	"crypto/sha256"
	"debug/pe"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	sgwBlockNonMicrosoftBinaries uint64 = 1 << 44
	sgwImageLoadNoRemote         uint64 = 1 << 52
	sgwImageLoadNoLowLabel       uint64 = 1 << 56
	sgwImageLoadPreferSystem32   uint64 = 1 << 60
	sgwWindowsStillActive               = 259
)

type sgwWindowsRunnerLease struct {
	runner       *os.File
	directories  []*os.File
	canonical    string
	volumeSerial uint32
	fileIndexHi  uint32
	fileIndexLo  uint32
}

func (lease *sgwWindowsRunnerLease) Close() {
	if lease == nil {
		return
	}
	if lease.runner != nil {
		_ = lease.runner.Close()
		lease.runner = nil
	}
	for i := len(lease.directories) - 1; i >= 0; i-- {
		_ = lease.directories[i].Close()
	}
	lease.directories = nil
}

type sgwWindowsProcess struct {
	mu       sync.Mutex
	waitOnce sync.Once
	handle   windows.Handle
	lease    *sgwWindowsRunnerLease
	waitErr  error
}

func (process *sgwWindowsProcess) Kill() error {
	if process == nil {
		return nil
	}
	process.mu.Lock()
	handle := process.handle
	process.mu.Unlock()
	if handle == 0 {
		return nil
	}
	if err := windows.TerminateProcess(handle, 1); err == nil {
		return nil
	}
	var exitCode uint32
	if windows.GetExitCodeProcess(handle, &exitCode) == nil && exitCode != sgwWindowsStillActive {
		return nil
	}
	return errors.New("terminate admitted s-gw native runner")
}

func (process *sgwWindowsProcess) Wait() error {
	if process == nil {
		return nil
	}
	process.waitOnce.Do(func() {
		process.mu.Lock()
		handle := process.handle
		process.mu.Unlock()
		if handle == 0 {
			return
		}
		result, err := windows.WaitForSingleObject(handle, windows.INFINITE)
		if err != nil || result != windows.WAIT_OBJECT_0 {
			process.waitErr = errors.New("wait for admitted s-gw native runner")
		} else {
			var exitCode uint32
			if err := windows.GetExitCodeProcess(handle, &exitCode); err != nil {
				process.waitErr = errors.New("read admitted s-gw native runner status")
			} else if exitCode != 0 {
				process.waitErr = fmt.Errorf("s-gw native runner exited with status %d", exitCode)
			}
		}

		process.mu.Lock()
		if process.handle != 0 {
			_ = windows.CloseHandle(process.handle)
			process.handle = 0
		}
		if process.lease != nil {
			process.lease.Close()
			process.lease = nil
		}
		process.mu.Unlock()
	})
	return process.waitErr
}

func startAdmittedSGWRunner(
	receipt *sgwModuleReceipt,
	runnerPath string,
	env []string,
	args []string,
) (*sgwAdmittedCommand, error) {
	if receipt == nil || receipt.runnerLaunch.Mode != "windows-locked-image-v1" {
		return nil, errors.New("s-gw native runner launch admission is unavailable")
	}
	lease, err := lockSGWWindowsRunner(runnerPath, receipt)
	if err != nil {
		return nil, err
	}

	stdinReader, stdinWriter, err := os.Pipe()
	if err != nil {
		lease.Close()
		return nil, errors.New("create s-gw credential broker input")
	}
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		lease.Close()
		stdinReader.Close()
		stdinWriter.Close()
		return nil, errors.New("create s-gw credential broker output")
	}
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		lease.Close()
		stdinReader.Close()
		stdinWriter.Close()
		stdoutReader.Close()
		stdoutWriter.Close()
		return nil, errors.New("create s-gw credential broker diagnostics")
	}
	closePipes := func() {
		for _, file := range []*os.File{
			stdinReader, stdinWriter, stdoutReader, stdoutWriter, stderrReader, stderrWriter,
		} {
			_ = file.Close()
		}
	}
	childEnds := []*os.File{stdinReader, stdoutWriter, stderrWriter}
	for _, file := range childEnds {
		handle := windows.Handle(file.Fd())
		if windows.SetHandleInformation(handle, windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT) != nil {
			lease.Close()
			closePipes()
			return nil, errors.New("prepare s-gw credential broker pipes")
		}
	}

	attributes, err := windows.NewProcThreadAttributeList(2)
	if err != nil {
		lease.Close()
		closePipes()
		return nil, errors.New("prepare s-gw process admission")
	}
	defer attributes.Delete()
	handles := []windows.Handle{
		windows.Handle(stdinReader.Fd()),
		windows.Handle(stdoutWriter.Fd()),
		windows.Handle(stderrWriter.Fd()),
	}
	if err := attributes.Update(
		windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
		unsafe.Pointer(&handles[0]),
		uintptr(len(handles))*unsafe.Sizeof(handles[0]),
	); err != nil {
		lease.Close()
		closePipes()
		return nil, errors.New("restrict s-gw inherited handles")
	}
	mitigation := sgwBlockNonMicrosoftBinaries | sgwImageLoadNoRemote |
		sgwImageLoadNoLowLabel | sgwImageLoadPreferSystem32
	if err := attributes.Update(
		windows.PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
		unsafe.Pointer(&mitigation),
		unsafe.Sizeof(mitigation),
	); err != nil {
		lease.Close()
		closePipes()
		return nil, errors.New("apply s-gw process mitigations")
	}

	executable, err := windows.UTF16PtrFromString(lease.canonical)
	if err != nil {
		lease.Close()
		closePipes()
		return nil, errors.New("prepare s-gw native runner path")
	}
	commandArgs := append([]string{lease.canonical}, args...)
	commandLine, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(commandArgs))
	if err != nil {
		lease.Close()
		closePipes()
		return nil, errors.New("prepare s-gw native runner arguments")
	}
	cwd, err := windows.UTF16PtrFromString(receipt.PackageRoot)
	if err != nil {
		lease.Close()
		closePipes()
		return nil, errors.New("prepare s-gw native runner directory")
	}
	environment, err := sgwWindowsEnvironmentBlock(env)
	if err != nil {
		lease.Close()
		closePipes()
		return nil, err
	}
	startup := windows.StartupInfoEx{
		StartupInfo: windows.StartupInfo{
			Cb:        uint32(unsafe.Sizeof(windows.StartupInfoEx{})),
			Flags:     windows.STARTF_USESTDHANDLES,
			StdInput:  handles[0],
			StdOutput: handles[1],
			StdErr:    handles[2],
		},
		ProcThreadAttributeList: attributes.List(),
	}
	var processInfo windows.ProcessInformation
	flags := uint32(
		windows.CREATE_NO_WINDOW |
			windows.CREATE_SUSPENDED |
			windows.CREATE_UNICODE_ENVIRONMENT |
			windows.EXTENDED_STARTUPINFO_PRESENT,
	)
	err = windows.CreateProcess(
		executable,
		commandLine,
		nil,
		nil,
		true,
		flags,
		&environment[0],
		cwd,
		&startup.StartupInfo,
		&processInfo,
	)
	if err != nil {
		lease.Close()
		closePipes()
		return nil, errors.New("start admitted s-gw native runner")
	}
	cleanupChild := func() {
		_ = windows.TerminateProcess(processInfo.Process, 1)
		_, _ = windows.WaitForSingleObject(processInfo.Process, windows.INFINITE)
		_ = windows.CloseHandle(processInfo.Thread)
		_ = windows.CloseHandle(processInfo.Process)
		lease.Close()
		closePipes()
	}
	if err := verifySGWWindowsProcessImage(processInfo.Process, lease); err != nil {
		cleanupChild()
		return nil, err
	}
	if _, err := windows.ResumeThread(processInfo.Thread); err != nil {
		cleanupChild()
		return nil, errors.New("resume admitted s-gw native runner")
	}
	_ = windows.CloseHandle(processInfo.Thread)
	_ = stdinReader.Close()
	_ = stdoutWriter.Close()
	_ = stderrWriter.Close()

	process := &sgwWindowsProcess{handle: processInfo.Process, lease: lease}
	return &sgwAdmittedCommand{
		process: process,
		stdin:   stdinWriter,
		stdout:  stdoutReader,
		stderr:  stderrReader,
	}, nil
}

func lockSGWWindowsRunner(path string, receipt *sgwModuleReceipt) (*sgwWindowsRunnerLease, error) {
	if receipt == nil || receipt.managedRoot == "" {
		return nil, errors.New("s-gw managed runner root is unavailable")
	}
	directories, err := lockSGWWindowsDirectories(receipt.managedRoot, filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	closeDirectories := func() {
		for i := len(directories) - 1; i >= 0; i-- {
			_ = directories[i].Close()
		}
	}
	runner, canonical, info, err := openSGWWindowsPath(path, false)
	if err != nil {
		closeDirectories()
		return nil, errors.New("lock s-gw native runner image")
	}
	lease := &sgwWindowsRunnerLease{
		runner: runner, directories: directories, canonical: canonical,
		volumeSerial: info.VolumeSerialNumber, fileIndexHi: info.FileIndexHigh, fileIndexLo: info.FileIndexLow,
	}
	digest := sha256.New()
	read, err := io.Copy(digest, io.LimitReader(runner, sgwModuleTotalBytes+1))
	if err != nil || read <= 0 || read > sgwModuleTotalBytes ||
		hex.EncodeToString(digest.Sum(nil)) != receipt.Runner.SHA256 {
		lease.Close()
		return nil, errors.New("s-gw native runner integrity check failed")
	}
	if _, err := runner.Seek(0, io.SeekStart); err != nil {
		lease.Close()
		return nil, errors.New("inspect s-gw native runner image")
	}
	binary, err := pe.NewFile(runner)
	if err != nil {
		lease.Close()
		return nil, errors.New("s-gw native runner is not a valid PE image")
	}
	machine := uint16(pe.IMAGE_FILE_MACHINE_ARM64)
	if receipt.runnerLaunch.PEMachine == "x86_64" {
		machine = pe.IMAGE_FILE_MACHINE_AMD64
	}
	if binary.FileHeader.Machine != machine || sgwPEHasDelayImports(binary) {
		binary.Close()
		lease.Close()
		return nil, errors.New("s-gw native runner PE identity is invalid")
	}
	libraries, err := binary.ImportedLibraries()
	binary.Close()
	if err != nil {
		lease.Close()
		return nil, errors.New("inspect s-gw native runner dependencies")
	}
	for _, library := range libraries {
		if library == "" || filepath.Base(library) != library || strings.ContainsAny(library, "/\\\x00") {
			lease.Close()
			return nil, errors.New("s-gw native runner dependency is unsafe")
		}
	}
	return lease, nil
}

func lockSGWWindowsDirectories(root, runnerParent string) ([]*os.File, error) {
	root = filepath.Clean(root)
	runnerParent = filepath.Clean(runnerParent)
	relative, err := filepath.Rel(root, runnerParent)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, errors.New("s-gw native runner path escapes its managed root")
	}
	paths := []string{root}
	if relative != "." {
		current := root
		for _, part := range strings.Split(relative, string(filepath.Separator)) {
			if part == "" || part == "." || part == ".." {
				return nil, errors.New("s-gw native runner directory path is invalid")
			}
			current = filepath.Join(current, part)
			paths = append(paths, current)
		}
	}
	leases := make([]*os.File, 0, len(paths))
	for _, path := range paths {
		file, canonical, _, err := openSGWWindowsPath(path, true)
		if err != nil || !strings.EqualFold(canonical, normalizeSGWWindowsPath(path)) {
			for i := len(leases) - 1; i >= 0; i-- {
				_ = leases[i].Close()
			}
			return nil, errors.New("lock s-gw native runner directory")
		}
		leases = append(leases, file)
	}
	return leases, nil
}

func openSGWWindowsPath(path string, directory bool) (*os.File, string, windows.ByHandleFileInformation, error) {
	var empty windows.ByHandleFileInformation
	path16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, "", empty, err
	}
	access := uint32(windows.GENERIC_READ)
	flags := uint32(windows.FILE_ATTRIBUTE_NORMAL | windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		access = windows.FILE_READ_ATTRIBUTES | windows.SYNCHRONIZE
		flags = windows.FILE_FLAG_BACKUP_SEMANTICS | windows.FILE_FLAG_OPEN_REPARSE_POINT
	}
	handle, err := windows.CreateFile(
		path16,
		access,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		flags,
		0,
	)
	if err != nil {
		return nil, "", empty, err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, "", empty, errors.New("open s-gw path")
	}
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(handle, &info) != nil ||
		info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		(directory && info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0) ||
		(!directory && info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) {
		file.Close()
		return nil, "", empty, errors.New("s-gw path identity is invalid")
	}
	canonical, err := sgwWindowsFinalPath(handle)
	if err != nil || !strings.EqualFold(canonical, normalizeSGWWindowsPath(path)) {
		file.Close()
		return nil, "", empty, errors.New("s-gw path changed during admission")
	}
	return file, canonical, info, nil
}

func verifySGWWindowsProcessImage(process windows.Handle, lease *sgwWindowsRunnerLease) error {
	buffer := make([]uint16, 32768)
	size := uint32(len(buffer))
	if err := windows.QueryFullProcessImageName(process, 0, &buffer[0], &size); err != nil || size == 0 {
		return errors.New("inspect admitted s-gw native runner process")
	}
	imagePath := normalizeSGWWindowsPath(windows.UTF16ToString(buffer[:size]))
	if !strings.EqualFold(imagePath, lease.canonical) {
		return errors.New("admitted s-gw process image path changed")
	}
	image, canonical, info, err := openSGWWindowsPath(imagePath, false)
	if err != nil {
		return errors.New("verify admitted s-gw process image")
	}
	defer image.Close()
	if !strings.EqualFold(canonical, lease.canonical) ||
		info.VolumeSerialNumber != lease.volumeSerial || info.FileIndexHigh != lease.fileIndexHi ||
		info.FileIndexLow != lease.fileIndexLo {
		return errors.New("admitted s-gw process image identity changed")
	}
	return nil
}

func sgwWindowsFinalPath(handle windows.Handle) (string, error) {
	buffer := make([]uint16, 32768)
	length, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), 0)
	if err != nil || length == 0 || length >= uint32(len(buffer)) {
		return "", errors.New("resolve s-gw path identity")
	}
	return normalizeSGWWindowsPath(windows.UTF16ToString(buffer[:length])), nil
}

func normalizeSGWWindowsPath(path string) string {
	if strings.HasPrefix(path, `\\?\UNC\`) {
		path = `\\` + strings.TrimPrefix(path, `\\?\UNC\`)
	} else {
		path = strings.TrimPrefix(path, `\\?\`)
	}
	return filepath.Clean(path)
}

func sgwPEHasDelayImports(binary *pe.File) bool {
	if binary == nil {
		return true
	}
	var directory pe.DataDirectory
	switch header := binary.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		directory = header.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT]
	case *pe.OptionalHeader64:
		directory = header.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT]
	default:
		return true
	}
	return directory.VirtualAddress != 0 || directory.Size != 0
}

func sgwWindowsEnvironmentBlock(env []string) ([]uint16, error) {
	values := append([]string(nil), env...)
	sort.Slice(values, func(left, right int) bool {
		return strings.ToUpper(values[left]) < strings.ToUpper(values[right])
	})
	for _, value := range values {
		if value == "" || strings.ContainsRune(value, '\x00') || !strings.Contains(value, "=") {
			return nil, errors.New("s-gw native runner environment is invalid")
		}
	}
	raw := strings.Join(values, "\x00") + "\x00\x00"
	return utf16.Encode([]rune(raw)), nil
}
