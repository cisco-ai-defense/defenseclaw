// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

const outputBound = 64 * 1024 // aggregate over BOTH streams and ALL three cases
const creationFlags = windows.CREATE_SUSPENDED | windows.CREATE_UNICODE_ENVIRONMENT | windows.EXTENDED_STARTUPINFO_PRESENT | windows.CREATE_NO_WINDOW

type budget struct {
	mu       sync.Mutex
	used     int
	overflow bool
}

func (b *budget) admit(n int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if n < 0 || n > outputBound-b.used {
		b.overflow = true
		return false
	}
	b.used += n
	return true
}

func (b *budget) exceeded() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.overflow
}

type inputs struct {
	command, environment, cwd []uint16
	budget                    *budget
}

func fixedCommand(argv0 string) ([]uint16, error) {
	if strings.ContainsAny(argv0, "\x00\"") || !strings.HasSuffix(argv0, `\`+imageName) {
		return nil, errors.New("fixed literal argv0 refused")
	}
	// Match the reviewed Rust literal encoder: BOTH arguments are quoted,
	// including the simple --version token. No shell/string expansion exists.
	return windows.UTF16FromString(`"` + argv0 + `" "--version"`)
}

func environmentBlock(system, root string) ([]uint16, error) {
	for _, path := range []string{system, root} {
		if !strings.HasPrefix(path, `\\?\`) || len(path) < 8 || path[5:7] != `:\` || strings.ContainsAny(path, "\x00=\r\n") {
			return nil, errors.New("fixed canonical private environment shape refused")
		}
	}
	entries := []string{
		"SYSTEMROOT=" + system, "WINDIR=" + system,
		"HOME=" + filepath.Join(root, "home"), "USERPROFILE=" + filepath.Join(root, "home"),
		"APPDATA=" + filepath.Join(root, "home", "AppData", "Roaming"),
		"LOCALAPPDATA=" + filepath.Join(root, "home", "AppData", "Local"),
		"TEMP=" + filepath.Join(root, "tmp"), "TMP=" + filepath.Join(root, "tmp"),
	}
	sort.Strings(entries)
	return utf16.Encode([]rune(strings.Join(entries, "\x00") + "\x00\x00")), nil
}

func fixedInputs(f *fixture) (inputs, error) {
	var result inputs
	system, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		return result, errors.New("native SystemRoot query refused")
	}
	directory, err := openPinned(system, true)
	if err != nil {
		return result, err
	}
	f.files = append(f.files, directory)
	canonicalSystem, err := finalPath(directory, 0)
	if err != nil {
		return result, err
	}
	result.environment, err = environmentBlock(canonicalSystem, f.dosRoot)
	if err != nil {
		return result, err
	}
	result.command, err = fixedCommand(f.argv0)
	if err != nil {
		return result, err
	}
	result.cwd, err = windows.UTF16FromString(filepath.Join(f.dosRoot, "workspace"))
	result.budget = &budget{}
	return result, err
}

type caseReport struct {
	Application               string  `json:"application_spelling"`
	CreateSucceeded           bool    `json:"create_succeeded"`
	Win32                     uint32  `json:"immediate_win32_error"`
	NTStatus                  uint32  `json:"sampled_ntstatus_may_be_stale"`
	ApplicationUnits          int     `json:"application_utf16_units"`
	CommandUnits              int     `json:"command_utf16_units"`
	EnvironmentUnits          int     `json:"environment_utf16_units"`
	CWDUnits                  int     `json:"cwd_utf16_units"`
	Flags                     uint32  `json:"creation_flags"`
	AttributeCount            int     `json:"attribute_count"`
	InheritedStdioHandles     int     `json:"inherited_stdio_handle_count"`
	AssignedBeforeResume      bool    `json:"assigned_before_resume"`
	ImageIdentityBeforeResume bool    `json:"image_identity_before_resume"`
	Resumed                   bool    `json:"resumed"`
	Deadline                  bool    `json:"child_deadline"`
	ExitCode                  *uint32 `json:"exit_code,omitempty"`
	ExactVersion              bool    `json:"exact_version_stdout_empty_stderr"`
	StdoutBytes               int     `json:"stdout_bytes"`
	StderrBytes               int     `json:"stderr_bytes"`
	StdoutSHA                 string  `json:"stdout_sha256"`
	StderrSHA                 string  `json:"stderr_sha256"`
	ReadersJoined             bool    `json:"output_readers_joined"`
	ReaderHandlesClosed       bool    `json:"output_reader_handles_closed"`
	JobEmpty                  bool    `json:"job_empty"`
	Active                    uint32  `json:"active_processes_at_last_query"`
	Elapsed                   float64 `json:"elapsed_seconds"`
}

// This seam is actually used on the retained process handles, in this order.
// A failed assignment or identity query can never reach ResumeThread.
func admitBeforeResume(assign, verify, resume func() error) error {
	if assign() != nil {
		return errors.New("owned Job assignment refused before resume")
	}
	if verify() != nil {
		return errors.New("created process image identity refused before resume")
	}
	if resume() != nil {
		return errors.New("owned primary thread resume refused")
	}
	return nil
}

func verifyProcessImage(process windows.Handle, expected *os.File) (*os.File, error) {
	buffer := make([]uint16, 32768)
	size := uint32(len(buffer))
	// PROCESS_NAME_NATIVE = 1. Keep the actual process handle: never PID-reopen.
	if windows.QueryFullProcessImageName(process, 1, &buffer[0], &size) != nil || size == 0 || size >= uint32(len(buffer)) {
		return nil, errors.New("created process image query refused")
	}
	native := windows.UTF16ToString(buffer[:size])
	if !strings.HasPrefix(native, `\Device\HarddiskVolume`) {
		return nil, errors.New("created image native name refused")
	}
	file, err := openPinned(`\\?\GLOBALROOT`+native, false)
	if err != nil {
		return nil, err
	}
	if err := sameIdentity(expected, file); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

type pipes struct {
	child   []windows.Handle
	readers []*os.File
}

func newPipes() (_ *pipes, resultErr error) {
	p := &pipes{}
	defer func() {
		if resultErr != nil {
			p.closeChildren()
			for _, file := range p.readers {
				_ = file.Close()
			}
		}
	}()
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), InheritHandle: 1}
	for index := range 3 {
		var read, write windows.Handle
		if windows.CreatePipe(&read, &write, &sa, 0) != nil {
			return nil, errors.New("fixed stdio pipe creation refused")
		}
		child, parent := write, read
		if index == 0 {
			child, parent = read, write
		}
		if windows.SetHandleInformation(parent, windows.HANDLE_FLAG_INHERIT, 0) != nil {
			_ = windows.CloseHandle(read)
			_ = windows.CloseHandle(write)
			return nil, errors.New("fixed stdio inheritance refused")
		}
		p.child = append(p.child, child)
		if index == 0 {
			// Actual pipe EOF, same stdio shape as SDK capture; not NUL or host stdin.
			if windows.CloseHandle(parent) != nil {
				return nil, errors.New("fixed stdin EOF close failed")
			}
		} else {
			p.readers = append(p.readers, os.NewFile(uintptr(parent), "owned-output-pipe"))
		}
	}
	return p, nil
}

func (p *pipes) closeChildren() error {
	var err error
	for _, handle := range p.child {
		if windows.CloseHandle(handle) != nil {
			err = errors.Join(err, errors.New("child pipe handle close failed"))
		}
	}
	p.child = nil
	return err
}

type streamResult struct {
	bytes  []byte
	failed bool
}

func drain(file *os.File, bound *budget, done chan<- streamResult) {
	result := streamResult{}
	buffer := make([]byte, 4096)
	for {
		n, err := file.Read(buffer)
		if n > 0 && bound.admit(n) {
			result.bytes = append(result.bytes, buffer[:n]...)
		}
		if err != nil {
			result.failed = !errors.Is(err, io.EOF)
			done <- result
			return
		}
	}
}

// Close owns this exact pipe, not an arbitrary handle. Windows Go 1.26.5's
// internal/poll.FD.Close calls CancelIoEx for pipes, then waits its references.
// Bound both Close and the worker join anyway: failure keeps this case failed,
// prohibits later cases, and leaves the independent outer Job responsible.
func finishStream(file *os.File, done <-chan streamResult, wait time.Duration) (result streamResult, joined, closed bool, resultErr error) {
	select {
	case result = <-done:
		joined = true
	case <-time.After(wait):
		resultErr = errors.New("bounded output completion deadline failed")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- file.Close() }()
	select {
	case err := <-closeDone:
		closed = err == nil
		if err != nil {
			resultErr = errors.Join(resultErr, errors.New("owned reader close failed"))
		}
	case <-time.After(500 * time.Millisecond):
		resultErr = errors.Join(resultErr, errors.New("owned reader close deadline failed"))
	}
	if !joined {
		select {
		case result = <-done:
			joined = true
		case <-time.After(500 * time.Millisecond):
			resultErr = errors.Join(resultErr, errors.New("cancelled reader join deadline failed"))
		}
	}
	if joined && result.failed {
		resultErr = errors.Join(resultErr, errors.New("bounded output read failed"))
	}
	return result, joined, closed, resultErr
}

type accounting struct {
	User, Kernel, PeriodUser, PeriodKernel int64
	PageFaults, Total, Active, Terminated  uint32
}

func waitEmpty(job windows.Handle, deadline time.Time) (uint32, error) {
	for {
		var info accounting
		if windows.QueryInformationJobObject(job, windows.JobObjectBasicAccountingInformation,
			uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), nil) != nil {
			return 0, errors.New("owned Job accounting query failed")
		}
		if info.Active == 0 {
			return 0, nil
		}
		if !time.Now().Before(deadline) {
			return info.Active, errors.New("owned Job cleanup deadline failed")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func runCase(application application, input inputs, expected *os.File, deadline time.Time) (record caseReport, resultErr error) {
	started := time.Now()
	app, err := windows.UTF16FromString(application.path)
	if err != nil {
		return record, errors.New("fixed application encoding refused")
	}
	record = caseReport{Application: application.label, ApplicationUnits: len(app), CommandUnits: len(input.command),
		EnvironmentUnits: len(input.environment), CWDUnits: len(input.cwd), Flags: creationFlags, AttributeCount: 1, InheritedStdioHandles: 3}
	// Registered first, so every Job/process/pipe close and reader-join error
	// has reached resultErr before the final per-case observation is accepted.
	defer func() {
		record.Elapsed = time.Since(started).Seconds()
		record.ExactVersion = record.ExactVersion && resultErr == nil && record.ExitCode != nil && *record.ExitCode == 0 && !record.Deadline
	}()
	if time.Until(deadline) < 7*time.Second {
		return record, errors.New("whole-helper case admission deadline refused")
	}
	pipe, err := newPipes()
	if err != nil {
		return record, err
	}
	defer func() { resultErr = errors.Join(resultErr, pipe.closeChildren()) }()
	readersStarted := false
	defer func() {
		if !readersStarted {
			for _, file := range pipe.readers {
				_ = file.Close()
			}
		}
	}()
	attributes, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return record, errors.New("fixed handle-list allocation refused")
	}
	defer attributes.Delete()
	if attributes.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&pipe.child[0]), uintptr(3)*unsafe.Sizeof(pipe.child[0])) != nil {
		return record, errors.New("fixed handle-list update refused")
	}
	startup := windows.StartupInfoEx{}
	startup.Cb = uint32(unsafe.Sizeof(startup))
	startup.Flags = windows.STARTF_USESTDHANDLES
	startup.StdInput, startup.StdOutput, startup.StdErr = pipe.child[0], pipe.child[1], pipe.child[2]
	startup.ProcThreadAttributeList = attributes.List()
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return record, errors.New("owned Job creation refused")
	}
	defer func() {
		if windows.CloseHandle(job) != nil {
			resultErr = errors.Join(resultErr, errors.New("owned Job close failed"))
		}
	}()
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return record, errors.New("owned Job kill-on-close setup refused")
	}
	var process windows.ProcessInformation
	command := slicesClone(input.command) // CreateProcessW is allowed to modify this buffer.
	create := windows.NewLazySystemDLL("kernel32.dll").NewProc("CreateProcessW")
	status := windows.NewLazySystemDLL("ntdll.dll").NewProc("RtlGetLastNtStatus")
	if create.Find() != nil || status.Find() != nil {
		return record, errors.New("fixed native diagnostic exports unavailable")
	}
	runtime.LockOSThread()
	ok, _, lastError := create.Call(uintptr(unsafe.Pointer(&app[0])), uintptr(unsafe.Pointer(&command[0])), 0, 0, 1,
		uintptr(creationFlags), uintptr(unsafe.Pointer(&input.environment[0])), uintptr(unsafe.Pointer(&input.cwd[0])),
		uintptr(unsafe.Pointer(&startup)), uintptr(unsafe.Pointer(&process)))
	ntstatus, _, _ := status.Call() // sampled on same OS thread, still may be stale
	runtime.UnlockOSThread()
	runtime.KeepAlive(input)
	runtime.KeepAlive(app)
	runtime.KeepAlive(command)
	runtime.KeepAlive(startup)
	if ok == 0 {
		code, valid := lastError.(syscall.Errno)
		if !valid {
			return record, errors.New("raw native error type refused")
		}
		record.Win32, record.NTStatus = uint32(code), uint32(ntstatus)
		record.Active, err = waitEmpty(job, time.Now().Add(time.Second))
		record.JobEmpty = err == nil
		return record, err // A refusal is a completed measurement, not a version pass.
	}
	record.CreateSucceeded = true
	defer func() {
		processErr := windows.CloseHandle(process.Process)
		threadErr := windows.CloseHandle(process.Thread)
		if processErr != nil || threadErr != nil {
			resultErr = errors.Join(resultErr, errors.New("retained process or primary thread handle close failed"))
		}
	}()
	var image *os.File
	var done []chan streamResult
	defer func() {
		// Kill descendants even after a successful root exit. The exact retained
		// process handle covers the pre-assignment error path; never PID-reopen.
		if windows.TerminateJobObject(job, 1) != nil {
			resultErr = errors.Join(resultErr, errors.New("owned Job termination failed"))
		}
		state, waitErr := windows.WaitForSingleObject(process.Process, 0)
		if waitErr != nil || state != windows.WAIT_OBJECT_0 {
			if windows.TerminateProcess(process.Process, 1) != nil {
				resultErr = errors.Join(resultErr, errors.New("owned root termination failed"))
			}
		}
		state, waitErr = windows.WaitForSingleObject(process.Process, 1500)
		if waitErr != nil || state != windows.WAIT_OBJECT_0 {
			resultErr = errors.Join(resultErr, errors.New("retained process did not stop"))
		}
		record.Active, err = waitEmpty(job, time.Now().Add(1500*time.Millisecond))
		record.JobEmpty = err == nil
		resultErr = errors.Join(resultErr, err)
		if image != nil && image.Close() != nil {
			resultErr = errors.Join(resultErr, errors.New("created image pin close failed"))
		}
		// Termination/wait/accounting above precede every output-completion wait,
		// including errors in assignment, image checks, resume or process wait.
		record.ReadersJoined, record.ReaderHandlesClosed = len(done) == 2, len(done) == 2
		for index, channel := range done {
			result, joined, closed, streamErr := finishStream(pipe.readers[index], channel, 250*time.Millisecond)
			resultErr = errors.Join(resultErr, streamErr)
			record.ReadersJoined = record.ReadersJoined && joined
			record.ReaderHandlesClosed = record.ReaderHandlesClosed && closed
			if joined {
				if index == 0 {
					record.StdoutBytes = len(result.bytes)
					record.StdoutSHA = digest(result.bytes)
					record.ExactVersion = bytes.Equal(result.bytes, []byte("2.1.292 (Claude Code)\n")) || bytes.Equal(result.bytes, []byte("2.1.292 (Claude Code)\r\n"))
				} else {
					record.StderrBytes = len(result.bytes)
					record.StderrSHA = digest(result.bytes)
					record.ExactVersion = record.ExactVersion && len(result.bytes) == 0
				}
			}
		}
		if input.budget.exceeded() {
			resultErr = errors.Join(resultErr, errors.New("aggregate output bound exceeded"))
		}
	}()
	if err := pipe.closeChildren(); err != nil {
		return record, err
	}
	done = []chan streamResult{make(chan streamResult, 1), make(chan streamResult, 1)}
	for index, file := range pipe.readers {
		go drain(file, input.budget, done[index])
	}
	readersStarted = true
	err = admitBeforeResume(func() error {
		if err := windows.AssignProcessToJobObject(job, process.Process); err != nil {
			return err
		}
		record.AssignedBeforeResume = true
		return nil
	}, func() error {
		var err error
		image, err = verifyProcessImage(process.Process, expected)
		record.ImageIdentityBeforeResume = err == nil
		return err
	}, func() error {
		_, err := windows.ResumeThread(process.Thread)
		record.Resumed = err == nil
		return err
	})
	if err != nil {
		return record, err
	}
	childDeadline := time.Now().Add(5 * time.Second)
	for {
		state, waitErr := windows.WaitForSingleObject(process.Process, 10)
		if waitErr != nil {
			return record, errors.New("owned process wait failed")
		}
		if state == windows.WAIT_OBJECT_0 {
			break
		}
		if input.budget.exceeded() {
			break
		}
		if !time.Now().Before(childDeadline) {
			record.Deadline = true
			break
		}
	}
	if windows.TerminateJobObject(job, 1) != nil {
		return record, errors.New("owned Job post-case termination failed")
	}
	if state, err := windows.WaitForSingleObject(process.Process, 1500); err != nil || state != windows.WAIT_OBJECT_0 {
		return record, errors.New("owned case did not stop")
	}
	var exit uint32
	if windows.GetExitCodeProcess(process.Process, &exit) != nil {
		return record, errors.New("owned exit-code query failed")
	}
	record.ExitCode = &exit
	if record.Deadline {
		return record, errors.New("fixed child deadline exceeded")
	}
	return record, nil
}

func slicesClone[T any](value []T) []T { return append([]T(nil), value...) }
