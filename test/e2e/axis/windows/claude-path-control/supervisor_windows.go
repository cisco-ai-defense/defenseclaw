// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build ignore

// Build explicitly with authority_windows.go and native_windows.go, excluding
// main_windows.go. This fixed contributor supervisor never accepts an image.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"golang.org/x/sys/windows"
)

// Exact independently reviewed Go1.26.5 build of Git 17ebe67f; no override.
const supervisedImageSHA = "a78aef62fd7f1b98293cf570a87e672fc3cb7b20d922748d7f34931b34adf823"
const supervisedImageSize int64 = 2830848
const jobListAttribute = 0x0002000d // ProcThreadAttributeValue(JobList=13, input=true)

type supervisionReport struct {
	Scope               string  `json:"scope"`
	Completed           bool    `json:"supervision_completed"`
	CreatedInJob        bool    `json:"created_in_owned_job"`
	ImageBound          bool    `json:"helper_image_bound_before_resume"`
	Deadline            bool    `json:"outer_deadline"`
	JobEmpty            bool    `json:"outer_job_empty"`
	Active              uint32  `json:"outer_job_active_processes"`
	ReadersJoined       bool    `json:"readers_joined"`
	ReaderHandlesClosed bool    `json:"reader_handles_closed"`
	Exit                *uint32 `json:"helper_exit_code,omitempty"`
	Stdout              string  `json:"helper_stdout"`
	StderrBytes         int     `json:"helper_stderr_bytes"`
	ImageSHA            string  `json:"helper_sha256"`
	Error               string  `json:"error,omitempty"`
	Production          bool    `json:"production_qualification"`
	Elapsed             float64 `json:"elapsed_seconds"`
}

func supervisorSelector(args []string) bool { return len(args) == 1 && args[0] == "--run-fixed" }

func supervise() (r supervisionReport, resultErr error) {
	started := time.Now()
	deadline := started.Add(30 * time.Second)
	runDeadline := started.Add(24 * time.Second) // reserve six seconds for owned cleanup
	r = supervisionReport{Scope: "fixed_uncontained_claude_path_control_supervisor", ImageSHA: supervisedImageSHA}
	defer func() {
		r.Elapsed = time.Since(started).Seconds()
		if !time.Now().Before(deadline) {
			r.Deadline = true
			resultErr = errors.Join(resultErr, errors.New("outer absolute deadline expired"))
		}
		if resultErr != nil {
			r.Error = resultErr.Error()
			r.Completed = false
		}
	}()
	if len(supervisedImageSHA) != 64 || supervisedImageSize <= 0 || supervisedImageSize > 8<<20 {
		return r, errors.New("supervised helper image is not admitted")
	}
	self, err := os.Executable()
	if err != nil || filepath.Base(self) != "claude-path-supervisor.exe" {
		return r, errors.New("fixed supervisor name refused")
	}
	root := filepath.Dir(self)
	if !strings.HasPrefix(filepath.Base(root), "claude-path-control-") || filepath.Base(filepath.Dir(root)) != "environment-control-private-02" {
		return r, errors.New("fixed private evidence parent refused")
	}
	imagePath := filepath.Join(root, "claude-path-control.exe")
	held, err := pinParents(imagePath)
	if err != nil {
		return r, err
	}
	defer func() { resultErr = errors.Join(resultErr, held.close()) }()
	if safefile.ValidatePrivateHandle(windows.Handle(held[len(held)-1].Fd())) != nil {
		return r, errors.New("private supervisor root refused")
	}
	image, err := openPinned(imagePath, false)
	if err != nil {
		return r, err
	}
	held = append(held, image)
	if err := readFixed(image, supervisedImageSize, supervisedImageSHA); err != nil {
		return r, err
	}
	pipe, err := newPipes()
	if err != nil {
		return r, err
	}
	readersStarted := false
	defer func() {
		resultErr = errors.Join(resultErr, pipe.closeChildren())
		if !readersStarted {
			for _, file := range pipe.readers {
				if file != nil && file.Close() != nil {
					resultErr = errors.Join(resultErr, errors.New("outer unused reader close failed"))
				}
			}
		}
	}()
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return r, errors.New("outer Job creation failed")
	}
	defer func() {
		if windows.CloseHandle(job) != nil {
			resultErr = errors.Join(resultErr, errors.New("outer Job close failed"))
		}
	}()
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return r, errors.New("outer Job limit refused")
	}
	attributes, err := windows.NewProcThreadAttributeList(2)
	if err != nil {
		return r, errors.New("outer startup allocation failed")
	}
	jobs := []windows.Handle{job}
	defer func() { attributes.Delete(); runtime.KeepAlive(jobs) }()
	if attributes.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&pipe.child[0]), uintptr(3)*unsafe.Sizeof(pipe.child[0])) != nil || attributes.Update(jobListAttribute, unsafe.Pointer(&jobs[0]), unsafe.Sizeof(job)) != nil {
		return r, errors.New("outer startup attributes refused")
	}
	startup := windows.StartupInfoEx{}
	startup.Cb = uint32(unsafe.Sizeof(startup))
	startup.Flags = windows.STARTF_USESTDHANDLES
	startup.StdInput, startup.StdOutput, startup.StdErr = pipe.child[0], pipe.child[1], pipe.child[2]
	startup.ProcThreadAttributeList = attributes.List()
	app, err := windows.UTF16PtrFromString(imagePath)
	if err != nil {
		return r, errors.New("outer image encoding failed")
	}
	command, err := windows.UTF16PtrFromString(windows.ComposeCommandLine([]string{imagePath, "--run-fixed"}))
	if err != nil {
		return r, errors.New("outer command encoding failed")
	}
	cwd, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return r, errors.New("outer cwd encoding failed")
	}
	system, err := windows.GetSystemWindowsDirectory()
	if err != nil || strings.ContainsAny(system, "\x00=\r\n") {
		return r, errors.New("outer SystemRoot query failed")
	}
	environment := utf16.Encode([]rune("SYSTEMROOT=" + system + "\x00WINDIR=" + system + "\x00\x00"))
	var process windows.ProcessInformation
	if time.Until(runDeadline) < 2*time.Second {
		return r, errors.New("outer creation admission deadline refused")
	}
	if windows.CreateProcess(app, command, nil, nil, true, creationFlags, &environment[0], cwd, &startup.StartupInfo, &process) != nil {
		return r, errors.New("outer fixed helper creation failed")
	}
	runtime.KeepAlive(jobs)
	runtime.KeepAlive(environment)
	defer func() {
		threadErr, processErr := windows.CloseHandle(process.Thread), windows.CloseHandle(process.Process)
		if threadErr != nil || processErr != nil {
			resultErr = errors.Join(resultErr, errors.New("outer retained process handles failed to close"))
		}
	}()
	var streams []chan streamResult
	bound := &budget{}
	defer func() {
		if windows.TerminateJobObject(job, 1) != nil {
			resultErr = errors.Join(resultErr, errors.New("outer Job termination failed"))
		}
		state, waitErr := windows.WaitForSingleObject(process.Process, 0)
		if waitErr != nil || state != windows.WAIT_OBJECT_0 {
			if windows.TerminateProcess(process.Process, 1) != nil {
				resultErr = errors.Join(resultErr, errors.New("outer retained helper termination failed"))
			}
		}
		if state, err := windows.WaitForSingleObject(process.Process, 1500); err != nil || state != windows.WAIT_OBJECT_0 {
			resultErr = errors.Join(resultErr, errors.New("outer retained helper wait failed"))
		}
		var err error
		r.Active, err = waitEmpty(job, time.Now().Add(1500*time.Millisecond))
		r.JobEmpty = err == nil
		resultErr = errors.Join(resultErr, err)
		r.ReadersJoined, r.ReaderHandlesClosed = len(streams) == 2, len(streams) == 2
		for i, ch := range streams {
			v, joined, closed, err := finishStream(pipe.readers[i], ch, 250*time.Millisecond)
			r.ReadersJoined = r.ReadersJoined && joined
			r.ReaderHandlesClosed = r.ReaderHandlesClosed && closed
			resultErr = errors.Join(resultErr, err)
			if closed {
				pipe.readers[i] = nil
			}
			if joined {
				if i == 0 {
					r.Stdout = string(v.bytes)
				} else {
					r.StderrBytes = len(v.bytes)
				}
			}
		}
		if bound.exceeded() {
			resultErr = errors.Join(resultErr, errors.New("outer aggregate capture exceeded"))
		}
	}()
	if err := pipe.closeChildren(); err != nil {
		return r, err
	}
	streams = []chan streamResult{make(chan streamResult, 1), make(chan streamResult, 1)}
	for i, file := range pipe.readers {
		go drain(file, bound, streams[i])
	}
	readersStarted = true
	var member int32
	membership := windows.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob")
	if membership.Find() != nil {
		return r, errors.New("outer membership export unavailable")
	}
	ok, _, _ := membership.Call(uintptr(process.Process), uintptr(job), uintptr(unsafe.Pointer(&member)))
	if ok == 0 || member == 0 {
		return r, errors.New("created helper is not in owned Job")
	}
	r.CreatedInJob = true
	actual, err := verifyProcessImage(process.Process, image)
	if err != nil {
		return r, err
	}
	if err := actual.Close(); err != nil {
		return r, errors.New("outer helper identity pin close failed")
	}
	r.ImageBound = true
	if !time.Now().Before(runDeadline) {
		r.Deadline = true
		return r, errors.New("outer pre-resume deadline refused")
	}
	if previous, err := windows.ResumeThread(process.Thread); err != nil || previous != 1 {
		return r, errors.New("outer helper resume refused")
	}
	for {
		state, err := windows.WaitForSingleObject(process.Process, 20)
		if err != nil {
			return r, errors.New("outer helper wait failed")
		}
		if state == windows.WAIT_OBJECT_0 {
			break
		}
		if !time.Now().Before(runDeadline) {
			r.Deadline = true
			return r, errors.New("outer helper deadline exceeded")
		}
		if bound.exceeded() {
			return r, errors.New("outer capture exceeded")
		}
	}
	var code uint32
	if !time.Now().Before(runDeadline) {
		r.Deadline = true
		return r, errors.New("outer terminal wait crossed deadline")
	}
	if windows.GetExitCodeProcess(process.Process, &code) != nil {
		return r, errors.New("outer helper exit query failed")
	}
	r.Exit = &code
	if code != 0 {
		return r, errors.New("fixed measurement helper failed")
	}
	r.Completed = true
	return r, nil
}

func main() {
	if !supervisorSelector(os.Args[1:]) {
		fmt.Fprintln(os.Stderr, "only the fixed supervisor selector is accepted")
		os.Exit(2)
	}
	r, err := supervise()
	if json.NewEncoder(os.Stdout).Encode(r) != nil || err != nil {
		os.Exit(1)
	}
}
