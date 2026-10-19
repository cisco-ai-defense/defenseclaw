// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package bridgeprocess

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeowner"
	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeproto"
	"golang.org/x/sys/windows"
)

const windowsStartJobList = 0x0002000d
const windowsStartFlags = windows.CREATE_SUSPENDED | windows.CREATE_UNICODE_ENVIRONMENT | windows.EXTENDED_STARTUPINFO_PRESENT | windows.CREATE_NO_WINDOW

var (
	windowsStartKernel       = windows.NewLazySystemDLL("kernel32.dll")
	windowsStartInJob        = windowsStartKernel.NewProc("IsProcessInJob")
	windowsStartImageMapping = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtQueryInformationProcess")
)

// Windows ordinary SealImage remains unsupported: Windows admission requires
// the explicit held-root fresh-copy constructor, never an ambient TEMP name.
func sealImage(context.Context, *os.File, string) (*Image, error) { return nil, ErrUnavailable }

// The same Session owns this native object before protocol workers or process
// creation. There is no PID adoption, second supervisor, output-reader goroutine,
// detached cleanup owner, or unbounded native wait. An error retains custody.
type windowsCustody struct {
	mu                                    sync.Mutex
	serial                                chan struct{} // context-aware serialization of StopAndWait attempts
	launchDone                            chan struct{}
	job, process, thread                  windows.Handle
	files                                 []*os.File // retained peer/payload/object pins, not caller handles
	startupCopies                         []*os.File // parent copies of inheritable handles and child endpoints
	preOwnerPipes                         []*os.File // only until bridgeowner.New accepts their ownership
	pipeSetup                             []*bridgeowner.OverlappedPrivatePipe
	starting, closed, complete, uncertain bool
}

func (custody *windowsCustody) StopAndWait(ctx context.Context) error {
	if ctx == nil {
		return ErrAdmission
	}
	custody.mu.Lock()
	custody.closed = true
	if custody.complete {
		uncertain := custody.uncertain
		custody.mu.Unlock()
		if uncertain {
			return bridgeowner.ErrCleanup
		}
		return nil
	}
	pending := custody.starting
	done := custody.launchDone
	custody.mu.Unlock()
	if pending {
		// The native creation goroutine retains startup buffers, handles and
		// child duplicates until CreateProcess and every startup check finish.
		// Closing admission latches a pre-Resume refusal even after late Create.
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	select {
	case custody.serial <- struct{}{}:
		defer func() { <-custody.serial }()
	case <-ctx.Done():
		return ctx.Err()
	}
	custody.mu.Lock()
	defer custody.mu.Unlock()
	if custody.complete {
		if custody.uncertain {
			return bridgeowner.ErrCleanup
		}
		return nil
	}
	// No kernel process creation is in progress while these retained objects
	// are inspected/closed. The mutex is held only around zero-time queries,
	// signals and single close attempts; polling sleeps release it below.
	for {
		rootDone := custody.process == 0
		if !rootDone {
			state, err := windows.WaitForSingleObject(custody.process, 0)
			if err != nil {
				return bridgeowner.ErrCleanup
			}
			rootDone = state == windows.WAIT_OBJECT_0
		}
		active, err := windowsActiveProcesses(custody.job)
		if err != nil {
			return bridgeowner.ErrCleanup
		}
		if rootDone && active == 0 {
			break
		}
		// Even a normally exited root leaves descendants to the owned Job.
		// The Job is never inherited, permits no breakaway, and was assigned
		// atomically by JOB_LIST before the initial suspended process existed.
		jobErr := windows.TerminateJobObject(custody.job, 1)
		var rootErr error
		if !rootDone {
			rootErr = windows.TerminateProcess(custody.process, 1)
		}
		if jobErr != nil || rootErr != nil {
			return bridgeowner.ErrCleanup // exact handles remain for explicit retry
		}
		custody.mu.Unlock()
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-timer.C:
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			custody.mu.Lock()
			return ctx.Err()
		}
		custody.mu.Lock()
	}
	for _, handle := range []*windows.Handle{&custody.thread, &custody.process, &custody.job} {
		if *handle != 0 {
			owned := *handle
			*handle = 0 // never retry a possibly recycled native handle
			if windows.CloseHandle(owned) != nil {
				custody.uncertain = true
			}
		}
	}
	custody.closeFiles(custody.files)
	custody.closeFiles(custody.startupCopies)
	custody.closeFiles(custody.preOwnerPipes)
	for index, setup := range custody.pipeSetup {
		if setup != nil {
			custody.mu.Unlock()
			err := setup.Close(ctx)
			custody.mu.Lock()
			if err != nil {
				return errors.Join(bridgeowner.ErrCleanup, err)
			}
			custody.pipeSetup[index] = nil
		}
	}
	if custody.uncertain {
		return bridgeowner.ErrCleanup
	}
	custody.complete = true
	return nil
}

// Caller holds mu and has excluded pending native creation. Each slot loses
// execution authority before exactly one Close attempt; uncertainty is sticky.
func (custody *windowsCustody) closeFiles(files []*os.File) {
	for index, file := range files {
		if file != nil {
			files[index] = nil
			if file.Close() != nil {
				custody.uncertain = true
			}
		}
	}
}

func windowsActiveProcesses(job windows.Handle) (uint32, error) {
	if job == 0 {
		return 0, nil
	}
	var accounting struct {
		User, Kernel, PeriodUser, PeriodKernel int64
		PageFaults, Total, Active, Terminated  uint32
	}
	if windows.QueryInformationJobObject(job, windows.JobObjectBasicAccountingInformation,
		uintptr(unsafe.Pointer(&accounting)), uint32(unsafe.Sizeof(accounting)), nil) != nil {
		return 0, bridgeowner.ErrCleanup
	}
	return accounting.Active, nil
}

// The class44 input is the held FILE_EXECUTE|SYNCHRONIZE image file handle.
// Success means exactly status zero. There is no returned name, PID reopen,
// byte-hash substitution or QueryFullProcessImageName fallback.
func windowsMatchProcessImage(process windows.Handle, expected *os.File) error {
	if expected == nil || windowsStartImageMapping.Find() != nil {
		return ErrUnavailable
	}
	connection, err := expected.SyscallConn()
	if err != nil {
		return ErrAdmission
	}
	status := uint32(0xffffffff)
	err = connection.Control(func(raw uintptr) {
		image := windows.Handle(raw)
		value, _, _ := windowsStartImageMapping.Call(uintptr(process), 44,
			uintptr(unsafe.Pointer(&image)), unsafe.Sizeof(image), 0)
		status = uint32(value)
	})
	if err != nil || status != 0 {
		return ErrAdmission
	}
	return nil
}

func windowsPeerInJob(process, job windows.Handle) error {
	if windowsStartInJob.Find() != nil {
		return ErrUnavailable
	}
	var member int32
	ok, _, _ := windowsStartInJob.Call(uintptr(process), uintptr(job), uintptr(unsafe.Pointer(&member)))
	if ok == 0 || member == 0 {
		return ErrAdmission
	}
	return nil
}

// Only the compatibility spelling is obtained here. The held-file kernel
// comparison after suspended creation is the executable identity authority.
// GUID/GLOBALROOT/UNC/fallback names and NULL application are not attempted.
func windowsPeerApplication(peer *os.File) (string, error) {
	if peer == nil {
		return "", ErrAdmission
	}
	var path [32768]uint16
	n, err := windows.GetFinalPathNameByHandle(windows.Handle(peer.Fd()), &path[0], uint32(len(path)), 0)
	if err != nil || n <= 7 || n >= uint32(len(path)) {
		return "", ErrAdmission
	}
	name := windows.UTF16ToString(path[:n])
	if !strings.HasPrefix(name, `\\?\`) || len(name) < 8 || name[5] != ':' || name[6] != '\\' ||
		(name[4] < 'A' || name[4] > 'Z') && (name[4] < 'a' || name[4] > 'z') || strings.ContainsAny(name, "\x00\r\n\"") {
		return "", ErrAdmission
	}
	return name[4:], nil
}

func windowsInheritableCopy(file *os.File) (*os.File, error) {
	if file == nil {
		return nil, ErrAdmission
	}
	connection, err := file.SyscallConn()
	if err != nil {
		return nil, ErrAdmission
	}
	var copy windows.Handle
	var nativeErr error
	err = connection.Control(func(raw uintptr) {
		nativeErr = windows.DuplicateHandle(windows.CurrentProcess(), windows.Handle(raw), windows.CurrentProcess(), &copy, 0, true, windows.DUPLICATE_SAME_ACCESS)
	})
	if copy == 0 || copy == windows.InvalidHandle {
		return nil, ErrAdmission
	}
	owned := os.NewFile(uintptr(copy), "private-axis-child-capability")
	if err != nil || nativeErr != nil {
		return owned, ErrAdmission
	}
	return owned, nil
}

func windowsAsset(file *os.File, write bool) (*os.File, bool, windowsImageID, error) {
	if file == nil {
		return nil, false, windowsImageID{}, ErrAdmission
	}
	info, err := file.Stat()
	if err != nil || !info.IsDir() && !info.Mode().IsRegular() {
		return nil, false, windowsImageID{}, ErrAdmission
	}
	directory := info.IsDir()
	access := uint32(windows.GENERIC_READ | windows.READ_CONTROL | windows.SYNCHRONIZE)
	if write {
		access |= windows.GENERIC_WRITE
	}
	var flags uint32
	if directory {
		flags = windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	connection, err := file.SyscallConn()
	if err != nil || windowsImageReopen.Find() != nil {
		return nil, false, windowsImageID{}, ErrAdmission
	}
	var handle windows.Handle
	var id windowsImageID
	var metadataErr error
	err = connection.Control(func(raw uintptr) {
		id, metadataErr = windowsAssetIdentity(windows.Handle(raw), directory)
		if metadataErr != nil {
			return
		}
		value, _, _ := windowsImageReopen.Call(raw, uintptr(access), windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, uintptr(flags|windows.FILE_FLAG_OPEN_REPARSE_POINT))
		handle = windows.Handle(value)
	})
	if handle == 0 || handle == windows.InvalidHandle {
		return nil, false, windowsImageID{}, ErrAdmission
	}
	owned := os.NewFile(uintptr(handle), "private-axis-object-capability")
	if err != nil || metadataErr != nil {
		return owned, directory, id, ErrAdmission
	}
	actual, err := windowsImageMetadata(owned, directory)
	if err != nil || id != actual || windowsImageLocalNTFS(owned) != nil {
		return owned, directory, id, ErrAdmission // caller must retain allocated refusal
	}
	return owned, directory, id, nil
}

// This original-object query runs inside SyscallConn.Control so a concurrent
// caller Close cannot recycle its HANDLE between identity and duplication.
func windowsAssetIdentity(handle windows.Handle, directory bool) (windowsImageID, error) {
	var id windowsImageID
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(handle, &info) != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		(info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory || !directory && info.NumberOfLinks != 1 ||
		windows.GetFileInformationByHandleEx(handle, windows.FileIdInfo, (*byte)(unsafe.Pointer(&id)), uint32(unsafe.Sizeof(id))) != nil || id == (windowsImageID{}) {
		return windowsImageID{}, ErrAdmission
	}
	return id, nil
}

type windowsPeerLaunch struct {
	application  string
	prefix       []byte
	input        *os.File // same overlapped parent command end owned by Owner
	stdio        [3]windows.Handle
	handles      []windows.Handle
	writeTimeout time.Duration
}

// The callback seam is used by the real retained-handle path below; tests must
// prove neither identity failure nor latched cleanup can reach ResumeThread.
func windowsBeforeResume(member, image, resume func() error) error {
	if member() != nil || image() != nil {
		return ErrAdmission
	}
	return resume()
}

func (custody *windowsCustody) begin(ctx context.Context, launch windowsPeerLaunch) error {
	custody.mu.Lock()
	if custody.closed || custody.complete || custody.starting || ctx.Err() != nil {
		custody.mu.Unlock()
		return bridgeowner.ErrClosed
	}
	custody.starting = true
	custody.mu.Unlock()
	result := make(chan error, 1)
	go func() {
		// This goroutine owns every startup argument/buffer and child duplicate
		// until CreateProcess has completed, even if the caller already timed out.
		err := custody.create(ctx, launch)
		custody.mu.Lock()
		custody.closeFiles(custody.startupCopies)
		if custody.uncertain {
			err = errors.Join(err, bridgeowner.ErrCleanup)
		}
		lateRefusal := custody.closed || ctx.Err() != nil
		custody.mu.Unlock()
		if err != nil || lateRefusal {
			// A caller may already have exhausted its cleanup deadline while
			// CreateProcess was pending. The creator itself signals any late
			// exact Job/root before declaring startup finished. Observation and
			// retryable signal failures remain the Session owner's responsibility.
			err = errors.Join(err, custody.signalLateRoot())
			if lateRefusal {
				err = errors.Join(err, bridgeowner.ErrClosed)
			}
		}
		custody.mu.Lock()
		custody.starting = false
		close(custody.launchDone)
		custody.mu.Unlock()
		result <- err
	}()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return ctx.Err() // nonnil Session still owns the exact late native result
	}
}

func (custody *windowsCustody) resumeIfOpen(ctx context.Context, resume func() error) error {
	custody.mu.Lock()
	defer custody.mu.Unlock()
	if custody.closed || ctx.Err() != nil {
		return bridgeowner.ErrClosed
	}
	return resume()
}

func (custody *windowsCustody) signalLateRoot() error {
	// starting is still true: StopAndWait cannot close these handles yet.
	if custody.process == 0 {
		return nil
	}
	jobErr := windows.TerminateJobObject(custody.job, 1)
	state, waitErr := windows.WaitForSingleObject(custody.process, 0)
	var rootErr error
	if waitErr != nil || state != windows.WAIT_OBJECT_0 {
		rootErr = windows.TerminateProcess(custody.process, 1)
	}
	if jobErr != nil || waitErr != nil || rootErr != nil {
		return bridgeowner.ErrCleanup
	}
	return nil
}

func (custody *windowsCustody) create(ctx context.Context, launch windowsPeerLaunch) error {
	attributes, err := windows.NewProcThreadAttributeList(2)
	if err != nil {
		return ErrUnavailable
	}
	jobs := []windows.Handle{custody.job}
	defer func() { attributes.Delete(); runtime.KeepAlive(jobs); runtime.KeepAlive(launch) }()
	if len(launch.handles) < 5 || attributes.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
		unsafe.Pointer(&launch.handles[0]), uintptr(len(launch.handles))*unsafe.Sizeof(launch.handles[0])) != nil ||
		attributes.Update(windowsStartJobList, unsafe.Pointer(&jobs[0]), unsafe.Sizeof(jobs[0])) != nil {
		return ErrUnavailable
	}
	startup := windows.StartupInfoEx{}
	startup.Cb = uint32(unsafe.Sizeof(startup))
	startup.Flags = windows.STARTF_USESTDHANDLES
	startup.StdInput, startup.StdOutput, startup.StdErr = launch.stdio[0], launch.stdio[1], launch.stdio[2]
	startup.ProcThreadAttributeList = attributes.List()
	app, err := windows.UTF16FromString(launch.application)
	if err != nil {
		return ErrAdmission
	}
	// Exactly argv0 and no extra arguments; never interpolate the workload plan.
	command, _ := windows.UTF16FromString("defenseclaw-axis-peer")
	// Startup cwd is the private image directory, not a grant and never used by
	// the trusted peer. Its workload cwd is only the inherited CWD capability.
	cwd, err := windows.UTF16FromString(filepath.Dir(launch.application))
	if err != nil {
		return ErrAdmission
	}
	environment := []uint16{0, 0} // explicit empty block, never nil/ambient
	custody.mu.Lock()
	abort := custody.closed || ctx.Err() != nil
	custody.mu.Unlock()
	if abort {
		return bridgeowner.ErrClosed
	}
	var pi windows.ProcessInformation
	if windows.CreateProcess(&app[0], &command[0], nil, nil, true, windowsStartFlags, &environment[0], &cwd[0], &startup.StartupInfo, &pi) != nil {
		return ErrUnavailable
	}
	custody.mu.Lock()
	custody.process, custody.thread = pi.Process, pi.Thread
	custody.mu.Unlock()
	err = windowsBeforeResume(func() error { return windowsPeerInJob(pi.Process, custody.job) },
		func() error { return windowsMatchProcessImage(pi.Process, custody.files[0]) }, func() error {
			return custody.resumeIfOpen(ctx, func() error {
				previous, err := windows.ResumeThread(pi.Thread)
				if err != nil || previous != 1 {
					return ErrUnavailable
				}
				return nil
			})
		})
	if err != nil {
		return err
	}
	// Only the verified trusted peer is running; it must wait for this bounded
	// fixed capability prefix. No caller can Send a JSON command until Start
	// returns. Parent cancellation closes this deadline-capable pipe.
	deadline := time.Now().Add(launch.writeTimeout)
	if bound, ok := ctx.Deadline(); ok && bound.Before(deadline) {
		deadline = bound
	}
	if launch.input.SetWriteDeadline(deadline) != nil {
		return bridgeowner.ErrClosed
	}
	n, err := launch.input.Write(launch.prefix)
	if err != nil || n != len(launch.prefix) {
		return bridgeowner.ErrClosed
	}
	return nil
}

func start(ctx context.Context, binding bridgeproto.Binding, plan bridgeproto.Preparation, inputs Inputs, limits bridgeowner.Limits) (result *Session, resultErr error) {
	if ctx == nil {
		return nil, ErrAdmission
	}
	deadline, bounded := ctx.Deadline()
	frame := bridgeproto.Frame{Version: bridgeproto.Version, Sequence: 1, Request: 1, Binding: binding, Kind: bridgeproto.Prepare, Plan: &plan}
	if ctx.Err() != nil || !bounded || time.Until(deadline) <= 0 || time.Until(deadline) > 24*time.Hour || runtime.GOARCH != "amd64" ||
		limits.WriteTimeout <= 0 || limits.WriteTimeout > 30*time.Second || limits.CleanupTimeout <= 0 || limits.CleanupTimeout > 30*time.Second ||
		frame.Validate() != nil || plan.Backend != "windows_psec" || plan.Terminal != nil || len(plan.Filesystem.Deny) != 0 || inputs.Bubblewrap != nil ||
		len(inputs.Read) != len(plan.Filesystem.Read) || len(inputs.Write) != len(plan.Filesystem.Write) {
		return nil, ErrAdmission
	}
	// Establish the SAME native cleanup owner before the first allocation, not
	// merely before CreateProcess. A refused-but-allocated handle is registered
	// immediately; helpers never close and discard it outside custody.
	custody := &windowsCustody{serial: make(chan struct{}, 1), launchDone: make(chan struct{})}
	result = &Session{native: custody}
	defer func() {
		if resultErr != nil {
			cleanup, cancel := context.WithTimeout(context.Background(), limits.CleanupTimeout)
			defer cancel()
			if result.Protocol == nil {
				resultErr = errors.Join(resultErr, custody.StopAndWait(cleanup))
			} else {
				resultErr = errors.Join(resultErr, result.Close(cleanup))
			}
		}
	}()
	own := func(file *os.File) {
		if file != nil {
			custody.files = append(custody.files, file)
		}
	}
	ownChild := func(file *os.File) {
		if file != nil {
			custody.startupCopies = append(custody.startupCopies, file)
		}
	}
	peer, err := inputs.Peer.duplicate()
	own(peer)
	if err != nil {
		return result, err
	}
	application, err := windowsPeerApplication(peer)
	if err != nil {
		return result, err
	}
	payload, err := inputs.Payload.duplicate()
	own(payload)
	if err != nil {
		return result, err
	}
	payloadID, err := windowsImageMetadata(payload, false)
	if err != nil {
		return result, err
	}
	caps := []windowsCapability{{file: payload, role: windowsCapabilityPayload, id: payloadID}}
	objects := append([]*os.File{inputs.CWD}, inputs.Read...)
	objects = append(objects, inputs.Write...)
	for index, object := range objects {
		write := index > len(inputs.Read)
		file, directory, id, err := windowsAsset(object, write)
		own(file) // includes allocated metadata/NTFS refusal
		if err != nil {
			return result, err
		}
		role := windowsCapabilityRead
		if index == 0 {
			role = windowsCapabilityCWD
		} else if write {
			role = windowsCapabilityWrite
		}
		if index == 0 && !directory {
			return result, ErrAdmission
		}
		caps = append(caps, windowsCapability{file: file, role: role, directory: directory, id: id})
	}
	cwdGranted := false
	paths := append(append([]string{}, plan.Filesystem.Read...), plan.Filesystem.Write...)
	for index, path := range paths {
		if path == plan.Workdir && caps[index+2].id == caps[1].id {
			cwdGranted = true
		}
	}
	if !cwdGranted {
		return result, ErrAdmission
	}
	var channels []bridgeowner.PrivatePipe
	for _, direction := range []bridgeowner.Direction{bridgeowner.ToPeer, bridgeowner.FromPeer, bridgeowner.FromPeer} {
		setupCtx, cancel := context.WithTimeout(ctx, min(limits.WriteTimeout, time.Second))
		setup, err := bridgeowner.NewOverlappedPrivatePipe(setupCtx, direction)
		cancel()
		if setup != nil {
			custody.pipeSetup = append(custody.pipeSetup, setup)
		}
		if err != nil {
			return result, err
		}
		channel, err := setup.Take()
		// Register transferred endpoints before checking any following error.
		if channel.Parent != nil {
			custody.preOwnerPipes = append(custody.preOwnerPipes, channel.Parent)
		}
		ownChild(channel.Child)
		if err != nil {
			return result, err
		}
		channels = append(channels, channel)
	}
	launch := windowsPeerLaunch{application: application, input: channels[0].Parent, writeTimeout: limits.WriteTimeout}
	for index := range caps {
		file, err := windowsInheritableCopy(caps[index].file)
		ownChild(file) // preserves allocated Control/native-error refusal
		if err != nil {
			return result, err
		}
		caps[index].inherited = uint64(file.Fd())
		launch.handles = append(launch.handles, windows.Handle(file.Fd()))
	}
	launch.prefix, err = encodeWindowsCapabilities(plan, binding, caps)
	if err != nil {
		return result, err
	}
	for index, channel := range channels {
		file, err := windowsInheritableCopy(channel.Child)
		ownChild(file)
		if err != nil {
			return result, err
		}
		launch.stdio[index] = windows.Handle(file.Fd())
		launch.handles = append(launch.handles, windows.Handle(file.Fd()))
	}
	job, err := windows.CreateJobObject(nil, nil)
	if job != 0 && job != windows.InvalidHandle {
		custody.job = job
	}
	if err != nil || custody.job == 0 {
		return result, ErrUnavailable
	}
	jobLimits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	jobLimits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&jobLimits)), uint32(unsafe.Sizeof(jobLimits))); err != nil {
		return result, ErrUnavailable // exact Job remains in cleanup owner
	}
	pipes := bridgeowner.Pipes{Input: channels[0].Parent, Output: channels[1].Parent, Diagnostics: channels[2].Parent, Custody: custody}
	// Owner.New may start cancellation/cleanup workers before returning. Its
	// nonnil result owns these pipes, so remove them from native cleanup before
	// calling it. A nil result starts no custody worker and restores ownership.
	preOwner := custody.preOwnerPipes
	custody.preOwnerPipes = nil
	owner, err := bridgeowner.New(ctx, binding, pipes, limits)
	if owner == nil {
		custody.preOwnerPipes = preOwner
		return result, err
	}
	result.Protocol = owner
	if err != nil {
		return result, err
	}
	if err = custody.begin(ctx, launch); err != nil {
		return result, err
	}
	return result, nil
}
