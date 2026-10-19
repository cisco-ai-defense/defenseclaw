// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/axis/namespaceinit"
	"golang.org/x/sys/unix"
)

const workerReady = "DC_AXIS_FIXED_WORKER_READY_V1\n"
const workerGrant = "DC_AXIS_FIXED_WORKER_GRANT_V1\n"

type workerPermit struct{ granted bool }

func readyThenGrant(ready io.Writer, grant io.Reader) error {
	if _, err := io.WriteString(ready, workerReady); err != nil {
		return errors.New("fixed worker READY failed")
	}
	message, err := io.ReadAll(io.LimitReader(grant, int64(len(workerGrant)+1)))
	if err != nil || string(message) != workerGrant {
		return errors.New("fixed worker GRANT absent or malformed")
	}
	return nil
}

// outerCustodian retains an atomic pidfd for the whole fixed worker PID
// namespace. Killing and reaping its init covers nested peer/workload namespaces.
// No raw host PID, name lookup, process group or JSON supplies cleanup authority.
type outerCustodian struct {
	mu                        sync.Mutex
	pidfd                     int
	starting, started, closed bool
	complete                  bool
	command                   *exec.Cmd
	done                      chan struct{}
	waitErr                   error
	exit                      int
	startStage, startErrno    string
}

// The start-error classification contains only fixed vocabulary. Separately
// retained bounded private worker streams may contain synthetic paths or runtime
// diagnostics; they do not inherit credentials from the empty child environment.
func startErrnoClass(err error) string {
	if err == nil {
		return "none"
	}
	for _, item := range []struct {
		err  error
		name string
	}{{unix.EPERM, "eperm"}, {unix.EACCES, "eacces"}, {unix.EINVAL, "einval"}, {unix.ENOENT, "enoent"},
		{unix.ENOSYS, "enosys"}, {unix.EAGAIN, "eagain"}, {unix.ENOMEM, "enomem"}, {unix.EIO, "eio"}, {context.Canceled, "cancelled"}} {
		if errors.Is(err, item.err) {
			return item.name
		}
	}
	return "other"
}

func procSelfPIDView(link string, pid int, readErr error) (available, matches bool) {
	if readErr != nil || pid <= 0 || len(link) == 0 || len(link) > 10 {
		return false, false
	}
	value, err := strconv.Atoi(link)
	if err != nil || value <= 0 || strconv.Itoa(value) != link {
		return false, false
	}
	return true, value == pid
}

func observeProcPIDView(record map[string]any) {
	// Read-only diagnostic, never authority for mappings, mounts or cleanup.
	// Distinguish an unavailable observation from an actual PID-view mismatch;
	// neither the raw link target nor the process ID enters evidence.
	var target [11]byte
	n, err := unix.Readlink("/proc/self", target[:])
	if n < 0 || n >= len(target) {
		n, err = 0, errors.New("fixed proc link unavailable")
	}
	record["proc_self_pid_view_available"], record["proc_self_pid_matches_getpid"] = procSelfPIDView(string(target[:n]), os.Getpid(), err)
}

func retainWorkerObservation(record map[string]any, owner *outerCustodian, stdout, stderr *boundedCapture) {
	owner.mu.Lock()
	record["worker_start_stage"], record["worker_start_errno"] = owner.startStage, owner.startErrno
	record["worker_native_wait_complete"], record["owned_worker_exit_code"] = owner.started && owner.complete, owner.exit
	owner.mu.Unlock()
	data, overflow := stdout.snapshot()
	diagnostics, stderrOverflow := stderr.snapshot()
	record["owned_worker_stdout"], record["owned_worker_stderr"] = string(data), string(diagnostics)
	record["owned_worker_stdout_truncated"], record["owned_worker_stderr_truncated"] = overflow, stderrOverflow
}

func (o *outerCustodian) signalLocked() error {
	var err error
	if o.pidfd >= 0 {
		err = unix.PidfdSendSignal(o.pidfd, unix.SIGKILL, nil, 0)
	} else if o.started && !o.complete && o.command != nil {
		// Atomic pidfd refusal still needs exact os.Process cleanup. It never
		// authorizes GRANT, and Go synchronizes this handle against PID reuse.
		err = o.command.Process.Kill()
	}
	if errors.Is(err, unix.ESRCH) || errors.Is(err, os.ErrProcessDone) {
		return nil
	}
	return err
}

func (o *outerCustodian) stopAndWait(ctx context.Context) error {
	o.mu.Lock()
	o.closed = true
	err := o.signalLocked()
	o.mu.Unlock()
	if err != nil {
		return err
	}
	select {
	case <-o.done:
		return o.waitErr
	default:
	}
	select {
	case <-o.done:
		return o.waitErr
	case <-ctx.Done():
		return ctx.Err() // the exact owner stays reachable in its caller
	}
}

func (o *outerCustodian) Close(ctx context.Context) error       { return o.stopAndWait(ctx) }
func (o *outerCustodian) StopAndWait(ctx context.Context) error { return o.stopAndWait(ctx) }

func (o *outerCustodian) start(ctx context.Context, command *exec.Cmd, pidfd *int, childFiles []*os.File) error {
	o.mu.Lock()
	o.starting = true
	o.startStage, o.startErrno = "start_pending", "none"
	o.mu.Unlock()
	result := make(chan error, 1)
	go func() {
		// Worker PR_SET_PDEATHSIG refers to this creating thread. Retain it
		// until wait, without Go's pre-exec getppid check across CLONE_NEWPID.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		o.mu.Lock()
		abort := o.closed || ctx.Err() != nil
		o.mu.Unlock()
		var startErr error
		if abort {
			startErr = context.Canceled
		} else {
			startErr = command.Start()
		}
		var closeErr error
		for _, f := range childFiles {
			closeErr = errors.Join(closeErr, f.Close())
		}
		o.mu.Lock()
		o.starting = false
		if startErr != nil {
			o.startStage, o.startErrno = "exec_start_refused", startErrnoClass(startErr)
			if abort {
				o.startStage = "start_cancelled_before_exec"
			}
			o.closed, o.complete, o.waitErr = true, true, closeErr
			close(o.done)
			o.mu.Unlock()
			result <- errors.Join(errors.New("fixed outer namespace start refused"), closeErr)
			return
		}
		o.started, o.pidfd, o.command = true, *pidfd, command
		o.startStage, o.startErrno = "started", "none"
		if *pidfd < 0 || o.closed || ctx.Err() != nil || closeErr != nil {
			switch {
			case *pidfd < 0:
				o.startStage = "atomic_pidfd_refused"
			case o.closed || ctx.Err() != nil:
				o.startStage = "start_cancelled_after_exec"
			default:
				o.startStage, o.startErrno = "child_descriptor_release_failed", startErrnoClass(closeErr)
			}
			o.closed = true
			startErr = errors.Join(errors.New("fixed outer atomic custody refused"), closeErr, o.signalLocked())
		}
		o.mu.Unlock()
		result <- startErr
		waitErr := command.Wait()
		exit := -1
		if command.ProcessState != nil {
			exit = command.ProcessState.ExitCode()
			if status, ok := command.ProcessState.Sys().(syscall.WaitStatus); ok && (status.Exited() || status.Signaled()) {
				var ordinaryExit *exec.ExitError
				if errors.As(waitErr, &ordinaryExit) {
					waitErr = nil // exit status is separately required for success
				}
			}
		}
		o.mu.Lock()
		if o.pidfd >= 0 {
			waitErr = errors.Join(waitErr, unix.Close(o.pidfd))
			o.pidfd = -1
		}
		o.waitErr, o.exit, o.complete, o.closed = waitErr, exit, true, true
		o.command = nil
		close(o.done)
		o.mu.Unlock()
	}()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return ctx.Err() // start goroutine owns child copies through kernel return
	}
}

type boundedCapture struct {
	mu       sync.Mutex
	data     []byte
	overflow bool
}

func (b *boundedCapture) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(p) > outputLimit-len(b.data) {
		b.overflow = true
		return 0, errors.New("fixed outer capture exceeded")
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

func (b *boundedCapture) snapshot() ([]byte, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.data), b.overflow
}

// This is a copy of the already running, externally source/image-admitted
// wrapper, not admission of an arbitrary path plus caller-provided digest.
// /proc/self/exe resolves the current executable inode, including after rename.
func sealedRunningImage() (_ *os.File, hash string, resultErr error) {
	source, err := os.Open("/proc/self/exe")
	if err != nil {
		return nil, "", err
	}
	defer func() { resultErr = errors.Join(resultErr, source.Close()) }()
	info, err := source.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 || info.Size() < 64 || info.Size() > 64<<20 {
		return nil, "", errors.New("fixed running wrapper image refused")
	}
	data, err := io.ReadAll(io.LimitReader(source, (64<<20)+1))
	if err != nil || int64(len(data)) != info.Size() || validateELF(data, true) != nil {
		return nil, "", errors.New("fixed running wrapper must be static Linux amd64")
	}
	fd, err := unix.MemfdCreate("fixed-native-peer-wrapper", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, "", err
	}
	file := os.NewFile(uintptr(fd), "fixed-sealed-wrapper")
	accepted := false
	defer func() {
		if !accepted {
			resultErr = errors.Join(resultErr, file.Close())
		}
	}()
	if _, err := file.Write(data); err != nil || file.Chmod(0500) != nil {
		return nil, "", errors.New("fixed running wrapper sealing failed")
	}
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL); err != nil {
		return nil, "", err
	}
	accepted = true
	return file, digestBytes(data), nil
}

func runSupervised(ctx context.Context, opts options, registry reviewedRegistry, record map[string]any, retained *cleanupOwner) (resultErr error) {
	if registry.validate() != nil {
		return errUnreviewed
	}
	if retained == nil {
		return errors.New("outer cleanup owner required")
	}
	if runtime.GOARCH != "amd64" || os.Geteuid() == 0 || os.Getuid() != os.Geteuid() || os.Getgid() != os.Getegid() {
		return errors.New("native unprivileged Linux amd64 required")
	}
	fixtureParent, fixtureRoot := os.NewFile(8, "fixed-inherited-host-tmp"), os.NewFile(9, "fixed-inherited-host-fixture")
	defer fixtureParent.Close()
	defer fixtureRoot.Close()
	if err := privateDirectory(fixtureRoot); err != nil {
		return err
	}
	for _, file := range []*os.File{fixtureParent, fixtureRoot} {
		if _, err := unix.FcntlInt(file.Fd(), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
			return err
		}
	}
	var loader *os.File
	if opts.suite == claudeVersionSuite {
		var err error
		loader, err = inheritedVersionLoader(fixtureRoot, 10)
		if err != nil {
			return err
		}
		defer func() {
			resultErr = errors.Join(resultErr, retained.releaseResource(loader.Close))
			record["pending_outer_loader_resources"] = len(retained.heldResources)
		}()
	}
	observeProcPIDView(record)
	image, hash, err := sealedRunningImage()
	if image != nil {
		defer func() { resultErr = errors.Join(resultErr, image.Close()) }()
	}
	if err != nil {
		return err
	}
	record["guardian_self_image_sha256"] = hash
	grantRead, grantWrite, err := os.Pipe()
	if err != nil {
		return err
	}
	defer grantWrite.Close()
	readyRead, readyWrite, err := os.Pipe()
	if err != nil {
		_ = grantRead.Close()
		return err
	}
	defer readyRead.Close()
	proof, err := namespaceinit.Capture()
	if err != nil {
		_ = grantRead.Close()
		_ = readyWrite.Close()
		return err
	}
	stdout, stderr := &boundedCapture{}, &boundedCapture{}
	pidfd := -1
	command := &exec.Cmd{Path: "/proc/self/fd/6", Args: []string{"fixed-native-peer-wrapper", "--owned-fixed-worker", "--receipt", opts.receipt, "--evidence", opts.evidence, "--suite", opts.suite},
		Env: []string{}, Dir: "/", ExtraFiles: []*os.File{proof, grantRead, readyWrite, image}, Stdout: stdout, Stderr: stderr,
		SysProcAttr: &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNET | syscall.CLONE_NEWIPC | syscall.CLONE_NEWUTS,
			AmbientCaps: []uintptr{unix.CAP_SYS_ADMIN},
			UidMappings: []syscall.SysProcIDMap{{ContainerID: os.Getuid(), HostID: os.Getuid(), Size: 1}},
			GidMappings: []syscall.SysProcIDMap{{ContainerID: os.Getgid(), HostID: os.Getgid(), Size: 1}}, GidMappingsEnableSetgroups: false, PidFD: &pidfd}}
	// An owned duplicate lets the creator alone release ExtraFiles, even if
	// the caller times out while command.Start is still inside the kernel.
	copyFD, err := unix.FcntlInt(image.Fd(), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		_ = proof.Close()
		_ = grantRead.Close()
		_ = readyWrite.Close()
		return err
	}
	childImage := os.NewFile(uintptr(copyFD), "fixed-child-sealed-wrapper")
	command.ExtraFiles[3] = childImage
	childFiles := []*os.File{proof, grantRead, readyWrite, childImage}
	fixtureInputs := versionFixtureInputs(fixtureParent, fixtureRoot, loader)
	for _, file := range fixtureInputs {
		fd, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 3)
		if err != nil {
			for _, held := range childFiles {
				_ = held.Close()
			}
			return err
		}
		childFiles = append(childFiles, os.NewFile(uintptr(fd), "fixed-worker-fixture-capability"))
	}
	command.ExtraFiles = childFiles
	owner := &outerCustodian{pidfd: -1, done: make(chan struct{}), exit: -1}
	defer func() {
		cleanupErr := retained.close(owner)
		retainWorkerObservation(record, owner, stdout, stderr)
		record["outer_namespace_cleanup_observed"] = cleanupErr == nil
		record["pending_outer_cleanup"] = len(retained.pending)
		resultErr = errors.Join(resultErr, cleanupErr)
	}()
	record["owned_worker_start_attempted"] = true
	if err := owner.start(ctx, command, &pidfd, childFiles); err != nil {
		return err
	}
	deadline := time.Now().Add(10 * time.Second)
	if outer, ok := ctx.Deadline(); ok && outer.Before(deadline) {
		deadline = outer
	}
	if readyRead.SetReadDeadline(deadline) != nil {
		return errors.New("fixed worker readiness deadline refused")
	}
	ready := make([]byte, len(workerReady))
	if _, err := io.ReadFull(readyRead, ready); err != nil || string(ready) != workerReady {
		return errors.New("fixed worker readiness refused")
	}
	record["outer_worker_ready_observed"] = true
	if grantWrite.SetWriteDeadline(deadline) != nil {
		return errors.New("fixed worker grant deadline refused")
	}
	if _, err := io.WriteString(grantWrite, workerGrant); err != nil {
		return errors.New("fixed worker grant refused")
	}
	if err := grantWrite.Close(); err != nil {
		return err
	}
	record["outer_worker_grant_sent"] = true
	record["execution_performed"] = nil // worker may now start the fixed payload
	select {
	case <-owner.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	data, overflow := stdout.snapshot()
	diagnostics, stderrOverflow := stderr.snapshot()
	record["owned_worker_exit_code"] = owner.exit
	var child map[string]any
	decoder := json.NewDecoder(bytes.NewReader(data))
	if overflow || decoder.Decode(&child) != nil || decoder.Decode(new(any)) != io.EOF || child["scope"] != registry.Receipt.Scope || child["fixed_suite"] != opts.suite || child["production_certification"] != false || child["common_launch_gate_qualified"] != false {
		return errors.New("fixed owned worker observation refused")
	}
	for key, value := range child {
		record[key] = value
	}
	record["owned_worker_result_observed"] = true
	if stderrOverflow || len(diagnostics) != 0 || owner.waitErr != nil || owner.exit != 0 || child["passed"] != true {
		return errors.New("fixed owned worker failed or exceeded output bound")
	}
	return nil
}

func executeWorker(args []string) (map[string]any, *cleanupOwner, error) {
	opts, err := workerOptions(args)
	if err != nil {
		return executeWorkerWithRegistry(args, reviewedRegistry{})
	}
	return executeWorkerWithRegistry(args, registryForSuite(opts.suite))
}

func executeWorkerWithRegistry(args []string, registry reviewedRegistry) (map[string]any, *cleanupOwner, error) {
	record := map[string]any{"scope": harnessScope, "passed": false, "execution_performed": false, "production_certification": false, "common_launch_gate_qualified": false}
	owner := &cleanupOwner{}
	record["worker_admission_stage"] = "registry"
	if registry.validate() != nil {
		return record, owner, errUnreviewed
	}
	record["worker_admission_stage"] = "metadata"
	opts, err := workerOptions(args)
	if err != nil {
		return record, owner, err
	}
	record["fixed_suite"] = opts.suite
	if !registry.supportsSuite(opts.suite) {
		return record, owner, errUnreviewed
	}
	record["scope"] = registry.Receipt.Scope
	record["worker_admission_stage"] = "namespace_identity"
	if os.Getpid() != 1 || os.Getppid() != 0 || runtime.GOARCH != "amd64" {
		return record, owner, errors.New("fixed worker requires its owned PID namespace")
	}
	record["worker_admission_stage"] = "namespace_bootstrap"
	if err := namespaceinit.Setup(); err != nil {
		return record, owner, err
	}
	record["namespace_bootstrap_complete"] = true
	observeProcPIDView(record)
	record["worker_admission_stage"] = "private_channels"
	grant, ready, self := os.NewFile(4, "fixed-worker-grant"), os.NewFile(5, "fixed-worker-ready"), os.NewFile(6, "fixed-worker-self")
	defer grant.Close()
	defer ready.Close()
	defer self.Close()
	for index, file := range []*os.File{grant, ready} {
		var stat unix.Stat_t
		flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
		want := unix.O_RDONLY
		if index == 1 {
			want = unix.O_WRONLY
		}
		if err != nil || unix.Fstat(int(file.Fd()), &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFIFO || flags&unix.O_ACCMODE != want {
			return record, owner, errors.New("fixed worker private channel refused")
		}
	}
	record["worker_admission_stage"] = "sealed_self"
	seals, err := unix.FcntlInt(self.Fd(), unix.F_GET_SEALS, 0)
	if err != nil || seals != unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL {
		return record, owner, errors.New("fixed worker sealed self image refused")
	}
	record["worker_admission_stage"] = "self_identity"
	current, err := os.Open("/proc/self/exe")
	if err != nil {
		return record, owner, err
	}
	d, i, currentErr := identity(current)
	sd, si, selfErr := identity(self)
	closeErr := current.Close()
	if errors.Join(currentErr, selfErr, closeErr) != nil || d != sd || i != si {
		return record, owner, errors.New("fixed worker self image identity differs")
	}
	record["worker_admission_stage"] = "ready_and_grant"
	if err := readyThenGrant(ready, grant); err != nil {
		return record, owner, err
	}
	record["worker_admission_stage"] = "native_fixed_cases"
	record["owned_guardian_grant_observed"] = true
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	return record, owner, runNative(ctx, opts, registry, record, workerPermit{granted: true}, owner)
}
