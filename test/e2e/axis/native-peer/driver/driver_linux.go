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
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/axis/namespaceinit"
	"golang.org/x/sys/unix"
)

func runDriver(ctx context.Context, opts options, admission wrapperAdmission, record map[string]any, retained *cleanupOwner) (resultErr error) {
	if err := admission.validate(); err != nil {
		return err
	}
	if retained == nil || runtime.GOARCH != "amd64" || os.Geteuid() == 0 || os.Getuid() != os.Geteuid() || os.Getgid() != os.Getegid() || filepath.Base(opts.receipt) != "REVIEWED-ARTIFACTS.json" {
		return errors.New("fixed unprivileged native Linux driver required")
	}
	root, err := openDirectory(filepath.Dir(opts.receipt))
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, root.Close()) }()
	if err := privateDirectory(root); err != nil {
		return err
	}
	receipt, _, err := boundedFile(root, "REVIEWED-ARTIFACTS.json", 64<<10, receiptForSuite(opts.suite))
	if err != nil {
		return err
	}
	if err := receipt.Close(); err != nil {
		return err
	}
	source, data, err := boundedFile(root, "images/reviewed-wrapper", admission.Size, admission.SHA)
	if err != nil {
		return err
	}
	if err := source.Close(); err != nil {
		return err
	}
	if int64(len(data)) != admission.Size {
		return errors.New("fixed wrapper size differs")
	}
	wrapper, err := sealBytes(data, admission.SHA)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, wrapper.Close()) }()
	self, selfHash, err := sealedRunningImage()
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, self.Close()) }()
	record["driver_self_image_sha256"], record["reviewed_wrapper_sha256"] = selfHash, admission.SHA
	record["driver_stage"] = "host_fixture"
	fixture, err := newHostFixture()
	if fixture != nil {
		record["synthetic_fixture"], record["fixture_retained"] = fixture.path, true
		defer func() {
			if opts.suite == claudeVersionSuite {
				resultErr = errors.Join(resultErr, retained.releaseResource(func() error {
					if fixture.loader != nil {
						if err := verifyDriverVersionLoader(fixture.root, fixture.loader, true); err != nil {
							return err
						}
						var st unix.Stat_t
						if err := unix.Fstat(int(fixture.loader.Fd()), &st); err != nil {
							return err
						}
						record["retained_loader"] = map[string]any{"leaf": claudeLoaderLeaf, "device": uint64(st.Dev), "inode": st.Ino, "size": int64(claudeLoaderSize), "sha256": claudeLoaderSHA}
					}
					return fixture.close()
				}))
				record["pending_driver_loader_resources"] = len(retained.heldResources)
			} else {
				resultErr = errors.Join(resultErr, fixture.close())
			}
		}()
	}
	if err != nil {
		return err
	}
	if opts.suite == claudeVersionSuite {
		record["driver_stage"] = "held_loader_copy"
		if err := copyVersionLoader(root, fixture); err != nil {
			return err
		}
		record["held_loader_copy_verified_before_clone"] = true
	}
	record["host_fixture_source_no_idmap_verified_before_clone"] = true
	record["host_fixture_parent_verified_before_clone"] = true
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
	var childFiles []*os.File
	fixedInputs := append([]*os.File{self, wrapper}, versionFixtureInputs(fixture.parent, fixture.root, fixture.loader)...)
	for _, image := range fixedInputs {
		fd, err := unix.FcntlInt(image.Fd(), unix.F_DUPFD_CLOEXEC, 3)
		if err != nil {
			_ = grantRead.Close()
			_ = readyWrite.Close()
			for _, copy := range childFiles {
				_ = copy.Close()
			}
			return err
		}
		childFiles = append(childFiles, os.NewFile(uintptr(fd), "fixed-child-owned-image"))
	}
	proof, err := namespaceinit.Capture()
	if err != nil {
		_ = grantRead.Close()
		_ = readyWrite.Close()
		for _, file := range childFiles {
			_ = file.Close()
		}
		return err
	}
	childFiles = append([]*os.File{proof, grantRead, readyWrite}, childFiles...)
	stdout, stderr := &boundedCapture{}, &boundedCapture{}
	pidfd := -1
	command := &exec.Cmd{Path: "/proc/self/fd/6", Args: []string{"fixed-native-peer-outer-driver", "--owned-wrapper-bootstrap", "--receipt", opts.receipt, "--evidence", opts.evidence, "--suite", opts.suite}, Env: []string{}, Dir: "/", ExtraFiles: childFiles, Stdout: stdout, Stderr: stderr,
		SysProcAttr: &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNET | syscall.CLONE_NEWIPC | syscall.CLONE_NEWUTS,
			AmbientCaps: []uintptr{unix.CAP_SYS_ADMIN},
			UidMappings: []syscall.SysProcIDMap{{ContainerID: os.Getuid(), HostID: os.Getuid(), Size: 1}}, GidMappings: []syscall.SysProcIDMap{{ContainerID: os.Getgid(), HostID: os.Getgid(), Size: 1}}, GidMappingsEnableSetgroups: false, PidFD: &pidfd}}
	owner := &outerCustodian{pidfd: -1, done: make(chan struct{}), exit: -1}
	defer func() {
		cleanupErr := retained.close(owner)
		record["whole_wrapper_namespace_cleanup_observed"] = cleanupErr == nil
		record["pending_driver_cleanup"] = len(retained.pending)
		// Capture on failures too, after bounded native cleanup has been tried.
		// The capture locks protect readers that remain owned on a failed wait.
		output, stdoutOverflow := stdout.snapshot()
		diagnostics, stderrOverflow := stderr.snapshot()
		record["wrapper_stdout"], record["wrapper_stderr"] = string(output), string(diagnostics)
		record["stdout_truncated"], record["stderr_truncated"] = stdoutOverflow, stderrOverflow
		resultErr = errors.Join(resultErr, cleanupErr)
	}()
	record["driver_stage"] = "wrapper_namespace_start"
	record["wrapper_namespace_start_attempted"] = true
	if err := owner.start(ctx, command, &pidfd, childFiles); err != nil {
		return err
	}
	deadline := time.Now().Add(10 * time.Second)
	if outer, ok := ctx.Deadline(); ok && outer.Before(deadline) {
		deadline = outer
	}
	if readyRead.SetReadDeadline(deadline) != nil || grantWrite.SetWriteDeadline(deadline) != nil {
		return errors.New("fixed outer handshake deadline refused")
	}
	ready := make([]byte, len(workerReady))
	if _, err := io.ReadFull(readyRead, ready); err != nil || string(ready) != workerReady {
		return errors.New("fixed outer bootstrap readiness refused")
	}
	record["bootstrap_ready_observed"] = true
	if _, err := io.WriteString(grantWrite, workerGrant); err != nil {
		return err
	}
	if err := grantWrite.Close(); err != nil {
		return err
	}
	record["wrapper_exec_authorized"], record["execution_performed"] = true, nil
	select {
	case <-owner.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	output, overflow := stdout.snapshot()
	diagnostics, stderrOverflow := stderr.snapshot()
	record["wrapper_exit_code"] = owner.exit
	var child map[string]any
	decoder := json.NewDecoder(bytes.NewReader(output))
	if overflow || stderrOverflow || len(diagnostics) != 0 || owner.waitErr != nil || owner.exit != 0 || decoder.Decode(&child) != nil || decoder.Decode(new(any)) != io.EOF {
		return errors.New("fixed wrapper output, exit or pipe bound failed")
	}
	record["wrapper_record"] = child
	if err := validateWrapperSuiteResult(child, opts.suite); err != nil {
		return err
	}
	record["wrapper_result_observed"], record["execution_performed"], record["passed"] = true, true, true
	return nil
}

func validateWrapperResult(child map[string]any) error {
	return validateWrapperSuiteResult(child, "baseline")
}

func validateWrapperSuiteResult(child map[string]any, suite string) error {
	if !validSuite(suite) || child["fixed_suite"] != suite {
		return errors.New("fixed wrapper suite differs")
	}
	if child["scope"] != scopeForSuite(suite) || child["passed"] != true || child["execution_performed"] != true || child["production_certification"] != false || child["common_launch_gate_qualified"] != false || child["artifact_receipt_sha256"] != receiptForSuite(suite) || child["outer_namespace_cleanup_observed"] != true || child["pending_outer_cleanup"] != float64(0) || child["pending_native_cleanup"] != float64(0) {
		return errors.New("fixed wrapper result or native cleanup differs")
	}
	if suite == claudeVersionSuite && (child["pending_version_resources"] != float64(0) || child["pending_outer_loader_resources"] != float64(0) || child["claude_version_output_observed"] != true) {
		return errors.New("fixed Claude source custody or output missing")
	}
	for _, key := range []string{"outer_worker_ready_observed", "outer_worker_grant_sent", "owned_worker_result_observed", "host_outside_read_and_write_positive_controls", "original_canary_identities_and_bytes_preserved"} {
		if child[key] != true {
			return errors.New("fixed wrapper control or canary evidence missing")
		}
	}
	want := []string{"argv", "stdio", "exit23", "boundaries"}
	if suite == claudeVersionSuite {
		want = []string{claudeVersionSuite}
	}
	if suite == "lifecycle" {
		want = []string{"wait-timeout", "wait-cancel", "tree-cancel"}
	}
	cases, ok := child["cases"].([]any)
	if !ok || len(cases) != len(want) {
		return errors.New("fixed wrapper case inventory differs")
	}
	for index, mode := range want {
		result, ok := cases[index].(map[string]any)
		if !ok || result["mode"] != mode || result["passed"] != true || result["prepared"] != true || result["started"] != true || suite != claudeVersionSuite && result["fixed_payload_marker_observed"] != true || result["destroyed"] != true || result["native_cleanup_observed"] != true || result["error"] != nil {
			return errors.New("fixed wrapper case assertion differs")
		}
		if suite == claudeVersionSuite {
			if result["claude_version_output_observed"] != true || result["output_bytes"] != float64(22) || result["stderr_bytes"] != float64(0) || result["exit_code"] != float64(0) || result["native_terminal_before_outer_cleanup"] != true || result["fixed_payload_marker_observed"] == true || result["timed_out"] == true || result["cancel_sent"] == true {
				return errors.New("fixed Claude version assertion differs")
			}
		} else if suite == "baseline" {
			if result["exit_code"] != float64(23) {
				return errors.New("fixed wrapper exit differs")
			}
		} else if result["exit_code"] != float64(-1) || result["timed_out"] != (mode == "wait-timeout") || result["cancel_sent"] != (mode != "wait-timeout") || result["native_terminal_before_outer_cleanup"] != true {
			return errors.New("fixed lifecycle terminal/cancel assertions differ")
		}
		if mode == "tree-cancel" && (result["tree_ready_files_verified"] != true || result["tree_heartbeat_progress_observed"] != true || result["tree_heartbeat_stable_before_destroy"] != true) {
			return errors.New("fixed lifecycle tree observations missing")
		}
		if mode == "tree-cancel" && !validTreeHeartbeatEvidence(result["tree_heartbeat_samples"]) {
			return errors.New("fixed lifecycle heartbeat sample inventory differed")
		}
	}
	return nil
}

func validTreeHeartbeatEvidence(value any) bool {
	object, ok := value.(map[string]any)
	if !ok || len(object) != 4 || object["stable_samples"] != float64(6) {
		return false
	}
	var counts [3][3]uint32
	for row, name := range []string{"before", "progressed", "terminal"} {
		values, ok := object[name].([]any)
		if !ok || len(values) != 3 {
			return false
		}
		for column, value := range values {
			number, ok := value.(float64)
			if !ok || number < 1 || number > 1000000 || number != float64(uint32(number)) {
				return false
			}
			counts[row][column] = uint32(number)
		}
	}
	for column := range 3 {
		if counts[1][column] <= counts[0][column] || counts[2][column] < counts[1][column] {
			return false
		}
	}
	return true
}

func bootstrap(args []string, admission wrapperAdmission) (map[string]any, *cleanupOwner, error) {
	record := map[string]any{"scope": scope, "passed": false, "execution_performed": false, "production_certification": false}
	owner := &cleanupOwner{}
	if err := admission.validate(); err != nil {
		return record, owner, err
	}
	opts, err := bootstrapOptions(args)
	if err != nil || admission.VersionOnly != (opts.suite == claudeVersionSuite) || os.Getpid() != 1 || os.Getppid() != 0 || os.Geteuid() == 0 || runtime.GOARCH != "amd64" {
		return record, owner, errors.New("fixed owned bootstrap required")
	}
	record["fixed_suite"] = opts.suite
	// Setup installs PDEATHSIG, verifies owned fresh USER/MNT/PID namespaces,
	// mounts matching procfs and drops capabilities on every Go OS thread.
	// No READY or GRANT is processed before successful completion.
	if err := namespaceinit.Setup(); err != nil {
		return record, owner, err
	}
	grant, ready, self, wrapper := os.NewFile(4, "fixed-outer-grant"), os.NewFile(5, "fixed-outer-ready"), os.NewFile(6, "fixed-outer-self"), os.NewFile(7, "fixed-outer-wrapper")
	fixtureParent, fixtureRoot := os.NewFile(8, "fixed-host-fixture-parent"), os.NewFile(9, "fixed-host-fixture-root")
	defer fixtureParent.Close()
	defer fixtureRoot.Close()
	if err := checkInheritedFixture(fixtureParent, fixtureRoot); err != nil {
		return record, owner, err
	}
	var loader *os.File
	if opts.suite == claudeVersionSuite {
		loader = os.NewFile(10, "fixed-inherited-version-loader")
		defer loader.Close()
		if err := verifyDriverVersionLoader(fixtureRoot, loader, false); err != nil {
			return record, owner, err
		}
	}
	defer grant.Close()
	defer ready.Close()
	defer self.Close()
	defer wrapper.Close()
	for index, file := range []*os.File{grant, ready} {
		var st unix.Stat_t
		flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
		want := unix.O_RDONLY
		if index == 1 {
			want = unix.O_WRONLY
		}
		if err != nil || unix.Fstat(int(file.Fd()), &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFIFO || flags&unix.O_ACCMODE != want {
			return record, owner, errors.New("fixed private outer channel refused")
		}
	}
	for _, file := range []*os.File{self, wrapper} {
		seals, err := unix.FcntlInt(file.Fd(), unix.F_GET_SEALS, 0)
		if err != nil || seals != unix.F_SEAL_SEAL|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_WRITE {
			return record, owner, errors.New("fixed sealed outer image refused")
		}
	}
	current, err := os.Open("/proc/self/exe")
	if err != nil {
		return record, owner, err
	}
	var currentStat, selfStat unix.Stat_t
	identityErr := errors.Join(unix.Fstat(int(current.Fd()), &currentStat), unix.Fstat(int(self.Fd()), &selfStat), current.Close())
	if identityErr != nil || currentStat.Dev != selfStat.Dev || currentStat.Ino != selfStat.Ino {
		return record, owner, errors.New("fixed bootstrap self identity differs")
	}
	info, err := wrapper.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != admission.Size {
		return record, owner, errors.New("fixed wrapper size differs")
	}
	data := make([]byte, admission.Size)
	if _, err := wrapper.ReadAt(data, 0); err != nil || digestBytes(data) != admission.SHA || validateStaticELF(data) != nil {
		return record, owner, errors.New("fixed wrapper image differs")
	}
	if err := readyThenGrant(ready, grant); err != nil {
		return record, owner, err
	}
	if err := errors.Join(grant.Close(), ready.Close(), self.Close()); err != nil {
		return record, owner, err
	}
	if _, err := unix.FcntlInt(wrapper.Fd(), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
		return record, owner, err
	}
	if loader != nil {
		flags, err := unix.FcntlInt(loader.Fd(), unix.F_GETFD, 0)
		if err != nil || flags&unix.FD_CLOEXEC != 0 {
			return record, owner, errors.New("fixed loader exec handoff refused")
		}
	}
	// Literal proc-self FD names the still-held sealed executable; no host image
	// pathname is reopened. Exec has no PATH lookup or command-string parsing.
	err = syscall.Exec("/proc/self/fd/7", []string{"reviewed-native-peer-wrapper", "--run-fixed", "--receipt", opts.receipt, "--evidence", opts.evidence, "--suite", opts.suite}, []string{})
	runtime.KeepAlive(wrapper)
	return record, owner, err
}
