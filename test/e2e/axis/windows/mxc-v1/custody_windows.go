// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build ignore

// Fixed contributor-only headless wrapper. It launches only the verified PSEC
// probe, suspended until assigned to its owned kill-on-close Windows Job.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"golang.org/x/sys/windows"
)

const binaryName = "bin/defenseclaw-axis-windows-psec-probe.exe"
const loaderName = "bin/defenseclaw-axis-windows-psec-loader-child.exe"
const diagnosticVariant = "separate_std_loader_diagnostic"
const diagnosticScope = "fixed_windows_native_psec_loader_diagnostic"
const boundaryName = "bin/defenseclaw-axis-windows-psec-boundary-child.exe"
const boundaryVariant = "standalone_std_boundary_native_identity_environment"
const boundaryScope = "fixed_windows_native_psec_boundary_native_identity_environment"
const dllName = "bin/defenseclaw-axis-windows-psec-dll-child.exe"
const dllVariant = "standalone_std_fixed_dll_startup_diagnostic"
const dllScope = "fixed_windows_native_psec_dll_startup_diagnostic"
const combinedLock = "3b29ecb06dd2a81266c84712f8d6e088605290f386e87498bb7a7472a005af69"
const outputBound = 64 * 1024

var shaPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

type receipt struct {
	ProbeCargoFeatures      []string    `json:"probe_cargo_features,omitempty"`
	Verified                bool        `json:"verified"`
	ExecutionPerformed      *bool       `json:"execution_performed"`
	ProductionCertification *bool       `json:"production_certification"`
	Scope                   string      `json:"scope"`
	Variant                 string      `json:"variant"`
	Axis                    string      `json:"axis_commit"`
	MXC                     string      `json:"mxc_commit"`
	BuildCommit             string      `json:"build_commit"`
	BuildRun                int64       `json:"build_run"`
	ArtifactID              int64       `json:"artifact_id"`
	Archive                 string      `json:"archive_sha256"`
	Provenance              string      `json:"provenance_sha256"`
	Lock                    string      `json:"combined_lock_sha256"`
	Artifact                string      `json:"artifact"`
	Binary                  string      `json:"binary"`
	BinarySHA               string      `json:"binary_sha256"`
	BinarySize              int64       `json:"binary_size"`
	Binaries                []component `json:"binaries"`
}

type component struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type pinnedImages []*os.File

func (files pinnedImages) Close() error {
	var result error
	for _, file := range files {
		result = errors.Join(result, file.Close())
	}
	return result
}

func noReparse(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("absolute ordinary path required")
	}
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		name, err := windows.UTF16PtrFromString(current)
		if err != nil {
			return err
		}
		attributes, err := windows.GetFileAttributes(name)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errors.New("reparse-point paths are refused")
		}
		if filepath.Dir(current) == current {
			return nil
		}
	}
}

func pinFile(path string, maximum int64) (*os.File, string, error) {
	if err := noReparse(path); err != nil {
		return nil, "", err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, "", err
	}
	// Share read access only: keep the verified image open against replacement
	// or writes through the complete owned run. This is a benign probe wrapper,
	// not a production installer or receipt authority.
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, "", err
	}
	file := os.NewFile(uintptr(handle), path)
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maximum {
		file.Close()
		return nil, "", errors.New("pinned file type or size differs")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, maximum+1)); err != nil {
		file.Close()
		return nil, "", err
	}
	return file, hex.EncodeToString(hash.Sum(nil)), nil
}

func checkedReceipt(path, expectedSHA, mode string) (*receipt, pinnedImages, error) {
	variant, scope := diagnosticVariant, diagnosticScope
	seen := map[string]bool{binaryName: false, loaderName: false}
	if mode == "standalone-boundary" {
		variant, scope = boundaryVariant, boundaryScope
		seen[boundaryName] = false
	} else if mode == "dll-startup-only" {
		variant, scope = dllVariant, dllScope
		seen[boundaryName], seen[dllName] = false, false
	} else if mode == "claude-create-control-only" {
		variant, scope = claudeControlVariant, claudeControlScope
		seen[boundaryName], seen[dllName] = false, false
	} else if mode == "claude-version-only" {
		variant, scope = claudeArtifactVariant, claudeArtifactScope
		seen[boundaryName], seen[dllName] = false, false
	} else if mode != "loader-only" {
		return nil, nil, errors.New("unknown fixed mode")
	}
	if !shaPattern.MatchString(expectedSHA) {
		return nil, nil, errors.New("an explicit receipt SHA256 pin is required")
	}
	file, actualSHA, err := pinFile(path, 64*1024)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	if actualSHA != expectedSHA {
		return nil, nil, errors.New("verification receipt changed")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, nil, err
	}
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var value receipt
	if err := decoder.Decode(&value); err != nil {
		return nil, nil, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, nil, errors.New("receipt has trailing JSON")
	}
	if !value.Verified || value.ExecutionPerformed == nil || *value.ExecutionPerformed ||
		value.ProductionCertification == nil || *value.ProductionCertification ||
		value.Scope != scope || value.Variant != variant ||
		value.Axis != "fb5fd5f0f9377c2ccb30d7e027a36373de0d037c" ||
		value.MXC != "fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2" ||
		value.Lock != combinedLock || value.Binary != binaryName ||
		!commitPattern.MatchString(value.BuildCommit) || value.BuildRun <= 0 || value.ArtifactID <= 0 ||
		!shaPattern.MatchString(value.Archive) || !shaPattern.MatchString(value.Provenance) ||
		!shaPattern.MatchString(value.BinarySHA) || value.BinarySize <= 0 || value.BinarySize > 64*1024*1024 {
		return nil, nil, errors.New("the reviewed locked Windows PSEC verification receipt is required")
	}
	if mode == "claude-create-control-only" {
		if len(value.ProbeCargoFeatures) != 1 || value.ProbeCargoFeatures[0] != "fixed-claude-create-control" {
			return nil, nil, errors.New("fixed control build feature evidence differs")
		}
	} else if len(value.ProbeCargoFeatures) != 0 {
		return nil, nil, errors.New("ordinary PSEC receipt cannot admit the uncontained build feature")
	}
	if len(value.Binaries) != len(seen) {
		return nil, nil, errors.New("all exact fixed-mode binaries are required")
	}
	var images pinnedImages
	for _, item := range value.Binaries {
		present, allowed := seen[item.Path]
		if !allowed || present || !shaPattern.MatchString(item.SHA256) || item.Size < 1 || item.Size > 64*1024*1024 {
			images.Close()
			return nil, nil, errors.New("diagnostic image inventory differs")
		}
		if item.Path == binaryName && (item.SHA256 != value.BinarySHA || item.Size != value.BinarySize) {
			images.Close()
			return nil, nil, errors.New("primary image identity differs")
		}
		seen[item.Path] = true
		image, actualSHA, err := pinFile(filepath.Join(value.Artifact, filepath.FromSlash(item.Path)), 64*1024*1024)
		if err != nil {
			images.Close()
			return nil, nil, err
		}
		images = append(images, image)
		info, err := image.Stat()
		if err != nil || info.Size() != item.Size || actualSHA != item.SHA256 {
			images.Close()
			return nil, nil, errors.New("verified diagnostic image changed")
		}
	}
	return &value, images, nil
}

type captured struct {
	mu       sync.Mutex
	data     []byte
	overflow bool
}

func (output *captured) drain(file *os.File, done chan<- error) {
	buffer := make([]byte, 4096)
	for {
		n, err := file.Read(buffer)
		if n > 0 {
			output.mu.Lock()
			if len(output.data)+n <= outputBound {
				output.data = append(output.data, buffer[:n]...)
			} else {
				output.overflow = true
			}
			output.mu.Unlock()
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = nil
			}
			done <- err
			return
		}
	}
}

func (output *captured) snapshot() (string, bool) {
	output.mu.Lock()
	defer output.mu.Unlock()
	return string(output.data), output.overflow
}

type jobAccounting struct {
	TotalUserTime, TotalKernelTime, PeriodUserTime, PeriodKernelTime int64
	PageFaults, TotalProcesses, ActiveProcesses, TerminatedProcesses uint32
}

func waitJobEmpty(job windows.Handle, duration time.Duration) (uint32, error) {
	deadline := time.Now().Add(duration)
	for {
		var info jobAccounting
		if err := windows.QueryInformationJobObject(job, windows.JobObjectBasicAccountingInformation,
			uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), nil); err != nil {
			return 0, err
		}
		if info.ActiveProcesses == 0 {
			return 0, nil
		}
		if time.Now().After(deadline) {
			return info.ActiveProcesses, errors.New("owned outer Job is not empty")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func childPipe() (windows.Handle, *os.File, error) {
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), InheritHandle: 1}
	var read, write windows.Handle
	if err := windows.CreatePipe(&read, &write, &sa, 0); err != nil {
		return 0, nil, err
	}
	if err := windows.SetHandleInformation(read, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
		windows.CloseHandle(read)
		windows.CloseHandle(write)
		return 0, nil, err
	}
	return write, os.NewFile(uintptr(read), "owned-output-pipe"), nil
}

func run(value *receipt, root, mode string, runtimeImages pinnedImages, localImage fixedLocalImage) (record map[string]any, resultErr error) {
	record = map[string]any{"passed": false, "production_certification": false, "scope": value.Scope,
		"variant": value.Variant, "mode": mode,
		"probe_cargo_features": value.ProbeCargoFeatures,
		"binary_sha256":        value.BinarySHA, "build_commit": value.BuildCommit, "build_run": value.BuildRun,
		"combined_lock_sha256": value.Lock, "artifact_id": value.ArtifactID}
	if !filepath.IsAbs(root) || !strings.HasPrefix(filepath.Base(root), "psec-headless-") {
		return record, errors.New("absolute fresh psec-headless-* case directory required")
	}
	if err := noReparse(filepath.Dir(root)); err != nil {
		return record, err
	}
	if isClaudeMode(mode) {
		if created, err := safefile.CreatePrivateDirectory(root); err != nil || !created {
			return record, errors.Join(errors.New("fresh private Claude case required"), err)
		}
	} else {
		if err := os.Mkdir(root, 0700); err != nil {
			return record, err
		}
	}
	for _, relative := range []string{"home", "tmp", "workspace", filepath.Join("home", "AppData"), filepath.Join("home", "AppData", "Roaming"), filepath.Join("home", "AppData", "Local")} {
		if err := os.Mkdir(filepath.Join(root, relative), 0700); err != nil {
			return record, err
		}
	}
	binary := filepath.Join(value.Artifact, filepath.FromSlash(binaryName))
	if isClaudeMode(mode) {
		staged, held, err := stageClaudeVersionImages(value, runtimeImages, localImage, root)
		if err != nil {
			return record, err
		}
		defer func() { resultErr = errors.Join(resultErr, held.Close()) }()
		binary = staged
		record["local_image_sha256"], record["local_image_size"] = claudeImageSHA, claudeImageSize
		record["local_image_product_version"] = claudeProductVersion
	}
	system, err := windows.GetSystemWindowsDirectory()
	if err != nil || !filepath.IsAbs(system) {
		return record, errors.New("native Windows system directory unavailable")
	}
	environment := map[string]string{"SYSTEMROOT": system, "WINDIR": system,
		"HOME": filepath.Join(root, "home"), "USERPROFILE": filepath.Join(root, "home"),
		"APPDATA": filepath.Join(root, "home", "AppData", "Roaming"), "LOCALAPPDATA": filepath.Join(root, "home", "AppData", "Local"),
		"TEMP": filepath.Join(root, "tmp"), "TMP": filepath.Join(root, "tmp")}
	var entries []string
	for key, value := range environment {
		entries = append(entries, key+"="+value)
	}
	sort.Strings(entries)
	envBlock := utf16.Encode([]rune(strings.Join(entries, "\x00") + "\x00\x00"))
	stdoutWrite, stdout, err := childPipe()
	if err != nil {
		return record, err
	}
	readersStarted, readersFinished := false, false
	defer func() {
		if !readersStarted || readersFinished {
			stdout.Close()
		}
	}()
	defer func() {
		if stdoutWrite != 0 {
			windows.CloseHandle(stdoutWrite)
		}
	}()
	stderrWrite, stderr, err := childPipe()
	if err != nil {
		return record, err
	}
	defer func() {
		if !readersStarted || readersFinished {
			stderr.Close()
		}
	}()
	defer func() {
		if stderrWrite != 0 {
			windows.CloseHandle(stderrWrite)
		}
	}()
	nulName, _ := windows.UTF16PtrFromString("NUL")
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), InheritHandle: 1}
	stdin, err := windows.CreateFile(nulName, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, &sa, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return record, err
	}
	defer windows.CloseHandle(stdin)
	handles := []windows.Handle{stdin, stdoutWrite, stderrWrite}
	attributes, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return record, err
	}
	defer attributes.Delete()
	if err := attributes.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&handles[0]), uintptr(len(handles))*unsafe.Sizeof(handles[0])); err != nil {
		return record, err
	}
	startup := windows.StartupInfoEx{}
	startup.Cb = uint32(unsafe.Sizeof(startup))
	startup.Flags = windows.STARTF_USESTDHANDLES
	startup.StdInput, startup.StdOutput, startup.StdErr = stdin, stdoutWrite, stderrWrite
	startup.ProcThreadAttributeList = attributes.List()
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return record, err
	}
	defer windows.CloseHandle(job)
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return record, err
	}
	application, err := windows.UTF16PtrFromString(binary)
	if err != nil {
		return record, err
	}
	command := []string{binary}
	if mode == "loader-only" {
		command = append(command, "--loader-only")
	} else if mode == "dll-startup-only" {
		command = append(command, "--dll-startup-only")
	} else if isClaudeMode(mode) {
		command = append(command, "--"+mode)
	} else if mode != "standalone-boundary" {
		return record, errors.New("unknown fixed mode")
	}
	commandLine, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(command))
	if err != nil {
		return record, err
	}
	cwd, err := windows.UTF16PtrFromString(filepath.Join(root, "workspace"))
	if err != nil {
		return record, err
	}
	var process windows.ProcessInformation
	if err := windows.CreateProcess(application, commandLine, nil, nil, true,
		windows.CREATE_SUSPENDED|windows.CREATE_UNICODE_ENVIRONMENT|windows.EXTENDED_STARTUPINFO_PRESENT|windows.CREATE_NO_WINDOW,
		&envBlock[0], cwd, &startup.StartupInfo, &process); err != nil {
		return record, err
	}
	defer windows.CloseHandle(process.Process)
	defer windows.CloseHandle(process.Thread)
	windows.CloseHandle(stdoutWrite)
	stdoutWrite = 0
	windows.CloseHandle(stderrWrite)
	stderrWrite = 0
	var out, diagnostic captured
	readers := make(chan error, 2)
	go out.drain(stdout, readers)
	go diagnostic.drain(stderr, readers)
	readersStarted = true
	assigned := false
	defer func() {
		state, waitErr := windows.WaitForSingleObject(process.Process, 0)
		if waitErr != nil || state != windows.WAIT_OBJECT_0 || resultErr != nil {
			resultErr = errors.Join(resultErr, windows.TerminateJobObject(job, 2))
			if state != windows.WAIT_OBJECT_0 {
				resultErr = errors.Join(resultErr, windows.TerminateProcess(process.Process, 2))
			}
		}
		state, waitErr = windows.WaitForSingleObject(process.Process, 5000)
		if waitErr != nil || state != windows.WAIT_OBJECT_0 {
			resultErr = errors.Join(resultErr, errors.New("owned supervisor handle did not stop"), waitErr)
		}
		active, emptyErr := waitJobEmpty(job, 5*time.Second)
		record["outer_job_active_before_final_cleanup"] = active
		if emptyErr != nil {
			resultErr = errors.Join(resultErr, emptyErr, windows.TerminateJobObject(job, 2))
			_, emptyErr = waitJobEmpty(job, 5*time.Second)
			resultErr = errors.Join(resultErr, emptyErr)
		}
		record["outer_job_empty"] = emptyErr == nil
		record["assigned_before_resume"] = assigned
		completedReaders := 0
		for i := 0; i < 2; i++ {
			select {
			case readErr := <-readers:
				completedReaders++
				resultErr = errors.Join(resultErr, readErr)
			case <-time.After(2 * time.Second):
				// A synchronous Windows pipe reader may hold a close lock.
				// Fail and leave its handle for this CLI process's teardown;
				// never defeat the deadline by closing it from this goroutine.
				resultErr = errors.Join(resultErr, errors.New("bounded output readers did not finish"))
			}
		}
		readersFinished = completedReaders == 2
		text, overflow := out.snapshot()
		errorText, errorOverflow := diagnostic.snapshot()
		if overflow || errorOverflow {
			resultErr = errors.Join(resultErr, errors.New("fixed output exceeded bound"))
		}
		record["stdout"], record["stderr"], record["error"] = text, errorText, fmt.Sprint(resultErr)
		record["passed"] = resultErr == nil && assigned && state == windows.WAIT_OBJECT_0
	}()
	record["supervisor_pid"] = process.ProcessId
	record["command"] = command
	if err := windows.AssignProcessToJobObject(job, process.Process); err != nil {
		return record, err
	}
	assigned = true
	if _, err := windows.ResumeThread(process.Thread); err != nil {
		return record, err
	}
	state, err := windows.WaitForSingleObject(process.Process, 30000)
	if err != nil || state != windows.WAIT_OBJECT_0 {
		return record, errors.Join(errors.New("bounded supervisor deadline or wait failure"), err)
	}
	var exit uint32
	if err := windows.GetExitCodeProcess(process.Process, &exit); err != nil {
		return record, err
	}
	record["exit_code"] = exit
	if exit != 0 {
		return record, fmt.Errorf("fixed PSEC probe exited %d", exit)
	}
	return record, nil
}

func selectedMode(loader, boundary, dll, claude, control bool) (string, error) {
	choices := 0
	for _, selected := range []bool{loader, boundary, dll, claude, control} {
		if selected {
			choices++
		}
	}
	if choices != 1 {
		return "", errors.New("exactly one fixed mode is required")
	}
	if control {
		return "claude-create-control-only", nil
	}
	if claude {
		return "claude-version-only", nil
	}
	if dll {
		return "dll-startup-only", nil
	}
	if boundary {
		return "standalone-boundary", nil
	}
	return "loader-only", nil
}

func main() {
	loaderOnly := flag.Bool("loader-only", false, "explicit fixed std-only loader diagnostic")
	boundary := flag.Bool("standalone-boundary", false, "explicit fixed std-only boundary and literal argv cases")
	dll := flag.Bool("dll-startup-only", false, "explicit fixed System32 DLL startup observations")
	claude := flag.Bool("claude-version-only", false, "explicit fixed signed Claude 2.1.292 --version")
	control := flag.Bool("claude-create-control-only", false, "explicit UNCONTAINED fixed Claude creation discriminator")
	localReceipt := flag.String("local-image-receipt", "", "independently reviewed fixed local-image receipt")
	localReceiptSHA := flag.String("local-image-receipt-sha256", "", "independent local-image receipt SHA256")
	receiptPath := flag.String("receipt", "", "absolute independently verified receipt")
	receiptSHA := flag.String("receipt-sha256", "", "reviewed receipt SHA256")
	caseRoot := flag.String("case-root", "", "absolute fresh psec-headless-* case path")
	flag.Parse()
	mode, modeErr := selectedMode(*loaderOnly, *boundary, *dll, *claude, *control)
	if flag.NArg() != 0 || modeErr != nil {
		fmt.Fprintln(os.Stderr, "exactly one fixed mode is required; no workload arguments accepted")
		os.Exit(2)
	}
	if isClaudeMode(mode) != (*localReceipt != "" && *localReceiptSHA != "") ||
		(!isClaudeMode(mode) && (*localReceipt != "" || *localReceiptSHA != "")) {
		fmt.Fprintln(os.Stderr, "only the fixed Claude mode accepts its separate local-image receipt")
		os.Exit(2)
	}
	value, image, err := checkedReceipt(*receiptPath, *receiptSHA, mode)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	defer func() {
		if image != nil {
			_ = image.Close()
		}
	}()
	var localImage fixedLocalImage
	if isClaudeMode(mode) {
		localImage, err = checkLocalClaudeReceipt(*localReceipt, *localReceiptSHA)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}
	started := time.Now()
	record, err := run(value, *caseRoot, mode, image, localImage)
	if isClaudeMode(mode) {
		err = errors.Join(err, localImage.held.Close(), image.Close())
		image = nil
		record["local_image_review_receipt_sha256"] = *localReceiptSHA
	}
	record["elapsed_seconds"] = time.Since(started).Seconds()
	if err != nil {
		record["error"] = err.Error()
		record["passed"] = false
	}
	if encodeErr := json.NewEncoder(os.Stdout).Encode(record); encodeErr != nil {
		os.Exit(1)
	}
	if err != nil {
		os.Exit(1)
	}
}
