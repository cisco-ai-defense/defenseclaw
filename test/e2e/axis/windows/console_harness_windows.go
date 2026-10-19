// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build ignore

// Fixed contributor-only native ConPTY experiment. It starts only the verified
// AXIS executable and the reviewed fixed probe; it accepts no workload command.
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
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

const axisPin = "fb5fd5f0f9377c2ccb30d7e027a36373de0d037c"
const mxcPin = "1736b48398c3fe4d1315b2311c0951cc893eb3ae"

type verification struct {
	Verified                 bool                   `json:"verified"`
	Variant                  string                 `json:"variant"`
	Payload                  string                 `json:"payload"`
	Axis                     string                 `json:"axis_commit"`
	MXC                      string                 `json:"mxc_commit"`
	Archive                  string                 `json:"archive_sha256"`
	ContributorOverlay       overlayInfo            `json:"contributor_overlay"`
	ContributorRelayOverlays map[string]overlayInfo `json:"contributor_relay_overlays"`
	Binaries                 []struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
		Size   int64  `json:"size_bytes"`
	} `json:"binaries"`
}

type overlayInfo struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Kind   string `json:"kind"`
}

type transcript struct {
	mu       sync.Mutex
	data     []byte
	overflow bool
}

func (t *transcript) add(data []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.data)+len(data) > 128*1024 {
		t.overflow = true
		return // Keep draining the pipe without retaining unbounded output.
	}
	t.data = append(t.data, data...)
}

func (t *transcript) text() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.data)
}

func attachConsole(attributes *windows.ProcThreadAttributeListContainer, hpc windows.Handle) error {
	// Unlike pointer-valued attributes, PSEUDOCONSOLE takes the opaque HPCON
	// value itself. Pass it as a native uintptr without pretending it is a Go
	// memory pointer retained by ProcThreadAttributeListContainer.Update.
	// https://learn.microsoft.com/windows/console/creating-a-pseudoconsole-session
	update := windows.NewLazySystemDLL("kernel32.dll").NewProc("UpdateProcThreadAttribute")
	result, _, err := update.Call(uintptr(unsafe.Pointer(attributes.List())), 0,
		windows.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, uintptr(hpc), unsafe.Sizeof(hpc), 0, 0)
	if result == 0 {
		return err
	}
	return nil
}

func fileHash(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func checkedBundle(path, probe, probeHash string) (*verification, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var v verification
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	if !v.Verified || (v.Variant != "inherited-console" && v.Variant != "inherited-console-relay") || v.Axis != axisPin || v.MXC != mxcPin || !filepath.IsAbs(v.Payload) || v.ContributorOverlay.Kind != "windows_inherited_console_experiment" {
		return nil, errors.New("the explicit reviewed inherited-console artifact is required")
	}
	required := map[string]bool{"bin/axis.exe": false, "bin/axisd.exe": false, "bin/wxc-exec.exe": false}
	seen := make(map[string]bool)
	for _, binary := range v.Binaries {
		if filepath.Dir(filepath.FromSlash(binary.Path)) != "bin" {
			return nil, errors.New("invalid binary inventory path")
		}
		if seen[binary.Path] || binary.Size < 1 {
			return nil, errors.New("duplicate or empty binary inventory entry")
		}
		seen[binary.Path] = true
		file := filepath.Join(v.Payload, filepath.FromSlash(binary.Path))
		info, err := os.Stat(file)
		if err != nil || !info.Mode().IsRegular() || info.Size() != binary.Size {
			return nil, fmt.Errorf("binary size or type changed: %s", binary.Path)
		}
		hash, err := fileHash(file)
		if err != nil || hash != binary.SHA256 {
			return nil, fmt.Errorf("binary digest changed: %s", binary.Path)
		}
		if _, ok := required[binary.Path]; ok {
			required[binary.Path] = true
		}
	}
	for path, present := range required {
		if !present {
			return nil, fmt.Errorf("required binary missing from inventory: %s", path)
		}
	}
	hash, err := fileHash(filepath.Join(v.Payload, "AXIS_INHERITED_CONSOLE.patch"))
	if err != nil || hash != v.ContributorOverlay.SHA256 {
		return nil, errors.New("retained reviewed overlay changed")
	}
	if v.Variant == "inherited-console-relay" {
		if len(v.ContributorRelayOverlays) != 2 {
			return nil, errors.New("the paired reviewed relay overlays are required")
		}
		for key, path := range map[string]string{"axis": "AXIS_CONSOLE_CTRL_C_RELAY.patch", "mxc": "MXC_CONSOLE_CTRL_C_RELAY.patch"} {
			overlay, ok := v.ContributorRelayOverlays[key]
			if !ok || overlay.Path != path || overlay.Kind != "windows_console_ctrl_c_relay_experiment" {
				return nil, errors.New("invalid paired relay overlay contract")
			}
			hash, err := fileHash(filepath.Join(v.Payload, path))
			if err != nil || hash != overlay.SHA256 {
				return nil, errors.New("retained reviewed relay overlay changed")
			}
		}
	} else if len(v.ContributorRelayOverlays) != 0 {
		return nil, errors.New("relay overlays require the exact relay variant")
	}
	hash, err = fileHash(probe)
	if err != nil || hash != probeHash || len(probeHash) != 64 {
		return nil, errors.New("the fixed payload digest must be explicitly pinned")
	}
	return &v, nil
}

func waitFor(process windows.Handle, output *transcript, condition func(string) bool, deadline time.Time) error {
	var stoppedAt time.Time
	for time.Now().Before(deadline) {
		if condition(output.text()) {
			return nil
		}
		state, err := windows.WaitForSingleObject(process, 0)
		if err != nil {
			return err
		}
		if state == windows.WAIT_OBJECT_0 {
			// The separate output reader can lag process termination. Give its
			// already-queued console bytes a bounded opportunity to arrive.
			if stoppedAt.IsZero() {
				stoppedAt = time.Now()
			} else if time.Since(stoppedAt) >= 250*time.Millisecond {
				return errors.New("AXIS exited before the expected terminal acknowledgement")
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	return errors.New("terminal acknowledgement deadline exceeded")
}

func claimFreshCaseRoot(root string) error {
	if !filepath.IsAbs(root) {
		return errors.New("absolute task-owned case root required")
	}
	if err := os.Mkdir(root, 0700); err != nil {
		if os.IsExist(err) {
			return errors.New("use a fresh task-owned terminal case root")
		}
		return err
	}
	return nil
}

func writeResultIfOwned(root string, claimed bool, raw []byte) error {
	if !claimed {
		return nil
	}
	file, err := os.OpenFile(filepath.Join(root, "terminal-result.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := file.Write(append(raw, '\n')); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func run(v *verification, probe, root, mode string) (record map[string]any, resultErr error) {
	record = map[string]any{"qualified_customer_runtime": false, "case_root_claimed": false, "variant": v.Variant, "axis_commit": v.Axis, "mxc_commit": v.MXC, "archive_sha256": v.Archive, "overlay_sha256": v.ContributorOverlay.SHA256}
	if len(v.ContributorRelayOverlays) != 0 {
		record["relay_overlays"] = v.ContributorRelayOverlays
	}
	record["mode"] = mode
	if mode != "terminal" && mode != "terminal-basic" && mode != "parent-death" && mode != "timeout" && mode != "close-session" && mode != "outer-control" && mode != "outer-control-interrupt" {
		return record, errors.New("unsupported fixed terminal harness mode")
	}
	if err := claimFreshCaseRoot(root); err != nil {
		return record, err
	}
	record["case_root_claimed"] = true
	workspace, home, tmp := filepath.Join(root, "workspace"), filepath.Join(root, "private-home"), filepath.Join(root, "private-tmp")
	for _, directory := range []string{workspace, home, tmp, filepath.Join(home, "AppData", "Roaming"), filepath.Join(home, "AppData", "Local"), filepath.Join(root, "readonly")} {
		if err := os.MkdirAll(directory, 0700); err != nil {
			return record, err
		}
	}
	probeBytes, err := os.ReadFile(probe)
	if err != nil {
		return record, err
	}
	containedProbe := filepath.Join(workspace, "axis-windows-fixed-probe.exe")
	if err := os.WriteFile(containedProbe, probeBytes, 0700); err != nil {
		return record, err
	}
	timeout := 15
	if mode == "timeout" {
		timeout = 1
	}
	policy := "version: 1\nname: defenseclaw-windows-terminal-probe\nruntime: {containment: process, provider: mxc}\nfilesystem:\n  compatibility: hard_requirement\n  read_write: ['{workspace}', '" + strings.ReplaceAll(tmp, "'", "''") + "']\nprocess:\n  max_processes: 0\n  max_memory_mb: 0\n  cpu_rate_percent: 0\n  timeout_sec: " + fmt.Sprint(timeout) + "\nnetwork: {mode: block}\n"
	policyPath := filepath.Join(root, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(policy), 0600); err != nil {
		return record, err
	}
	probeMode := "terminal"
	if mode == "parent-death" || mode == "timeout" || mode == "close-session" {
		probeMode = "tree"
	}
	command := []string{filepath.Join(v.Payload, "bin", "axis.exe"), "--socket", "127.0.0.1:0", "run", "--policy", policyPath, "--", containedProbe, "-mode", probeMode, "-root", root}
	if mode == "outer-control" || mode == "outer-control-interrupt" {
		// An explicit positive host control qualifies only this fixed harness's
		// ConPTY plumbing. It is never a runtime fallback or containment proof.
		command = []string{containedProbe, "-mode", "console-control", "-root", root}
		record["uncontained_positive_host_control"] = true
	}
	record["command"] = command
	record["cwd"] = workspace
	record["probe_sha256"], _ = fileHash(probe)
	if executable, err := os.Executable(); err == nil {
		record["harness_sha256"], _ = fileHash(executable)
	}
	record["policy_sha256"], _ = fileHash(policyPath)
	system := os.Getenv("SystemRoot")
	if !filepath.IsAbs(system) {
		return record, errors.New("absolute Windows system directory required")
	}
	environment := map[string]string{
		"SYSTEMROOT": system, "WINDIR": system, "COMSPEC": filepath.Join(system, "System32", "cmd.exe"), "PATH": filepath.Join(system, "System32") + ";" + system,
		"HOME": home, "USERPROFILE": home, "APPDATA": filepath.Join(home, "AppData", "Roaming"), "LOCALAPPDATA": filepath.Join(home, "AppData", "Local"), "TEMP": tmp, "TMP": tmp,
		"XDG_CONFIG_HOME": filepath.Join(home, ".config"), "XDG_DATA_HOME": filepath.Join(home, ".local", "share"), "XDG_CACHE_HOME": filepath.Join(home, ".cache"),
	}
	var entries []string
	for key, value := range environment {
		entries = append(entries, key+"="+value)
	}
	sort.Strings(entries)
	envBlock := utf16.Encode([]rune(strings.Join(entries, "\x00") + "\x00\x00"))
	var inputRead, inputWrite, outputRead, outputWrite windows.Handle
	if err := windows.CreatePipe(&inputRead, &inputWrite, nil, 0); err != nil {
		return record, err
	}
	defer func() {
		if inputRead != 0 {
			_ = windows.CloseHandle(inputRead)
		}
	}()
	input := os.NewFile(uintptr(inputWrite), "conpty-input")
	defer input.Close()
	if err := windows.CreatePipe(&outputRead, &outputWrite, nil, 0); err != nil {
		return record, err
	}
	defer func() {
		if outputWrite != 0 {
			_ = windows.CloseHandle(outputWrite)
		}
	}()
	outputFile := os.NewFile(uintptr(outputRead), "conpty-output")
	defer outputFile.Close()
	var hpc windows.Handle
	if err := windows.CreatePseudoConsole(windows.Coord{X: 100, Y: 30}, inputRead, outputWrite, 0, &hpc); err != nil {
		return record, err
	}
	var output transcript
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		buffer := make([]byte, 4096)
		for {
			n, err := outputFile.Read(buffer)
			if n > 0 {
				output.add(buffer[:n])
			}
			if err != nil {
				return
			}
		}
	}()
	defer func() {
		if hpc != 0 {
			windows.ClosePseudoConsole(hpc)
		}
		select {
		case <-readerDone:
		case <-time.After(2 * time.Second):
			_ = outputFile.Close()
			if resultErr == nil {
				resultErr = errors.New("console output reader did not finish")
			}
		}
		output.mu.Lock()
		if output.overflow && resultErr == nil {
			resultErr = errors.New("fixed console output exceeded its bound")
		}
		output.mu.Unlock()
		record["output"] = output.text()
		record["error"] = fmt.Sprint(resultErr)
		record["passed"] = resultErr == nil
	}()
	attributes, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return record, err
	}
	defer attributes.Delete()
	if err := attachConsole(attributes, hpc); err != nil {
		return record, err
	}
	startup := windows.StartupInfoEx{}
	startup.Cb = uint32(unsafe.Sizeof(startup))
	startup.ProcThreadAttributeList = attributes.List()
	// Do not inherit this contributor harness's redirected logging handles.
	// Null standard entries are populated from the attached console.
	// https://learn.microsoft.com/windows/console/getstdhandle
	startup.Flags = windows.STARTF_USESTDHANDLES
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return record, err
	}
	defer windows.CloseHandle(job)
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	// The patched MXC BaseContainer child explicitly breaks away into its
	// own kill-on-close resource Job. Executor processes stay in this Job.
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_BREAKAWAY_OK
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return record, err
	}
	commandLine, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(command))
	if err != nil {
		return record, err
	}
	cwd, err := windows.UTF16PtrFromString(workspace)
	if err != nil {
		return record, err
	}
	var process windows.ProcessInformation
	if err := windows.CreateProcess(nil, commandLine, nil, nil, false, windows.EXTENDED_STARTUPINFO_PRESENT|windows.CREATE_UNICODE_ENVIRONMENT|windows.CREATE_SUSPENDED, &envBlock[0], cwd, &startup.StartupInfo, &process); err != nil {
		return record, err
	}
	defer windows.CloseHandle(process.Process)
	defer windows.CloseHandle(process.Thread)
	defer func() {
		if resultErr != nil {
			_ = windows.TerminateJobObject(job, 2)
			_ = windows.TerminateProcess(process.Process, 2)
		}
		_, _ = windows.WaitForSingleObject(process.Process, 5000)
		var code uint32
		if windows.GetExitCodeProcess(process.Process, &code) == nil {
			record["exit_code"] = code
		}
	}()
	record["axis_pid"] = process.ProcessId
	_ = windows.CloseHandle(inputRead)
	inputRead = 0
	_ = windows.CloseHandle(outputWrite)
	outputWrite = 0
	if err := windows.AssignProcessToJobObject(job, process.Process); err != nil {
		_ = windows.TerminateProcess(process.Process, 2)
		return record, err
	}
	if _, err := windows.ResumeThread(process.Thread); err != nil {
		return record, err
	}
	deadline := time.Now().Add(12 * time.Second)
	if probeMode == "tree" {
		if err := waitFor(process.Process, &output, func(text string) bool {
			return strings.Contains(text, `"ok":true,"probe":"descendant_ready"`) && strings.Contains(text, `"ok":true,"probe":"descendant_token"`)
		}, deadline); err != nil {
			return record, fmt.Errorf("contained descendant readiness: %w", err)
		}
		record["contained_descendant_started"] = true
		switch mode {
		case "parent-death":
			ready, _ := json.MarshalIndent(map[string]any{"axis_pid": process.ProcessId, "output": output.text(), "overlay_sha256": v.ContributorOverlay.SHA256}, "", "  ")
			if err := os.WriteFile(filepath.Join(root, "parent-death-ready.json"), ready, 0600); err != nil {
				return record, err
			}
			time.Sleep(20 * time.Second)
			return record, errors.New("external parent-death controller did not terminate this harness")
		case "close-session":
			windows.ClosePseudoConsole(hpc)
			hpc = 0
		}
		state, err := windows.WaitForSingleObject(process.Process, 5000)
		if err != nil {
			return record, err
		}
		if state != windows.WAIT_OBJECT_0 {
			return record, errors.New("AXIS supervisor did not stop for the fixed lifecycle case")
		}
		var code uint32
		if err := windows.GetExitCodeProcess(process.Process, &code); err != nil {
			return record, err
		}
		if mode == "timeout" {
			if code != 1 {
				return record, errors.New("interactive descendant timeout did not return the expected status")
			}
			if err := waitFor(process.Process, &output, func(text string) bool {
				return strings.Contains(text, "Windows MXC process timed out after 1 seconds")
			}, time.Now().Add(time.Second)); err != nil {
				return record, fmt.Errorf("interactive descendant timeout diagnostic: %w", err)
			}
		}
		record["lifecycle_supervisor_stopped"] = true
		return record, nil
	}
	if err := waitFor(process.Process, &output, func(text string) bool {
		contained := strings.HasPrefix(mode, "outer-control") || strings.Contains(text, `"ok":true,"probe":"terminal_token"`)
		return contained && strings.Contains(text, `"ok":true,"probe":"terminal_private_state"`) && strings.Contains(text, `"probe":"console_handles"`) && strings.Contains(text, `"detail":[true,true,true]`) && strings.Contains(text, `"columns":100`) && strings.Contains(text, `"rows":30`)
	}, deadline); err != nil {
		return record, fmt.Errorf("initial 100x30 console: %w", err)
	}
	record["initial_console_100x30"] = true
	if _, err := input.Write([]byte("hello\r")); err != nil {
		return record, err
	}
	if err := waitFor(process.Process, &output, func(text string) bool { return strings.Contains(text, `"probe":"input_ack"`) }, deadline); err != nil {
		return record, fmt.Errorf("keyboard acknowledgement: %w", err)
	}
	record["input_acknowledged"] = true
	if err := windows.ResizePseudoConsole(hpc, windows.Coord{X: 160, Y: 40}); err != nil {
		return record, err
	}
	if _, err := input.Write([]byte("dimensions\r")); err != nil {
		return record, err
	}
	if err := waitFor(process.Process, &output, func(text string) bool {
		return strings.Contains(text, `"columns":160`) && strings.Contains(text, `"rows":40`)
	}, deadline); err != nil {
		return record, fmt.Errorf("resize to 160x40: %w", err)
	}
	record["resize_160x40"] = true
	if mode == "terminal" || mode == "outer-control-interrupt" {
		before := strings.Count(output.text(), `"probe":"input_ack"`)
		if _, err := input.Write([]byte{3}); err != nil {
			return record, err
		}
		if err := waitFor(process.Process, &output, func(text string) bool { return strings.Contains(text, `"probe":"interrupt"`) }, deadline); err != nil {
			return record, fmt.Errorf("Ctrl-C acknowledgement: %w", err)
		}
		record["ctrl_c_acknowledged"] = true
		if _, err := input.Write([]byte("hello\r")); err != nil {
			return record, err
		}
		if err := waitFor(process.Process, &output, func(text string) bool { return strings.Count(text, `"probe":"input_ack"`) > before }, deadline); err != nil {
			return record, fmt.Errorf("input after Ctrl-C: %w", err)
		}
		record["input_after_ctrl_c"] = true
	}
	if _, err := input.Write([]byte("exit7\r")); err != nil {
		return record, err
	}
	state, err := windows.WaitForSingleObject(process.Process, 5000)
	if err != nil {
		return record, err
	}
	if state != windows.WAIT_OBJECT_0 {
		return record, errors.New("AXIS did not exit after the fixed exit7 command")
	}
	var code uint32
	if err := windows.GetExitCodeProcess(process.Process, &code); err != nil {
		return record, err
	}
	if code != 7 {
		return record, fmt.Errorf("AXIS exit=%d, want 7", code)
	}
	record["exit7_preserved"] = true
	return record, nil
}

func main() {
	verified := flag.String("verification", "", "verified inherited-console bundle JSON")
	probe := flag.String("probe", "", "reviewed fixed probe executable")
	probeHash := flag.String("probe-sha256", "", "reviewed fixed probe SHA256")
	root := flag.String("case-root", "", "fresh absolute task-owned case root")
	mode := flag.String("mode", "terminal", "fixed case: terminal, terminal-basic, parent-death, timeout, close-session, outer-control, outer-control-interrupt")
	flag.Parse()
	v, err := checkedBundle(*verified, *probe, *probeHash)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	record, err := run(v, *probe, *root, *mode)
	raw, marshalErr := json.MarshalIndent(record, "", "  ")
	if marshalErr != nil {
		fmt.Fprintln(os.Stderr, marshalErr)
		os.Exit(1)
	}
	if writeErr := writeResultIfOwned(*root, record["case_root_claimed"] == true, raw); writeErr != nil {
		record["passed"] = false
		record["error"] = fmt.Sprintf("terminal result receipt: %v", writeErr)
		raw, _ = json.MarshalIndent(record, "", "  ")
		fmt.Println(string(raw))
		os.Exit(1)
	}
	fmt.Println(string(raw))
	if err != nil {
		os.Exit(1)
	}
}
