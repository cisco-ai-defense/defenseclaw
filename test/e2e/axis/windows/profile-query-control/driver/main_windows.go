// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build ignore

// Fixed contributor supervisor; no arbitrary executable, argument or hash input.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/processutil"
	"golang.org/x/sys/windows"
)

const helperSHA = "0e5123f5f20d992b36f07ce8a6670675996e1d333e37bf07ea5668e9cae8d24e"
const helperSize int64 = 2158592
const captureLimit = 8 * 1024

type capture struct {
	mu       sync.Mutex
	bytes    []byte
	overflow bool
}

func (c *capture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	remaining := captureLimit - len(c.bytes)
	if len(p) > remaining {
		c.overflow = true
	}
	c.bytes = append(c.bytes, p[:min(remaining, len(p))]...)
	return len(p), nil // Drain without blocking the fixed helper on a full pipe.
}

func (c *capture) snapshot() (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return string(c.bytes), c.overflow
}

type pins []*os.File

func (p pins) close() error {
	var result error
	for index := len(p) - 1; index >= 0; index-- {
		result = errors.Join(result, p[index].Close())
	}
	return result
}

func pinFixedImage(path string, expected string, size int64) (_ pins, err error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) < 3 || path[1:3] != `:\` ||
		strings.Contains(path[2:], ":") || strings.ContainsRune(path, 0) {
		return nil, errors.New("ordinary fixed image path required")
	}
	var names []string
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		names = append(names, parent)
		if filepath.Dir(parent) == parent {
			break
		}
	}
	slices.Reverse(names)
	names = append(names, path)
	var held pins
	defer func() {
		if err != nil {
			err = errors.Join(err, held.close())
		}
	}()
	for index, name := range names {
		directory := index != len(names)-1
		access, share := uint32(windows.GENERIC_READ), uint32(windows.FILE_SHARE_READ)
		if directory {
			access = windows.FILE_LIST_DIRECTORY | windows.FILE_READ_ATTRIBUTES
			share |= windows.FILE_SHARE_WRITE
		}
		encoded, encodingErr := windows.UTF16PtrFromString(name)
		if encodingErr != nil {
			return nil, encodingErr
		}
		handle, openErr := windows.CreateFile(encoded, access, share, nil, windows.OPEN_EXISTING,
			windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if openErr != nil {
			return nil, errors.New("fixed image path custody refused")
		}
		file := os.NewFile(uintptr(handle), "held-fixed-query-image")
		held = append(held, file)
		var info windows.ByHandleFileInformation
		if windows.GetFileInformationByHandle(handle, &info) != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
			(info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory || (!directory && info.NumberOfLinks != 1) {
			return nil, errors.New("fixed image type/reparse/link refusal")
		}
	}
	image := held[len(held)-1]
	info, statErr := image.Stat()
	if statErr != nil || !info.Mode().IsRegular() || info.Size() != size || size <= 0 || size > 8*1024*1024 {
		return nil, errors.New("fixed image size refused")
	}
	hash := sha256.New()
	n, hashErr := io.Copy(hash, io.LimitReader(image, size+1))
	if hashErr != nil || n != size || hex.EncodeToString(hash.Sum(nil)) != expected {
		return nil, errors.New("fixed query image changed")
	}
	return held, nil
}

type classSummary struct {
	WellFormed     bool  `json:"well_formed_local_disk_paths"`
	KnownExtended  bool  `json:"known_base_extended_prefix"`
	NativeExtended bool  `json:"native_folder_extended_prefix"`
	KnownExact     *bool `json:"known_packages_prefix_exact"`
	KnownFold      *bool `json:"known_packages_prefix_ascii_fold"`
	PrivateExact   *bool `json:"private_packages_prefix_exact"`
	PrivateFold    *bool `json:"private_packages_prefix_ascii_fold"`
	TailShape      *bool `json:"native_packages_profile_ac_tail_shape"`
	EqualBase      *bool `json:"known_base_equals_private_exact"`
	EqualBaseFold  *bool `json:"known_base_equals_private_ascii_fold"`
}

type childReport struct {
	Scope          string        `json:"scope"`
	Stage          string        `json:"stage"`
	Completed      bool          `json:"query_completed"`
	Synthetic      bool          `json:"fixed_synthetic_sid"`
	Environment    bool          `json:"fixed_eight_environment_matched"`
	ThreadIdentity string        `json:"thread_identity"`
	KnownHRESULT   *string       `json:"known_folder_hresult"`
	NativeHRESULT  *string       `json:"synthetic_native_folder_hresult"`
	Classes        *classSummary `json:"classes"`
	ProfileCreate  bool          `json:"profile_creation_calls"`
	WriteCalls     bool          `json:"explicit_filesystem_write_calls"`
	Production     bool          `json:"production_qualification"`
}

func completeReport(raw string) bool {
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	var r childReport
	if decoder.Decode(&r) != nil || decoder.Decode(new(any)) != io.EOF {
		return false
	}
	return r.Scope == "fixed_windows_read_only_synthetic_profile_query" && r.Stage == "query_completed" &&
		r.Completed && r.Synthetic && r.Environment && r.ThreadIdentity == "absent" &&
		r.KnownHRESULT != nil && *r.KnownHRESULT == "0x00000000" &&
		r.NativeHRESULT != nil && *r.NativeHRESULT == "0x00000000" &&
		r.Classes != nil && r.Classes.WellFormed && r.Classes.KnownExact != nil && r.Classes.KnownFold != nil &&
		r.Classes.PrivateExact != nil && r.Classes.PrivateFold != nil && r.Classes.TailShape != nil &&
		r.Classes.EqualBase != nil && r.Classes.EqualBaseFold != nil &&
		!r.ProfileCreate && !r.WriteCalls && !r.Production
}

type report struct {
	Scope           string `json:"scope"`
	Stage           string `json:"stage"`
	Passed          bool   `json:"passed"`
	HelperSHA       string `json:"helper_sha256"`
	ExitCode        *int   `json:"helper_exit_code"`
	RunError        bool   `json:"run_error"`
	LaunchAttempted bool   `json:"launch_attempted"`
	Deadline        bool   `json:"context_deadline"`
	PinClose        bool   `json:"pin_close_error"`
	Overflow        bool   `json:"output_overflow"`
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	Custody         string `json:"process_custody"`
	FullTree        bool   `json:"full_tree_qualification"`
	Production      bool   `json:"production_qualification"`
}

func runFixed() (r report) {
	r = report{Scope: "fixed_read_only_profile_query_supervisor", Stage: "fixture_refused", HelperSHA: helperSHA,
		Custody: "existing processutil.RunTree suspended Job assignment; cleanup errors fail"}
	self, err := os.Executable()
	if err != nil || filepath.Base(self) != "profile-query-supervisor.exe" {
		return r
	}
	root := filepath.Dir(self)
	if !strings.HasPrefix(filepath.Base(root), "profile-query-control-") ||
		filepath.Base(filepath.Dir(root)) != "environment-control-private-02" {
		return r
	}
	image := filepath.Join(root, "profile-query-control.exe")
	held, err := pinFixedImage(image, helperSHA, helperSize)
	if err != nil {
		r.Stage = "fixed_image_refused"
		return r
	}
	defer func() {
		if held.close() != nil {
			r.PinClose, r.Passed = true, false
		}
	}()
	// Only fresh owned fixture directories are created. Never repair ACLs or
	// remove/reuse any failed fixture; every outcome retains this synthetic case.
	for _, relative := range []string{"home", "tmp", "workspace", `home\AppData`, `home\AppData\Roaming`, `home\AppData\Local`} {
		if os.Mkdir(filepath.Join(root, relative), 0700) != nil {
			return r
		}
	}
	system, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		r.Stage = "system_directory_refused"
		return r
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := processutil.CommandContext(ctx, image, "--query-fixed")
	cmd.Dir = filepath.Join(root, "workspace")
	cmd.Env = []string{"SYSTEMROOT=" + system, "WINDIR=" + system,
		"HOME=" + filepath.Join(root, "home"), "USERPROFILE=" + filepath.Join(root, "home"),
		"APPDATA=" + filepath.Join(root, "home", "AppData", "Roaming"),
		"LOCALAPPDATA=" + filepath.Join(root, "home", "AppData", "Local"),
		"TEMP=" + filepath.Join(root, "tmp"), "TMP=" + filepath.Join(root, "tmp")}
	var stdout, stderr capture
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	r.LaunchAttempted = true
	err = processutil.RunTree(cmd) // No managed breakaway or alternate launcher.
	r.RunError, r.Deadline = err != nil, errors.Is(ctx.Err(), context.DeadlineExceeded)
	if cmd.ProcessState != nil {
		code := cmd.ProcessState.ExitCode()
		r.ExitCode = &code
	}
	var outOverflow, errOverflow bool
	r.Stdout, outOverflow = stdout.snapshot()
	r.Stderr, errOverflow = stderr.snapshot()
	r.Overflow = outOverflow || errOverflow
	r.Stage = "owned_query_returned"
	r.Passed = err == nil && !r.Deadline && !r.Overflow && r.Stderr == "" && completeReport(r.Stdout)
	return r
}

func main() {
	if !slices.Equal(os.Args[1:], []string{"--run-fixed"}) {
		fmt.Fprintln(os.Stderr, "only the reviewed fixed supervisor selector is supported")
		os.Exit(2)
	}
	r := runFixed()
	if json.NewEncoder(os.Stdout).Encode(r) != nil || !r.Passed {
		os.Exit(1)
	}
}
