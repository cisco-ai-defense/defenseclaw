// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

// Contributor-only fixed environment control. No default path executes a child.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/processutil"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"golang.org/x/sys/windows"
)

const (
	scope       = "fixed_windows_246_outside_psec_environment_control"
	parentName  = "bin/defenseclaw-axis-windows-psec-probe.exe"
	loaderName  = "bin/defenseclaw-axis-windows-psec-loader-child.exe"
	childName   = "bin/defenseclaw-axis-windows-psec-boundary-child.exe"
	sourceName  = "source/src/boundary_child.rs"
	sentinel    = "fixed-public-synthetic-canary\n"
	fixtureName = "dc-axis-windows-psec-environment-control"
	outputLimit = 64 * 1024
	deadline    = 30 * time.Second
)

type component struct {
	Path string `json:"path"`
	SHA  string `json:"sha256"`
	Size int64  `json:"size"`
}

type verificationReceipt struct {
	Verified   bool        `json:"verified"`
	Executed   *bool       `json:"execution_performed"`
	Certified  *bool       `json:"production_certification"`
	Scope      string      `json:"scope"`
	Variant    string      `json:"variant"`
	Axis       string      `json:"axis_commit"`
	MXC        string      `json:"mxc_commit"`
	Commit     string      `json:"build_commit"`
	Run        int64       `json:"build_run"`
	ArtifactID int64       `json:"artifact_id"`
	Archive    string      `json:"archive_sha256"`
	Provenance string      `json:"provenance_sha256"`
	Lock       string      `json:"combined_lock_sha256"`
	Artifact   string      `json:"artifact"`
	Binary     string      `json:"binary"`
	BinarySHA  string      `json:"binary_sha256"`
	BinarySize int64       `json:"binary_size"`
	Binaries   []component `json:"binaries"`
}

type reviewedPins struct {
	Receipt, Commit, Archive, Provenance, Source string
	Run, ArtifactID                              int64
	Images                                       []component
}

var reviewed246 = reviewedPins{
	Receipt: "b257b27b49f1cf7ee4fa510e17e198760f77a31a409d9188d8458f054a720612",
	Commit:  "246210c3b484ea1de0785756dd4410beda25adfb", Run: 39129614000, ArtifactID: 12137991365,
	Archive:    "715c01dac75dd24300f3154622eb3837afa0de36de37462873fc477b271c6b49",
	Provenance: "099bcb4a93fb74974afa727911570f604300c7f44d56d5519bb8457723e53581",
	Source:     "3809389bab54663d6c1d1975602af80b03571239bad2a425523153c8e5dd375d",
	Images: []component{
		{parentName, "f0ad20723af461d958962ecfc65ecb6b6138883d8b5e89a960726a505a62d949", 2474496},
		{loaderName, "6ffd0f5a356292768ebde084a9534d2af341ce3aa7efc78f23ce8bfbdeb6cc3e", 122880},
		{childName, "02ee46ec8bd3d5a4694c6ea8d7a03cb4b227d37945d9725e1ba2ad8e41620cba", 211456},
	},
}

type heldFiles []*os.File

func (h heldFiles) close() error {
	var err error
	for _, f := range h {
		err = errors.Join(err, f.Close())
	}
	return err
}

func ordinaryPath(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) < 3 || path[1:3] != `:\` || strings.Contains(path[2:], ":") || strings.ContainsRune(path, 0) {
		return errors.New("ordinary absolute local disk path required")
	}
	return nil
}

// This fixed contributor wrapper refuses reparse ancestors and holds all path
// components against rename with list access and no delete sharing. Directory
// contents and metadata remain mutable. It is not a production registry.
func pinParents(path string) (heldFiles, error) {
	if err := ordinaryPath(path); err != nil {
		return nil, err
	}
	var names []string
	for p := filepath.Dir(path); ; p = filepath.Dir(p) {
		names = append(names, p)
		if filepath.Dir(p) == p {
			break
		}
	}
	slices.Reverse(names)
	var held heldFiles
	for _, name := range names {
		ptr, err := windows.UTF16PtrFromString(name)
		if err != nil {
			_ = held.close()
			return nil, err
		}
		h, err := windows.CreateFile(ptr, windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING,
			windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if err != nil {
			_ = held.close()
			return nil, errors.New("cannot hold non-reparse ancestor")
		}
		f := os.NewFile(uintptr(h), name)
		held = append(held, f)
		var info windows.ByHandleFileInformation
		if err := windows.GetFileInformationByHandle(h, &info); err != nil ||
			info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
			_ = held.close()
			return nil, errors.New("ancestor type/reparse refusal")
		}
	}
	return held, nil
}

func pinFile(path string, size int64, expected string) (heldFiles, []byte, error) {
	parents, err := pinParents(path)
	if err != nil {
		return nil, nil, err
	}
	failed := true
	defer func() {
		if failed {
			_ = parents.close()
		}
	}()
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, nil, err
	}
	h, err := windows.CreateFile(ptr, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, nil, errors.New("cannot hold exact reviewed file")
	}
	f := os.NewFile(uintptr(h), path)
	parents = append(parents, f)
	info, err := f.Stat()
	var native windows.ByHandleFileInformation
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > size ||
		windows.GetFileInformationByHandle(h, &native) != nil || native.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || native.NumberOfLinks != 1 {
		return nil, nil, errors.New("reviewed file type/size/link refusal")
	}
	data, err := io.ReadAll(io.LimitReader(f, size+1))
	if err != nil || int64(len(data)) != info.Size() {
		return nil, nil, errors.New("reviewed file read refusal")
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != expected {
		return nil, nil, errors.New("reviewed file digest differs")
	}
	failed = false
	return parents, data, nil
}

func checkReceipt(path string, pins reviewedPins) (_ verificationReceipt, _ heldFiles, resultErr error) {
	var value verificationReceipt
	if len(pins.Images) != 3 {
		return value, nil, errors.New("three trusted image pins required")
	}
	held, data, err := pinFile(path, outputLimit, pins.Receipt)
	if err != nil {
		return value, nil, err
	}
	defer func() {
		if resultErr != nil {
			_ = held.close()
		}
	}()
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return value, nil, errors.New("invalid fixed receipt")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return value, nil, errors.New("receipt trailing data")
	}
	if !value.Verified || value.Executed == nil || *value.Executed || value.Certified == nil || *value.Certified ||
		value.Scope != "fixed_windows_native_psec_boundary_literal_argv" || value.Variant != "standalone_std_boundary_literal_argv" ||
		value.Axis != "fb5fd5f0f9377c2ccb30d7e027a36373de0d037c" || value.MXC != "fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2" ||
		value.Lock != "3b29ecb06dd2a81266c84712f8d6e088605290f386e87498bb7a7472a005af69" ||
		value.Commit != pins.Commit || value.Run != pins.Run || value.ArtifactID != pins.ArtifactID ||
		value.Archive != pins.Archive || value.Provenance != pins.Provenance ||
		value.Binary != parentName || value.BinarySHA != pins.Images[0].SHA || value.BinarySize != pins.Images[0].Size ||
		!slices.Equal(value.Binaries, pins.Images) {
		return value, nil, errors.New("only exact reviewed246 verification receipt is admitted")
	}
	for _, image := range pins.Images {
		files, data, err := pinFile(filepath.Join(value.Artifact, filepath.FromSlash(image.Path)), image.Size, image.SHA)
		if err != nil {
			return value, nil, err
		}
		held = append(held, files...)
		if int64(len(data)) != image.Size {
			return value, nil, errors.New("reviewed image size differs")
		}
	}
	files, _, err := pinFile(filepath.Join(value.Artifact, filepath.FromSlash(sourceName)), 1<<20, pins.Source)
	if err != nil {
		return value, nil, err
	}
	held = append(held, files...)
	return value, held, nil
}

type fixture struct {
	evidence, root *os.Root
	canonical      string
	parents        heldFiles
}

func (f *fixture) close() error {
	return errors.Join(f.root.Close(), f.evidence.Close(), f.parents.close())
}

func canonicalDirectory(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	name := make([]uint16, 32768)
	n, err := windows.GetFinalPathNameByHandle(windows.Handle(f.Fd()), &name[0], uint32(len(name)), 0)
	if err != nil || n >= uint32(len(name)) {
		return "", errors.New("canonical local directory unavailable")
	}
	value := windows.UTF16ToString(name[:n])
	if !strings.HasPrefix(value, `\\?\`) || ordinaryPath(strings.TrimPrefix(value, `\\?\`)) != nil {
		return "", errors.New("canonical verbatim disk spelling required")
	}
	return value, nil
}

func newFixture(evidence string) (_ *fixture, resultErr error) {
	if !strings.HasPrefix(filepath.Base(evidence), "environment-control-") {
		return nil, errors.New("fresh environment-control-* evidence directory required")
	}
	parents, err := pinParents(evidence)
	if err != nil {
		return nil, err
	}
	if err := safefile.ValidatePrivateHandle(windows.Handle(parents[len(parents)-1].Fd())); err != nil {
		_ = parents.close()
		return nil, errors.New("existing evidence parent must already be private")
	}
	keep := false
	defer func() {
		if !keep {
			_ = parents.close()
		}
	}()
	if created, err := safefile.CreatePrivateDirectory(evidence); err != nil || !created {
		return nil, errors.New("new private evidence creation refused")
	}
	e, err := os.OpenRoot(evidence)
	if err != nil {
		return nil, err
	}
	defer func() {
		if !keep {
			_ = e.Close()
		}
	}()
	if err := e.Mkdir(fixtureName, 0700); err != nil {
		return nil, err
	}
	r, err := e.OpenRoot(fixtureName)
	if err != nil {
		return nil, err
	}
	defer func() {
		if !keep {
			_ = r.Close()
		}
	}()
	held, err := r.Open(".")
	if err != nil {
		return nil, err
	}
	aclErr := safefile.ValidatePrivateHandle(windows.Handle(held.Fd()))
	_ = held.Close()
	if aclErr != nil {
		return nil, errors.New("new fixture private DACL refused")
	}
	for _, name := range []string{"home", "tmp", "workspace", "outside-parent", "home/AppData", "home/AppData/Roaming", "home/AppData/Local"} {
		if err := r.Mkdir(name, 0700); err != nil {
			return nil, err
		}
	}
	for _, name := range []string{"workspace/fixture-seal", "outside-parent/outside.txt", "readonly.txt"} {
		if err := r.WriteFile(name, []byte(sentinel), 0600); err != nil {
			return nil, err
		}
	}
	canonical, err := canonicalDirectory(filepath.Join(evidence, fixtureName))
	if err != nil {
		return nil, err
	}
	keep = true
	return &fixture{e, r, canonical, parents}, nil
}

func fixedEnvironment(root, system string) []string {
	values := map[string]string{
		"SYSTEMROOT": system, "WINDIR": system,
		"HOME": filepath.Join(root, "home"), "USERPROFILE": filepath.Join(root, "home"),
		"APPDATA": filepath.Join(root, "home", "AppData", "Roaming"), "LOCALAPPDATA": filepath.Join(root, "home", "AppData", "Local"),
		"TEMP": filepath.Join(root, "tmp"), "TMP": filepath.Join(root, "tmp"),
	}
	var result []string
	for name, value := range values {
		result = append(result, name+"="+value)
	}
	sort.Strings(result)
	return result
}

type boundedOutput struct {
	data     []byte
	overflow bool
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	n := min(len(p), outputLimit-len(b.data))
	b.data = append(b.data, p[:n]...)
	b.overflow = b.overflow || n != len(p)
	return len(p), nil // drain without retaining excess bytes
}

func cleanExitOne(err error) bool {
	// A joined Job/reader/cleanup error must never become an expected exit.
	exit, exact := err.(*exec.ExitError)
	return exact && exit.ExitCode() == 1
}

func expectedTranscript(stdout, stderr []byte) bool {
	return len(stdout) == 0 && strings.ReplaceAll(string(stderr), "\r\n", "\n") ==
		"FIXED_CANONICALIZE result=ok\nfixed child failed: outside read was not denied\n"
}

func inspectFixture(root *os.Root) error {
	for name, want := range map[string]string{
		"outside-parent/outside.txt": sentinel, "readonly.txt": sentinel, "workspace/fixture-seal": sentinel,
		"workspace/allowed-write": "fixed write", "outside-parent/allowed-sibling": "fixed parent-grant write",
	} {
		f, err := root.Open(name)
		if err != nil {
			return errors.New("fixed canary/positive write missing")
		}
		data, readErr := io.ReadAll(io.LimitReader(f, 1024))
		err = errors.Join(readErr, f.Close())
		if err != nil || string(data) != want {
			return errors.New("fixed canary/positive write differs")
		}
	}
	return nil
}

func runFixed(value verificationReceipt, f *fixture, record map[string]any) error {
	system, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		return errors.New("system directory lookup failed")
	}
	system, err = canonicalDirectory(system)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	child := filepath.Join(value.Artifact, filepath.FromSlash(childName))
	cmd := processutil.CommandContext(ctx, child, "--fixed-child", "boundary", "1", "1", "1", "1")
	cmd.Dir = filepath.Join(f.canonical, "workspace")
	cmd.Env = fixedEnvironment(f.canonical, system)
	var stdout, stderr boundedOutput
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	record["execution_attempted"] = true
	err = processutil.RunTree(cmd)
	record["execution_performed"] = cmd.Process != nil
	record["child_process_created"] = cmd.Process != nil
	record["stdout"], record["stderr"] = string(stdout.data), string(stderr.data)
	record["output_truncated"] = stdout.overflow || stderr.overflow
	record["deadline_exceeded"] = ctx.Err() != nil
	record["expected_clean_exit_one"] = cleanExitOne(err)
	if cmd.ProcessState != nil {
		record["child_exit_code"] = cmd.ProcessState.ExitCode()
	}
	if ctx.Err() != nil || stdout.overflow || stderr.overflow || !cleanExitOne(err) {
		return errors.New("fixed child exit/deadline/output/owned-tree cleanup differed")
	}
	if !expectedTranscript(stdout.data, stderr.data) {
		return errors.New("fixed child did not reach the exact outside-read control failure")
	}
	if err := inspectFixture(f.root); err != nil {
		return err
	}
	record["six_exact_environment_assertions_passed_by_source_order"] = true
	record["credential_and_parent_canary_absence_passed_by_source_order"] = true
	record["outside_read_succeeded_and_stopped_before_negative_writes_or_sockets"] = true
	record["original_sentinels_preserved"] = true
	return nil
}

type options struct{ receipt, evidence string }

func parseOptions(args []string) (options, error) {
	var opts options
	flags := flag.NewFlagSet("environment-control", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	explicit := flags.Bool("run-fixed", false, "explicit reviewed246 uncontained control")
	flags.StringVar(&opts.receipt, "receipt", "", "exact independently reviewed246 receipt")
	flags.StringVar(&opts.evidence, "evidence", "", "new private evidence directory")
	if err := flags.Parse(args); err != nil {
		return opts, errors.New("invalid fixed control options")
	}
	if !*explicit || flags.NArg() != 0 || opts.receipt == "" || opts.evidence == "" {
		return opts, errors.New("explicit --run-fixed --receipt --evidence required; no default execution")
	}
	return opts, nil
}

func execute(args []string) (record map[string]any, resultErr error) {
	record = map[string]any{"scope": scope, "passed": false, "production_certification": false, "execution_performed": false,
		"build_commit": reviewed246.Commit, "build_run": reviewed246.Run, "artifact_id": reviewed246.ArtifactID,
		"receipt_sha256": reviewed246.Receipt, "child_sha256": reviewed246.Images[2].SHA,
		"source_sha256": reviewed246.Source, "custody": "processutil.RunTree non-breakaway kill-on-close Job before resume"}
	opts, err := parseOptions(args)
	if err != nil {
		return record, err
	}
	value, held, err := checkReceipt(opts.receipt, reviewed246)
	if err != nil {
		return record, err
	}
	defer func() { resultErr = errors.Join(resultErr, held.close()) }()
	f, err := newFixture(opts.evidence)
	if err != nil {
		return record, err
	}
	record["fixture_retained"] = true
	record["fixture_relative"] = fixtureName
	defer func() {
		// Keep evidence rooted until the report is written. Close image/source
		// pins only after RunTree has returned and before deciding success.
		resultErr = errors.Join(resultErr, f.root.Close(), f.parents.close(), held.close())
		held = nil
		record["passed"] = resultErr == nil
		record["error"] = fmt.Sprint(resultErr)
		data, err := json.MarshalIndent(record, "", "  ")
		if err == nil {
			err = f.evidence.WriteFile("CONTROL-RESULT.json", append(data, '\n'), 0600)
		}
		err = errors.Join(err, f.evidence.Close())
		if err != nil {
			resultErr = errors.Join(resultErr, errors.New("private result persistence/close failed"))
			record["passed"] = false
		}
	}()
	return record, runFixed(value, f, record)
}

func main() {
	record, err := execute(os.Args[1:])
	if err != nil {
		record["error"] = err.Error()
		record["passed"] = false
	}
	if json.NewEncoder(os.Stdout).Encode(record) != nil || err != nil {
		os.Exit(1)
	}
}
