//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type fakePrereqFileInfo struct {
	mode fs.FileMode
}

func (f fakePrereqFileInfo) Name() string       { return "f" }
func (f fakePrereqFileInfo) Size() int64        { return 1 }
func (f fakePrereqFileInfo) Mode() fs.FileMode  { return f.mode }
func (f fakePrereqFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakePrereqFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakePrereqFileInfo) Sys() any           { return nil }

// healthyHostProbes describes a host with every prerequisite met.
func healthyHostProbes() HostPrereqProbes {
	executable := fakePrereqFileInfo{mode: 0o755}
	return HostPrereqProbes{
		Lstat:       func(string) (fs.FileInfo, error) { return executable, nil },
		Stat:        func(path string) (fs.FileInfo, error) { return executable, nil },
		Flags:       func(string) (uint32, bool) { return 0, true },
		Securelevel: func() (int, bool) { return 0, true },
		ReadDir:     func(string) ([]fs.DirEntry, error) { return nil, nil },
		RunVersion:  func(context.Context, string) ([]byte, error) { return []byte("defenseclaw 1.0.6\n"), nil },
		PortHolder: func(context.Context, int) (int, string, bool, error) {
			return 42, "defenseclaw-gateway", true, nil
		},
		DialLoopback:            func(int) error { return nil },
		RunCurl:                 func(context.Context) error { return nil },
		CommandLineToolsPresent: func(context.Context) bool { return true },
	}
}

func prereqChecks(findings []PrereqFinding) map[string]PrereqFinding {
	out := map[string]PrereqFinding{}
	for _, finding := range findings {
		out[finding.Check] = finding
	}
	return out
}

func TestCheckHostPrerequisitesHealthyHost(t *testing.T) {
	in := HostPrereqInput{InstallRoot: "/opt/x", Ports: []int{18970, 4000}, ExecProbe: true}
	if findings := CheckHostPrerequisites(in, healthyHostProbes()); len(findings) != 0 {
		t.Fatalf("healthy host reported %+v", findings)
	}
}

func TestCheckHostPrerequisitesBinaryExecAllowed(t *testing.T) {
	gateway := filepath.Join("/opt/x", "bin", "defenseclaw-gateway")
	cases := map[string]func(*HostPrereqProbes){
		"quarantined binary": func(p *HostPrereqProbes) {
			lstat := p.Lstat
			p.Lstat = func(path string) (fs.FileInfo, error) {
				if path == gateway {
					return nil, fs.ErrNotExist
				}
				return lstat(path)
			}
		},
		"spawn refused": func(p *HostPrereqProbes) {
			p.RunVersion = func(context.Context, string) ([]byte, error) {
				return nil, &fs.PathError{Op: "fork/exec", Path: gateway, Err: syscall.EPERM}
			}
		},
		"killed": func(p *HostPrereqProbes) {
			p.RunVersion = func(ctx context.Context, _ string) ([]byte, error) {
				cmd := exec.CommandContext(ctx, "/bin/sh", "-c", "kill -9 $$")
				return cmd.CombinedOutput()
			}
		},
		"silent failure": func(p *HostPrereqProbes) {
			p.RunVersion = func(ctx context.Context, _ string) ([]byte, error) {
				return exec.CommandContext(ctx, "/bin/sh", "-c", "exit 3").CombinedOutput()
			}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			probes := healthyHostProbes()
			mutate(&probes)
			findings := prereqChecks(CheckHostPrerequisites(HostPrereqInput{InstallRoot: "/opt/x", ExecProbe: true}, probes))
			finding, ok := findings[PrereqBinaryExecAllowed]
			if !ok || finding.Path != gateway || !strings.Contains(finding.Remedy, "DE8Y96K9QP") {
				t.Fatalf("findings = %+v, want binary_exec_allowed for %s", findings, gateway)
			}
		})
	}
	// The guardian only checks presence; it never executes the binary.
	probes := healthyHostProbes()
	probes.RunVersion = func(context.Context, string) ([]byte, error) {
		t.Fatal("the guardian probe executed the gateway")
		return nil, nil
	}
	if findings := CheckHostPrerequisites(HostPrereqInput{InstallRoot: "/opt/x"}, probes); len(findings) != 0 {
		t.Fatalf("findings = %+v", findings)
	}
}

func TestCheckHostPrerequisitesSystemImmutableFlag(t *testing.T) {
	probes := healthyHostProbes()
	probes.Flags = func(path string) (uint32, bool) {
		if path == "/opt/x" {
			return darwinSystemBlockingFlagsMask, true
		}
		return 0, true
	}
	if findings := CheckHostPrerequisites(HostPrereqInput{InstallRoot: "/opt/x"}, probes); len(findings) != 0 {
		t.Fatalf("schg at securelevel 0 is a repair, not a prerequisite: %+v", findings)
	}
	probes.Securelevel = func() (int, bool) { return 1, true }
	finding, ok := prereqChecks(CheckHostPrerequisites(HostPrereqInput{InstallRoot: "/opt/x"}, probes))[PrereqSystemImmutableFlag]
	if !ok || finding.Path != "/opt/x" || !strings.Contains(finding.Remedy, "securelevel is 1") {
		t.Fatalf("finding = %+v, want system_immutable_flag on /opt/x", finding)
	}
}

func TestCheckHostPrerequisitesGatewayLoopbackPort(t *testing.T) {
	probes := healthyHostProbes()
	probes.PortHolder = func(_ context.Context, port int) (int, string, bool, error) {
		if port == 18970 {
			return 777, "nc", true, nil
		}
		return 0, "", false, nil
	}
	finding, ok := prereqChecks(CheckHostPrerequisites(HostPrereqInput{Ports: []int{18970, 4000}}, probes))[PrereqGatewayLoopbackPort]
	if !ok || !strings.Contains(finding.Detail, "pid 777 (nc)") {
		t.Fatalf("finding = %+v, want a foreign holder", finding)
	}

	probes = healthyHostProbes()
	probes.DialLoopback = func(int) error { return errors.New("filtered") }
	finding, ok = prereqChecks(CheckHostPrerequisites(HostPrereqInput{Ports: []int{18970}}, probes))[PrereqGatewayLoopbackPort]
	if !ok || finding.Detail != "unreachable over loopback" {
		t.Fatalf("finding = %+v, want unreachable over loopback", finding)
	}

	probes = healthyHostProbes()
	probes.PortHolder = func(context.Context, int) (int, string, bool, error) { return 0, "", false, nil }
	if findings := CheckHostPrerequisites(HostPrereqInput{Ports: []int{18970}}, probes); len(findings) != 0 {
		t.Fatalf("a free port is not a prerequisite: %+v", findings)
	}
}

func TestParseLsofListener(t *testing.T) {
	pid, command := parseLsofListener([]byte("p123\ncdefenseclaw-gateway\nf7\np456\ncother\n"))
	if pid != 123 || command != "defenseclaw-gateway" {
		t.Fatalf("pid=%d command=%q", pid, command)
	}
}

func TestCheckHostPrerequisitesHookTransportTools(t *testing.T) {
	probes := healthyHostProbes()
	probes.RunCurl = func(context.Context) error { return errors.New("signal: killed") }
	if _, ok := prereqChecks(CheckHostPrerequisites(HostPrereqInput{}, probes))[PrereqHookTransportTools]; !ok {
		t.Fatal("a curl the EDR kills was not reported")
	}

	// No jq anywhere; only the /usr/bin/python3 stub without the CLT.
	probes = healthyHostProbes()
	probes.Stat = func(path string) (fs.FileInfo, error) {
		if path == "/usr/bin/python3" {
			return fakePrereqFileInfo{mode: 0o755}, nil
		}
		return nil, fs.ErrNotExist
	}
	probes.CommandLineToolsPresent = func(context.Context) bool { return false }
	finding, ok := prereqChecks(CheckHostPrerequisites(HostPrereqInput{}, probes))[PrereqHookTransportTools]
	if !ok || finding.Path != "jq" {
		t.Fatalf("finding = %+v, want the missing parser", finding)
	}
	probes.CommandLineToolsPresent = func(context.Context) bool { return true }
	if _, ok := prereqChecks(CheckHostPrerequisites(HostPrereqInput{}, probes))[PrereqHookTransportTools]; ok {
		t.Fatal("python3 with the Command Line Tools was not accepted")
	}
}

func TestTCCProtectedRoot(t *testing.T) {
	cases := map[string]string{
		"/Users/u/Documents/repo/x":            "/Users/u/Documents",
		"/Users/u/Library/Containers/app/Data": "/Users/u/Library/Containers",
		"/Volumes/USB/stuff":                   "/Volumes/USB",
		"/Users/u/.claude/settings.json":       "",
		"/Users/u/Library/Caches/x":            "",
		"/opt/cisco":                           "",
	}
	for path, want := range cases {
		if got := TCCProtectedRoot(path); got != want {
			t.Fatalf("TCCProtectedRoot(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestReportInventoryScanDenialIgnoresOrdinaryPermissionErrors(t *testing.T) {
	events := capturePrereqEvents(t)
	eacces := &fs.PathError{Op: "open", Path: "/Users/u/Documents/x", Err: syscall.EACCES}
	if ReportInventoryScanDenial("/Users/u/Documents/x", eacces) {
		t.Fatal("EACCES (mode or ACL) reported as a TCC denial")
	}
	eperm := &fs.PathError{Op: "open", Path: "/Users/u/.claude/x", Err: syscall.EPERM}
	if ReportInventoryScanDenial("/Users/u/.claude/x", eperm) {
		t.Fatal("a path outside the TCC folders reported as a TCC denial")
	}
	if len(*events) != 0 {
		t.Fatalf("events = %v", *events)
	}
}

func writeIntegrityTree(t *testing.T) (string, map[string][]byte) {
	t.Helper()
	root := t.TempDir()
	files := map[string][]byte{
		"bin/defenseclaw-gateway": []byte("binary"),
		"lib/installer_lib.sh":    []byte("lib"),
		"libexec/helper":          []byte("helper"),
	}
	for rel, data := range files {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return root, files
}

func writeIntegrityManifest(t *testing.T, root string, files map[string][]byte) {
	t.Helper()
	var b strings.Builder
	for rel, data := range files {
		sum := sha256.Sum256(data)
		b.WriteString(hex.EncodeToString(sum[:]) + "  " + rel + "\n")
	}
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, IntegrityManifestRelPath), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

func integrityReasons(findings []IntegrityFinding) map[string]string {
	out := map[string]string{}
	for _, finding := range findings {
		if finding.Reason == "code_untrusted_writer" && os.Geteuid() != 0 {
			continue // test files are owned by the test user
		}
		out[filepath.Base(finding.Path)] = finding.Reason
	}
	return out
}

func TestIntegrityCheckerMissingManifestIsOneDegradedLine(t *testing.T) {
	events := capturePrereqEvents(t)
	root, _ := writeIntegrityTree(t)
	checker := NewIntegrityChecker(root)
	checker.Check()
	checker.Check()
	if len(*events) != 1 || !strings.HasPrefix((*events)[0], MarkerDegraded) || !strings.Contains((*events)[0], "integrity_manifest_missing") {
		t.Fatalf("events = %v, want one degraded line", *events)
	}
}

func TestIntegrityCheckerComparesManifestAndKeepsRunning(t *testing.T) {
	events := capturePrereqEvents(t)
	root, files := writeIntegrityTree(t)
	writeIntegrityManifest(t, root, files)
	checker := NewIntegrityChecker(root)
	if reasons := integrityReasons(checker.Check()); len(reasons) != 0 {
		t.Fatalf("a matching tree reported %v", reasons)
	}

	if err := os.WriteFile(filepath.Join(root, "lib", "installer_lib.sh"), []byte("tampered"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "libexec", "helper")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bin", "extra"), []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	reasons := integrityReasons(checker.Check())
	want := map[string]string{"installer_lib.sh": "code_hash_mismatch", "helper": "code_missing", "extra": "code_unlisted"}
	for name, reason := range want {
		if reasons[name] != reason {
			t.Fatalf("reasons = %v, want %s for %s", reasons, reason, name)
		}
	}
	boundary := 0
	for _, event := range *events {
		if strings.HasPrefix(event, MarkerBoundary) && !strings.Contains(event, "code_untrusted_writer") {
			boundary++
		}
	}
	if boundary != 3 {
		t.Fatalf("boundary lines = %d, want 3: %v", boundary, *events)
	}
	checker.Check()
	after := 0
	for _, event := range *events {
		if strings.HasPrefix(event, MarkerBoundary) && !strings.Contains(event, "code_untrusted_writer") {
			after++
		}
	}
	if after != boundary {
		t.Fatalf("a persisting finding was logged again: %v", *events)
	}
}

func TestIntegrityCheckerReHashesOnlyChangedFiles(t *testing.T) {
	root, files := writeIntegrityTree(t)
	writeIntegrityManifest(t, root, files)
	checker := NewIntegrityChecker(root)
	checker.Check()
	path := filepath.Join(root, "bin", "defenseclaw-gateway")
	cached := checker.hashes["bin/defenseclaw-gateway"]
	if cached.digest == "" {
		t.Fatal("hash was not cached")
	}
	// Same size, new content and times: the stamp changes, so it is re-hashed.
	time.Sleep(10 * time.Millisecond)
	if err := os.WriteFile(path, []byte("BINARY"), 0o755); err != nil {
		t.Fatal(err)
	}
	if reasons := integrityReasons(checker.Check()); reasons["defenseclaw-gateway"] != "code_hash_mismatch" {
		t.Fatalf("a same-size rewrite was missed: %v", reasons)
	}
}

func TestParseIntegrityManifestAcceptsShasumForms(t *testing.T) {
	digest := strings.Repeat("a", 64)
	data := []byte(digest + "  bin/a\n" + digest + " *./lib/b.sh\n" + digest + "  /root/libexec/c\n" +
		digest + "  etc/config.yaml\n" + digest + "  /elsewhere/bin/d\nnot a line\n# comment\n")
	entries, skipped := ParseIntegrityManifest("/root", data)
	for _, rel := range []string{"bin/a", "lib/b.sh", "libexec/c"} {
		if entries[rel] != digest {
			t.Fatalf("entries = %v, missing %s", entries, rel)
		}
	}
	if len(entries) != 3 || len(skipped) != 3 {
		t.Fatalf("entries = %v skipped = %v", entries, skipped)
	}
}

func TestHostChecksRunsProcessProbesAtMostEveryInterval(t *testing.T) {
	probes := healthyHostProbes()
	curls := 0
	probes.RunCurl = func(context.Context) error { curls++; return nil }
	now := time.Unix(1000, 0)
	checks := &HostChecks{
		opts:      HostCheckOptions{InstallRoot: t.TempDir()},
		probes:    probes,
		integrity: NewIntegrityChecker(t.TempDir()),
		now:       func() time.Time { return now },
	}
	checks.Run()
	checks.Run()
	if curls != 1 {
		t.Fatalf("curl ran %d times on back-to-back ticks, want 1", curls)
	}
	now = now.Add(hostPrereqInterval)
	checks.Run()
	if curls != 2 {
		t.Fatalf("curl ran %d times after the interval, want 2", curls)
	}
}
