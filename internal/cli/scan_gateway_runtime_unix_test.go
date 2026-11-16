// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-1234 / GAP-1527: a managed Linux or macOS package installs the
// scanner runtime, so `scan skill|plugin|mcp` run through the managed
// gateway instead of answering that the packages have no scanner.
func stubManagedUnixScan(t *testing.T, record bool, runtimeErr error, goos string) string {
	t.Helper()
	data := t.TempDir()
	oldLayout, oldRead, oldRecord, oldRuntime, oldGOOS := managedScanUnixLayout, managedScanUnixReadFile, managedScanUnixRecord, managedScanUnixRuntime, managedScanUnixGOOS
	t.Cleanup(func() {
		managedScanUnixLayout, managedScanUnixReadFile, managedScanUnixRecord, managedScanUnixRuntime, managedScanUnixGOOS = oldLayout, oldRead, oldRecord, oldRuntime, oldGOOS
	})
	managedScanUnixLayout = func() (managed.StandaloneLayout, error) {
		return managed.StandaloneLayout{DataDir: data, APIAddr: managed.StandaloneAPIAddr}, nil
	}
	managedScanUnixRecord = func() bool { return record }
	managedScanUnixRuntime = func() error { return runtimeErr }
	managedScanUnixGOOS = goos
	return data
}

func TestGAP1234ManagedUnixScanRunsWhenThePackageInstalledTheRuntime(t *testing.T) {
	stubManagedUnixScan(t, true, nil, "linux")
	for _, kind := range []string{"skill", "plugin"} {
		if err := managedScanUnavailable(kind, "/opt/defenseclaw-scan/review-skill"); err != nil {
			t.Fatalf("scan %s with the runtime installed refused: %v", kind, err)
		}
	}
	if err := managedScanUnavailable("mcp", "https://mcp.example.test/mcp"); err != nil {
		t.Fatalf("scan mcp with the runtime installed refused: %v", err)
	}
}

func TestGAP1234ManagedUnixScanWithoutTheRuntimeNamesThePackage(t *testing.T) {
	stubManagedUnixScan(t, true, managed.ErrNoScannerRuntime, "linux")
	err := managedScanUnavailable("skill", "/opt/defenseclaw-scan/review-skill")
	if err == nil || commandExitCode(err) != 3 || !strings.Contains(err.Error(), "installs the scanner runtime") {
		t.Fatalf("payload deployment answer = %v (exit %d)", err, commandExitCode(err))
	}
	stubManagedUnixScan(t, true, errors.New("/opt/defenseclaw/scanner-runtime/python: group/other writable"), "linux")
	err = managedScanUnavailable("plugin", "/opt/defenseclaw-scan/p")
	if err == nil || commandExitCode(err) != 3 || !strings.Contains(err.Error(), "not trusted") || !strings.Contains(err.Error(), "reinstall") {
		t.Fatalf("untrusted runtime answer = %v", err)
	}
	stubManagedUnixScan(t, false, managed.ErrNoScannerRuntime, "linux")
	if err := managedScanUnavailable("skill", "/home/u/skill"); err != nil {
		t.Fatalf("a per-user host got the managed answer: %v", err)
	}
}

func TestGAP1234ManagedUnixScanRefusesAFolderTheServiceCannotRead(t *testing.T) {
	stubManagedUnixScan(t, true, nil, "linux")
	for _, target := range []string{"/home/dcad-r103-eng1/project/skill", "/root/skill", "/tmp/skill", "/var/tmp/x"} {
		err := managedScanUnavailable("skill", target)
		if err == nil || commandExitCode(err) != 3 || !strings.Contains(err.Error(), "cannot read") || !strings.Contains(err.Error(), "/opt/defenseclaw-scan") {
			t.Fatalf("%s: answer = %v", target, err)
		}
	}
	for _, target := range []string{"/homework/skill", "/srv/skills/x", "/opt/defenseclaw-scan/x"} {
		if err := managedScanUnavailable("skill", target); err != nil {
			t.Fatalf("%s refused: %v", target, err)
		}
	}
	stubManagedUnixScan(t, true, nil, "darwin")
	if err := managedScanUnavailable("plugin", "/Users/dcm-std1/p"); err == nil || !strings.Contains(err.Error(), "/Users") {
		t.Fatalf("macOS user folder answer = %v", err)
	}
}

func TestGAP1234ManagedUnixScanUsesTheManagedGatewayToken(t *testing.T) {
	data := stubManagedUnixScan(t, true, nil, "linux")
	if err := os.WriteFile(filepath.Join(data, ".env"), []byte("OTHER=1\nDEFENSECLAW_GATEWAY_TOKEN='tok-123'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	base, token, managedHost, err := managedScanGatewayEndpoint()
	if err != nil || !managedHost || base != "http://"+managed.StandaloneAPIAddr || token != "tok-123" {
		t.Fatalf("endpoint = %q %q %v %v", base, token, managedHost, err)
	}
	managedScanUnixReadFile = func(string) ([]byte, error) { return nil, os.ErrPermission }
	if _, _, managedHost, err := managedScanGatewayEndpoint(); !managedHost || err == nil || !strings.Contains(err.Error(), "run it with sudo") {
		t.Fatalf("standard account answer = %v %v", managedHost, err)
	}
	stubManagedUnixScan(t, false, nil, "linux")
	if _, _, managedHost, err := managedScanGatewayEndpoint(); managedHost || err != nil {
		t.Fatalf("a per-user host bound to the managed gateway: %v %v", managedHost, err)
	}
}

// The managed gateway runs as its service account: the administrator's scan
// checks the connected listener against the service, not the caller's own
// account ("connected gateway socket belongs to another account").
func TestGAP1234ManagedUnixScanVerifiesTheGatewayService(t *testing.T) {
	descriptor := filepath.Join(t.TempDir(), "managed-runtime.json")
	if err := os.WriteFile(descriptor, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	restorePath, restoreTrust, restoreManaged, restorePerUser := managedHostDescriptorPath, managedHostRecordTrusted, managedGatewayClientFactory, perUserGatewayClientFactory
	t.Cleanup(func() {
		managedHostDescriptorPath, managedHostRecordTrusted, managedGatewayClientFactory, perUserGatewayClientFactory = restorePath, restoreTrust, restoreManaged, restorePerUser
	})
	managedHostDescriptorPath = func() string { return descriptor }
	managedHostRecordTrusted = func(string) error { return nil }
	service := ""
	managedGatewayClientFactory = func(_ time.Duration, _ string, name string) (*http.Client, error) {
		service = name
		return &http.Client{}, nil
	}
	perUserGatewayClientFactory = func(time.Duration, string) (*http.Client, error) {
		t.Fatal("the managed scan checked the listener as a per-user gateway")
		return nil, nil
	}
	if _, err := gatewayPeerClientForURL(nil, "http://"+managed.StandaloneAPIAddr, time.Second); err != nil {
		t.Fatal(err)
	}
	if service != managedServiceName(false) {
		t.Fatalf("listener checked against %q, want %q", service, managedServiceName(false))
	}
}
