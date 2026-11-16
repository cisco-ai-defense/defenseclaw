// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// productionSyncFile is syncFile as the package defines it.
var productionSyncFile = syncFile

// TestMain runs the package without fsync. A test lifecycle run fsyncs
// every file it installs and the folder it renamed it into, about 500
// times per run; at about 5 ms each on the EBS root disk of the build
// boxes, the whole package took over 15 minutes there (6 on the CI
// runners) and hit its -timeout (GAP-0281). No test can observe a flush
// to stable storage; TestInstallAtomicSyncsTheFileThenItsFolder checks
// that the calls are still made.
func TestMain(m *testing.M) {
	syncFile = func(*os.File) error { return nil }
	os.Exit(m.Run())
}

func TestInstallAtomicSyncsTheFileThenItsFolder(t *testing.T) {
	if reflect.ValueOf(productionSyncFile).Pointer() != reflect.ValueOf((*os.File).Sync).Pointer() {
		t.Fatal("syncFile must be (*os.File).Sync outside the tests")
	}
	var synced []string
	previous := syncFile
	syncFile = func(file *os.File) error {
		synced = append(synced, file.Name())
		return nil
	}
	t.Cleanup(func() { syncFile = previous })
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	env := &Env{Lchown: func(string, int, int) error { return nil }}
	if err := env.installAtomic(path, 0o640, fileOwner{UID: os.Getuid(), GID: os.Getgid()}, func(w io.Writer) error {
		_, err := io.WriteString(w, "v: 1\n")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(synced) != 2 || filepath.Dir(synced[0]) != dir ||
		!strings.HasPrefix(filepath.Base(synced[0]), ".config.yaml.dc-") || synced[1] != dir {
		t.Fatalf("installAtomic synced %q, want its staged file and then %s", synced, dir)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "v: 1\n" {
		t.Fatalf("installed %q %v", got, err)
	}
}
