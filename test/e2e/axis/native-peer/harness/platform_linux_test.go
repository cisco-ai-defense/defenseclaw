// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func inertELF() []byte {
	// Non-runnable header: entry point zero, no PT_LOAD. Never passed to Start.
	data := make([]byte, 128)
	copy(data, "\x7fELF\x02\x01\x01")
	binary.LittleEndian.PutUint16(data[16:], 2)
	binary.LittleEndian.PutUint16(data[18:], 62)
	binary.LittleEndian.PutUint32(data[20:], 1)
	binary.LittleEndian.PutUint16(data[52:], 64)
	binary.LittleEndian.PutUint16(data[54:], 56)
	binary.LittleEndian.PutUint16(data[58:], 64)
	return data
}

func TestStaticImageStructureRejectsDynamicProgramHeaderWithoutExec(t *testing.T) {
	data := inertELF()
	if err := validateELF(data, true); err != nil {
		t.Fatal(err)
	}
	for _, typ := range []uint32{2, 3} { // PT_DYNAMIC, PT_INTERP
		candidate := inertELF()
		binary.LittleEndian.PutUint64(candidate[32:], 64)
		binary.LittleEndian.PutUint16(candidate[56:], 1)
		binary.LittleEndian.PutUint32(candidate[64:], typ)
		if err := validateELF(candidate, true); err == nil {
			t.Fatal("dynamic candidate accepted as required static closure")
		}
	}
}

func TestArtifactAndProofAdmissionSealsOnlyInertReviewedBytes(t *testing.T) {
	root := t.TempDir()
	r := syntheticRegistry(t)
	image := inertELF()
	proof := []byte("fixed public synthetic provenance; no execution")
	for i := range r.Receipt.Images {
		r.Receipt.Images[i].SHA = digestBytes(image)
		r.Receipt.Images[i].Size = int64(len(image))
	}
	for i := range r.Receipt.Builds {
		r.Receipt.Builds[i].ProvenanceSHA = digestBytes(proof)
	}
	r.Receipt.StaticClosureSHA, r.Receipt.PayloadSourceSHA = digestBytes(proof), digestBytes(proof)
	for _, name := range []string{"images/peer", "images/bwrap-static-musl", "images/fixed-payload", "proofs/STATIC-CLOSURE.json", "proofs/peer-PROVENANCE.json", "proofs/payload-PROVENANCE.json", "source/payload-main_linux.go"} {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		data := proof
		if strings.HasPrefix(name, "images/") {
			data = image
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	data, err := json.Marshal(r.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	r.ReceiptSHA = digestBytes(data)
	path := filepath.Join(root, "REVIEWED-ARTIFACTS.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, sealed, err := admitImages(ctx, path, r)
	if err != nil {
		t.Fatal(err)
	}
	if sealed == nil || sealed.peer == nil || sealed.bwrap == nil || sealed.payload == nil {
		t.Fatal("owned inert image table missing")
	}
	if err := sealed.close(); err != nil {
		t.Fatal(err)
	}
	// A changed proof cannot be self-admitted by matching image bytes alone.
	if err := os.WriteFile(filepath.Join(root, "proofs", "STATIC-CLOSURE.json"), []byte("different synthetic proof"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, sealed, err := admitImages(ctx, path, r); err == nil {
		sealed.close()
		t.Fatal("changed reviewed closure admitted")
	}
}

func TestRelativeObjectsRefuseSymlinksAndNonregularFiles(t *testing.T) {
	root, err := openDirectory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	outside := filepath.Join(t.TempDir(), "fixed-public-canary")
	if err := os.WriteFile(outside, []byte(sentinel), 0600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Symlinkat(outside, int(root.Fd()), "redirect"); err != nil {
		t.Fatal(err)
	}
	if file, err := openRelative(root, "redirect", unix.O_RDONLY); err == nil {
		file.Close()
		t.Fatal("symlink artifact followed")
	}
	if err := unix.Mkfifoat(int(root.Fd()), "fixed-fifo", 0600); err != nil {
		t.Fatal(err)
	}
	if f, _, err := boundedFile(root, "fixed-fifo", 1024, digestBytes([]byte(sentinel))); err == nil {
		f.Close()
		t.Fatal("nonregular input admitted")
	}
	for _, name := range []string{"../outside", "a/../b", "/absolute", "a//b"} {
		if f, err := openRelative(root, name, unix.O_RDONLY); err == nil {
			f.Close()
			t.Fatal("nonfixed relative object admitted")
		}
	}
}

func TestHeldSyntheticFixtureDetectsSameByteNameReplacement(t *testing.T) {
	parentPath := t.TempDir()
	parent, err := openDirectory(parentPath)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	f, err := newFixtureUnder(parent, parentPath, strings.Repeat("a", 32))
	if err != nil {
		t.Fatal(err)
	}
	defer f.close()
	if err := f.verify(false); err != nil {
		t.Fatal(err)
	}
	if _, err := f.bindingIdentity(); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []*os.File{f.work, f.home, f.temporary} {
		fd, err := unix.Openat(int(directory.Fd()), "allowed-write", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC, 0600)
		if err != nil {
			t.Fatal(err)
		}
		file := os.NewFile(uintptr(fd), "owned-inert-positive")
		_, err = file.WriteString(sentinel)
		err = errors.Join(err, file.Close())
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := f.verify(true); err != nil {
		t.Fatal(err)
	}
	if err := unix.Renameat(int(f.root.Fd()), "readonly", int(f.root.Fd()), "old-readonly"); err != nil {
		t.Fatal(err)
	}
	replacement, err := createCanary(f.root, "readonly")
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.file.Close()
	if err := f.verify(true); err == nil {
		t.Fatal("same bytes concealed original held identity replacement")
	}
}

func TestHeldFixtureNamesMustStillIdentifyOriginalRootAndOutside(t *testing.T) {
	for _, child := range []string{"root", "outside"} {
		t.Run(child, func(t *testing.T) {
			parentPath := t.TempDir()
			parent, err := openDirectory(parentPath)
			if err != nil {
				t.Fatal(err)
			}
			defer parent.Close()
			f, err := newFixtureUnder(parent, parentPath, strings.Repeat("b", 32))
			if err != nil {
				t.Fatal(err)
			}
			defer f.close()
			directory, name := f.parent, f.name
			if child == "outside" {
				directory, name = f.root, "outside"
			}
			if err := unix.Renameat(int(directory.Fd()), name, int(directory.Fd()), name+"-retained"); err != nil {
				t.Fatal(err)
			}
			if err := unix.Mkdirat(int(directory.Fd()), name, 0700); err != nil {
				t.Fatal(err)
			}
			if err := f.verify(false); err == nil {
				t.Fatal("host path silently detached from held positive control")
			}
		})
	}
}

func TestInheritedFixtureInitializesOnlyFreshHeldRoot(t *testing.T) {
	parentPath := t.TempDir()
	parent, err := openDirectory(parentPath)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	nonce := strings.Repeat("c", 32)
	name := "dc-axis-native-peer-" + nonce
	if err := unix.Mkdirat(int(parent.Fd()), name, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := openRelative(parent, name, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	f, err := initializeFixture(parent, root, parentPath, nonce)
	if err != nil {
		t.Fatal(err)
	}
	defer f.close()
	if err := f.verify(false); err != nil {
		t.Fatal(err)
	}
	if again, err := initializeFixture(parent, root, parentPath, nonce); err == nil || again != nil {
		t.Fatal("nonempty existing root was mutated/reused")
	}
}
func TestInheritedFixtureRejectsLabelSelectingAnotherOwnedObject(t *testing.T) {
	parentPath := t.TempDir()
	parent, err := openDirectory(parentPath)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	nonce := strings.Repeat("d", 32)
	name := "dc-axis-native-peer-" + nonce
	if err := unix.Mkdirat(int(parent.Fd()), name, 0700); err != nil {
		t.Fatal(err)
	}
	otherPath := t.TempDir()
	other, err := openDirectory(otherPath)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if f, err := initializeFixture(parent, other, parentPath, nonce); err == nil || f != nil {
		t.Fatal("display label selected different root")
	}
	entries, err := os.ReadDir(otherPath)
	if err != nil || len(entries) != 0 {
		t.Fatal("mismatched held root was populated")
	}
}
