// Copyright 2026 Cisco Systems, Inc. and its affiliates
// Copyright (c) 2026 Mike Storm. All rights reserved.
//
// Derived from ShadowClaw -- Universal Shadow AI Detector, by Mike Storm,
// Distinguished Engineer, CCIE Security 13847. Reimplemented in Go and
// absorbed into the DefenseClaw gateway; see NOTICE for the modifications.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package plane

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestLinuxParsesProcNetStatSafely pins the field-offset hazard: a process can
// name itself "a) 1 2 3 (b", and a naive split on whitespace would then read
// ppid and the CPU counters from the wrong offsets.
func TestLinuxDecodesProcessEvents(t *testing.T) {
	t.Parallel()
	source := &linuxSource{buffer: NewBuffer()}

	// A PROC_EVENT_EXEC payload: what(u32) cpu(u32) timestamp(u64), then
	// process_pid(u32) process_tgid(u32).
	body := make([]byte, procEventHdr+8)
	binary.LittleEndian.PutUint32(body[0:], procEventExec)
	binary.LittleEndian.PutUint32(body[procEventHdr:], 4242)
	source.decodeProcessEvent(body)

	select {
	case event := <-source.buffer.Events():
		if event.Kind != KindExec || event.PID != 4242 {
			t.Fatalf("decoded %+v, want an exec for pid 4242", event)
		}
	default:
		t.Fatal("an exec event produced nothing")
	}

	// PROC_EVENT_EXIT.
	exit := make([]byte, procEventHdr+8)
	binary.LittleEndian.PutUint32(exit[0:], procEventExit)
	binary.LittleEndian.PutUint32(exit[procEventHdr:], 4243)
	source.decodeProcessEvent(exit)
	select {
	case event := <-source.buffer.Events():
		if event.Kind != KindExit || event.PID != 4243 {
			t.Fatalf("decoded %+v, want an exit for pid 4243", event)
		}
	default:
		t.Fatal("an exit event produced nothing")
	}
}

func TestLinuxDecodesUIDChangeAsPrivilege(t *testing.T) {
	t.Parallel()
	source := &linuxSource{buffer: NewBuffer()}
	// id_proc_event: process_pid process_tgid ruid euid
	body := make([]byte, procEventHdr+16)
	binary.LittleEndian.PutUint32(body[0:], procEventUID)
	binary.LittleEndian.PutUint32(body[procEventHdr:], 5000)
	binary.LittleEndian.PutUint32(body[procEventHdr+12:], 0) // euid 0
	source.decodeProcessEvent(body)

	select {
	case event := <-source.buffer.Events():
		if event.Kind != KindPrivilege || event.PID != 5000 {
			t.Fatalf("decoded %+v, want a privilege event for pid 5000", event)
		}
		if event.Detail == "" {
			t.Error("a privilege event carried no detail")
		}
	default:
		t.Fatal("a uid change produced nothing")
	}
}

// TestLinuxIgnoresTruncatedPayloads pins that a short or malformed netlink
// datagram yields nothing rather than reading past the buffer.
func TestLinuxIgnoresTruncatedPayloads(t *testing.T) {
	t.Parallel()
	source := &linuxSource{buffer: NewBuffer()}
	for _, payload := range [][]byte{
		{}, make([]byte, 4), make([]byte, procEventHdr), make([]byte, procEventHdr+2),
	} {
		source.decodeProcessEvent(payload)
	}
	select {
	case event := <-source.buffer.Events():
		t.Fatalf("a truncated payload produced %+v", event)
	default:
	}
}

func TestLinuxCredentialRootsCoverTheAgentSurfaces(t *testing.T) {
	t.Parallel()
	roots := credentialRoots([]string{"/home/dev"})
	// fanotify has no path filter, so every root is events delivered and then
	// discarded. The set is narrow on purpose, and must still cover the two
	// things the host plane is about: secrets at rest and agent config.
	wantSuffixes := []string{".aws", ".ssh", ".claude", ".cursor", "/etc/shadow"}
	for _, want := range wantSuffixes {
		found := false
		for _, root := range roots {
			if len(root.path) >= len(want) && root.path[len(root.path)-len(want):] == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("credential roots do not cover %q: %v", want, roots)
		}
	}
	if len(credentialRoots(nil)) == 0 {
		t.Error("with no home dirs, the system roots should still be watched")
	}
	for _, root := range roots {
		underHome := strings.HasPrefix(root.path, "/home/dev/")
		if underHome != (root.home == "/home/dev") {
			t.Errorf("root %s must be tied to its home only when it lives there, got home %q", root.path, root.home)
		}
	}
}

// TestLinuxHomeCredentialRootsDoNotFollowLinksOutOfTheHome pins that the
// root helper never marks a location a home's owner redirected elsewhere:
// marking /etc through ~/.kube would flood the shared event buffer with every
// process's opens.
func TestLinuxHomeCredentialRootsDoNotFollowLinksOutOfTheHome(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	outside := t.TempDir()
	mkdir := func(path string) {
		t.Helper()
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	symlink := func(target, link string) {
		t.Helper()
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
	}
	mkdir(filepath.Join(home, ".aws"))
	mkdir(filepath.Join(home, "dotfiles", "ssh"))
	symlink(filepath.Join(home, "dotfiles", "ssh"), filepath.Join(home, ".ssh"))
	symlink("dotfiles/ssh", filepath.Join(home, ".cursor"))
	symlink(outside, filepath.Join(home, ".kube"))
	symlink("/etc", filepath.Join(home, ".docker"))
	symlink(home, filepath.Join(home, ".codex"))
	mkdir(filepath.Join(outside, "gcloud"))
	symlink(outside, filepath.Join(home, ".config"))
	if err := os.WriteFile(filepath.Join(home, ".claude"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		root string
		want string // the directory the descriptor must name; "" = refused
	}{
		{root: ".aws", want: filepath.Join(home, ".aws")},
		{root: ".ssh", want: filepath.Join(home, "dotfiles", "ssh")},
		{root: ".cursor", want: filepath.Join(home, "dotfiles", "ssh")},
		{root: ".kube"},
		{root: ".docker"},
		{root: ".codex"},
		{root: ".config/gcloud"},
		{root: ".claude"},
		{root: ".openclaw"},
	} {
		fd, err := openHomeCredentialRoot(home, filepath.Join(home, test.root))
		if test.want == "" {
			if err == nil {
				_ = unix.Close(fd)
				t.Errorf("%s: opened a credential root outside the home or not a directory", test.root)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", test.root, err)
			continue
		}
		var got, want unix.Stat_t
		statErr := unix.Fstat(fd, &got)
		_ = unix.Close(fd)
		if statErr != nil {
			t.Fatal(statErr)
		}
		if err := unix.Stat(test.want, &want); err != nil {
			t.Fatal(err)
		}
		if got.Ino != want.Ino || got.Dev != want.Dev {
			t.Errorf("%s: descriptor does not name %s", test.root, test.want)
		}
	}
}

// TestLinuxListenMessageIsWellFormed pins the netlink subscribe request, which
// is the one thing that silently yields no events when wrong.
func TestLinuxListenMessageIsWellFormed(t *testing.T) {
	t.Parallel()
	message := listenMessage()
	if got := binary.LittleEndian.Uint32(message[0:]); int(got) != len(message) {
		t.Fatalf("nlmsg_len = %d, want %d", got, len(message))
	}
	body := message[nlMsgHdrLen:]
	if got := binary.LittleEndian.Uint32(body[0:]); got != cnIdxProc {
		t.Errorf("cb_id.idx = %d, want %d", got, cnIdxProc)
	}
	if got := binary.LittleEndian.Uint32(body[4:]); got != cnValProc {
		t.Errorf("cb_id.val = %d, want %d", got, cnValProc)
	}
	if got := binary.LittleEndian.Uint32(body[20:]); got != procCNMcastListen {
		t.Errorf("op = %d, want PROC_CN_MCAST_LISTEN", got)
	}
}
