//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// The tests of this package never ask the host's nslcd, sssctl or winbind
// for SIDs and online states: a test that needs them says so.
func init() {
	nslcdSockets = []string{filepath.Join(os.TempDir(), "defenseclaw-test-no-nslcd", "socket")}
	sssdDomainsOnline = func(context.Context) error { return nil }
	winbindDomainsOnline = func(context.Context) error { return nil }
	winbindUIDSID = func(context.Context, int) (string, error) { return "", errors.New("no winbind in tests") }
}

// fakeNSLCD answers the nslcd protocol. passwd maps "name:NAME" and
// "uid:N" to the account nslcd holds (more to the accounts it returns after
// that one), members maps a member name to the
// gids of the groups that list it, groups maps a gid to the name of the
// group nslcd holds for it, and incomplete names the requests ("name:NAME",
// "uid:N", "member:NAME", "gid:N") whose search fails: nslcd then
// closes the connection without NSLCD_RESULT_END, as it does when LDAP
// cannot be reached for that search. Every other request completes.
type fakeNSLCD struct {
	passwd     map[string]Account
	more       map[string][]Account
	members    map[string][]int
	groups     map[int]string
	incomplete map[string]bool
}

// startFakeNSLCD serves f on a socket of its own for the test.
func startFakeNSLCD(t *testing.T, f *fakeNSLCD) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "socket")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	previous := nslcdSockets
	nslcdSockets = []string{path}
	t.Cleanup(func() { nslcdSockets = previous; ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(conn)
		}
	}()
}

func (f *fakeNSLCD) serve(conn net.Conn) {
	defer conn.Close()
	read := func() (uint32, bool) {
		var buf [4]byte
		if _, err := io.ReadFull(conn, buf[:]); err != nil {
			return 0, false
		}
		return binary.BigEndian.Uint32(buf[:]), true
	}
	readString := func() (string, bool) {
		n, ok := read()
		if !ok || n > 4096 {
			return "", false
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", false
		}
		return string(buf), true
	}
	version, ok := read()
	if !ok || version != nslcdVersion {
		return
	}
	action, ok := read()
	if !ok {
		return
	}
	var key string
	switch action {
	case nslcdActionPasswdByName:
		name, ok := readString()
		if !ok {
			return
		}
		key = "name:" + name
	case nslcdActionPasswdByUID:
		uid, ok := read()
		if !ok {
			return
		}
		key = "uid:" + strconv.Itoa(int(int32(uid)))
	case nslcdActionGroupByMember:
		name, ok := readString()
		if !ok {
			return
		}
		key = "member:" + name
	case nslcdActionGroupByGID:
		gid, ok := read()
		if !ok {
			return
		}
		key = "gid:" + strconv.Itoa(int(int32(gid)))
	default:
		return
	}
	out := binary.BigEndian.AppendUint32(nil, nslcdVersion)
	out = binary.BigEndian.AppendUint32(out, action)
	putString := func(s string) { out = append(binary.BigEndian.AppendUint32(out, uint32(len(s))), s...) }
	switch action {
	case nslcdActionGroupByMember:
		for _, gid := range f.members[key[len("member:"):]] {
			out = binary.BigEndian.AppendUint32(out, nslcdResultBegin)
			putString("group" + strconv.Itoa(gid))
			putString("*")
			out = binary.BigEndian.AppendUint32(out, uint32(gid))
			out = binary.BigEndian.AppendUint32(out, 0)
		}
	case nslcdActionGroupByGID:
		gid, _ := strconv.Atoi(key[len("gid:"):])
		if name, ok := f.groups[gid]; ok {
			out = binary.BigEndian.AppendUint32(out, nslcdResultBegin)
			putString(name)
			putString("*")
			out = binary.BigEndian.AppendUint32(out, uint32(gid))
			out = binary.BigEndian.AppendUint32(out, 0)
		}
	default:
		var accounts []Account
		if account, ok := f.passwd[key]; ok {
			accounts = append(accounts, account)
		}
		for _, account := range append(accounts, f.more[key]...) {
			out = binary.BigEndian.AppendUint32(out, nslcdResultBegin)
			putString(account.Name)
			putString("*")
			out = binary.BigEndian.AppendUint32(out, uint32(account.UID))
			out = binary.BigEndian.AppendUint32(out, uint32(account.GID))
			putString(account.Gecos)
			putString(account.Home)
			putString(account.Shell)
		}
	}
	if !f.incomplete[key] {
		out = binary.BigEndian.AppendUint32(out, nslcdResultEnd)
	}
	_, _ = conn.Write(out)
}
