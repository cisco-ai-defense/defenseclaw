// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// procSelfNet holds this network namespace's socket tables. /proc/net is
// only a symlink to it, and a /proc mounted subset=pid (ProcSubset=pid) has
// no /proc/net, while /proc/self is always there, hidepid included
// (GAP-1138).
const procSelfNet = "/proc/self/net"

func verifyPerUserConnectedTuple(client, server *net.TCPAddr) error {
	return verifyPerUserConnectedTupleIn(procSelfNet, os.Geteuid(), perUserConnectedWait, client, server)
}

// verifyPerUserConnectedTupleIn waits for the gateway to accept the held
// connection. A connection still unaccepted at the end of the wait proves
// nothing about the process that will accept it: the error is
// errPerUserNotAccepted, and the transport reads who holds the listener
// (classifyUnaccepted, listenersHeldOnlyBy).
func verifyPerUserConnectedTupleIn(procNet string, self int, wait time.Duration, client, server *net.TCPAddr) error {
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	err := awaitPerUserLinuxSocket(ctx, self, func() (int, error) {
		return findConnectedTCPUID(procNet, client, server)
	})
	if errors.Is(err, errConnectedSocketNotAccepted) {
		return fmt.Errorf("%w: %w", errPerUserNotAccepted, err)
	}
	return err
}

// listenersHeldOnlyByPID is listenersHeldOnlyBy on the live socket tables.
func listenersHeldOnlyByPID(pid int, server *net.TCPAddr) bool {
	return listenersHeldOnlyBy(procSelfNet, "/proc", pid, server)
}

// listenersHeldOnlyBy reports whether the kernel lists at least one listening
// socket that can take a connection to server and every one is a socket that
// process pid holds open. A dual-stack IPv6 listener appears in tcp6, so both
// tables are read; a socket bound to the wildcard address counts for the
// loopback server, and no other process of this account holds any of those
// sockets (a forked or inherited listener descriptor shares the accept queue).
// Any other holder of the port, even one of the same account, an unreadable
// table or descriptor list, or no listener, is false.
func listenersHeldOnlyBy(procNet, procRoot string, pid int, server *net.TCPAddr) bool {
	key, table, err := procTCPEndpoint(server)
	if err != nil {
		return false
	}
	any4 := fmt.Sprintf("00000000:%04X", server.Port)
	any6 := fmt.Sprintf("00000000000000000000000000000000:%04X", server.Port)
	keys := map[string][]string{"tcp": {key, any4}, "tcp6": {any6}}
	if table == "tcp" {
		keys["tcp6"] = append(keys["tcp6"], mappedTCP6Endpoint(server))
	} else {
		keys["tcp"] = nil
		keys["tcp6"] = append(keys["tcp6"], key)
	}
	var inodes []string
	for _, name := range []string{"tcp", "tcp6"} {
		found, ok := readListenerInodes(procNet, name, keys[name])
		if !ok {
			return false
		}
		inodes = append(inodes, found...)
	}
	if len(inodes) == 0 {
		return false
	}
	var settle unreadableThreadSettle
	held, err := settle.socketInodesOf(procRoot, pid)
	if err != nil {
		return false
	}
	for _, inode := range inodes {
		if !held[inode] {
			return false
		}
	}
	return heldByNoOtherProcessOfThisAccount(procRoot, pid, inodes, &settle)
}

// heldByNoOtherProcessOfThisAccount reports whether no process other than pid
// holds one of the socket inodes. Every process of this account is read. A
// process that cannot be read is skipped when the kernel refuses the read as a
// permission matter of the whole process (a non-dumpable process such as an
// sshd session child, see socketInodesOf) or the process is gone or exiting:
// such a process is not a copy of the gateway's own descriptors, which a fork
// keeps readable. A live thread that cannot be read beside readable ones, and
// any other read failure, leave the answer open, so it is false. A live thread
// that cannot be read for a moment (a process of the account in the middle of
// exec or of a credential change, as the compiler and test processes of a busy
// host are all the time) is read again for a short window before it counts as
// open (unreadableThreadSettle).
func heldByNoOtherProcessOfThisAccount(procRoot string, pid int, inodes []string, settle *unreadableThreadSettle) bool {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return false
	}
	self := uint32(os.Geteuid())
	for _, entry := range entries {
		other, err := strconv.Atoi(entry.Name())
		if err != nil || other == pid {
			continue
		}
		dir := filepath.Join(procRoot, entry.Name())
		info, err := os.Stat(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return false
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid != self {
			continue
		}
		held, err := settle.socketInodesOf(procRoot, other)
		if err != nil {
			if errors.Is(err, os.ErrPermission) || errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
				continue
			}
			return false
		}
		for _, inode := range inodes {
			if held[inode] {
				return false
			}
		}
	}
	return true
}

// Reading the descriptor list of a process right while it execs or changes its
// credentials is refused for a thread that is readable a few milliseconds
// later. A refusal that outlasts unreadableThreadWindow is a thread this
// account cannot see into, and stays open (errUnreadableLiveThread: the
// listener is not proven to belong to the recorded gateway alone).
const (
	unreadableThreadWindow = 250 * time.Millisecond
	unreadableThreadPoll   = 10 * time.Millisecond
)

// unreadableThreadSettle is the one retry window of a scan: it starts at the
// first live thread that cannot be read, so a scan that meets a process which
// stays unreadable waits unreadableThreadWindow once and is then false.
type unreadableThreadSettle struct {
	by time.Time
}

// socketInodesOf is socketInodesOf that reads the process again, until the
// window ends, while the answer is errUnreadableLiveThread.
func (s *unreadableThreadSettle) socketInodesOf(procRoot string, pid int) (map[string]bool, error) {
	for {
		held, err := socketInodesOf(procRoot, pid)
		if !errors.Is(err, errUnreadableLiveThread) {
			return held, err
		}
		if s.by.IsZero() {
			s.by = time.Now().Add(unreadableThreadWindow)
		}
		if !time.Now().Before(s.by) {
			return held, err
		}
		time.Sleep(unreadableThreadPoll)
	}
}

// readListenerInodes reads one socket table and returns the socket inode of
// every listening row on one of keys, and whether the table could be read
// (tcp6 may be missing from a host).
func readListenerInodes(procNet, table string, keys []string) ([]string, bool) {
	if len(keys) == 0 {
		return nil, true
	}
	file, err := os.Open(filepath.Join(procNet, table))
	if err != nil {
		return nil, table == "tcp6" && os.IsNotExist(err)
	}
	defer file.Close()
	var inodes []string
	scanner := bufio.NewScanner(file)
	scanner.Scan() // header
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 || fields[3] != "0A" {
			continue
		}
		for _, key := range keys {
			if strings.EqualFold(fields[1], key) {
				inodes = append(inodes, fields[9])
			}
		}
	}
	return inodes, scanner.Err() == nil
}

// errUnreadableLiveThread is a refusal that is not a permission skip: a live
// thread whose descriptor folder this account may not read, in a process the
// account cannot be shown to be unable to read as a whole.
var errUnreadableLiveThread = errors.New("a live thread of the process has a descriptor folder this account may not read")

// socketInodesOf lists the socket inodes process pid holds open, from the
// descriptor folder of each of its threads. Threads usually share one
// descriptor table, but a thread can own a private copy (unshare with
// CLONE_FILES) that keeps a socket open after the leader closed it, and the
// leader folder /proc/<pid>/fd shows only the leader table, so every thread
// folder is read. A thread that exits while the list is read is skipped, and
// so is the folder of a thread that has exited but is still listed (the
// leader of a process whose workers run on is a zombie) or is exiting (the
// kernel refuses its folder part-way through, see threadRunsNoMore): it runs
// no more user code, so it can neither use nor keep a descriptor.
//
// A folder (or a link in it) the kernel refuses for a thread that is alive is
// a thread this account cannot see into. Credentials belong to the thread, so
// such a thread can sit beside readable ones, and it may hold the socket; the
// answer is errUnreadableLiveThread then. The one refusal that is a plain permission
// error is a process none of whose threads can be read, all of them with this
// account's own user and group IDs: only the dumpable flag (shared by every
// thread) explains that, as for an sshd session child, and it is not a copy of
// the gateway's descriptors, which a fork keeps readable. Any other unreadable
// live process, such as one holding group IDs of another group, is ambiguous.
func socketInodesOf(procRoot string, pid int) (map[string]bool, error) {
	taskDir := filepath.Join(procRoot, strconv.Itoa(pid), "task")
	threads, err := os.ReadDir(taskDir)
	if err != nil {
		return nil, err
	}
	held := make(map[string]bool)
	var denied error
	read, unreadable := 0, 0
	sameIDs := true
	for _, thread := range threads {
		threadDir := filepath.Join(taskDir, thread.Name())
		sockets, err := socketsOfThread(threadDir)
		switch {
		case err == nil:
			read++
			for inode := range sockets {
				held[inode] = true
			}
		case errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH):
			// thread gone
		case errors.Is(err, os.ErrPermission):
			if !threadRunsNoMore(threadDir) {
				denied = err
				unreadable++
				sameIDs = sameIDs && threadHasOwnIDs(threadDir)
			}
		default:
			return nil, err
		}
	}
	switch {
	case unreadable > 0 && (read > 0 || !sameIDs):
		return nil, errUnreadableLiveThread
	case denied != nil && read == 0:
		return nil, denied
	}
	return held, nil
}

// socketsOfThread lists the socket inodes in one thread's descriptor folder.
// The kernel can let the folder be listed and still refuse to read the links
// in it (the check on the links is the one that looks at the thread's
// credentials), so a refusal of either is a permission error of the thread.
func socketsOfThread(threadDir string) (map[string]bool, error) {
	dir := filepath.Join(threadDir, "fd")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	sockets := make(map[string]bool)
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join(dir, entry.Name()))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue // closed while listing
			}
			return nil, err
		}
		if inode, ok := strings.CutPrefix(target, "socket:["); ok {
			sockets[strings.TrimSuffix(inode, "]")] = true
		}
	}
	return sockets, nil
}

// pfExiting is the flag the kernel sets on a thread, in the first step of its
// exit, in the flags field of its stat file (PF_EXITING).
const pfExiting = 0x4

// threadRunsNoMore reports whether the task folder is one of a thread that
// will never run user code again: it has exited (zombie or dead state), is
// gone, or is exiting (PF_EXITING). Such a thread cannot accept on a
// descriptor, pass it on or keep it, and the kernel closes what it still holds
// as its exit goes on. The kernel also starts refusing its descriptor folder
// part-way through the exit, while the thread is still in state R: an
// exiting hook process of this account that another hook scans looks like a
// thread this account cannot see into. PF_EXITING is set before that refusal
// begins and is never cleared, so a refused folder of a thread without it
// stays a live thread. A state that cannot be read is a live thread.
func threadRunsNoMore(threadDir string) bool {
	raw, err := os.ReadFile(filepath.Join(threadDir, "stat"))
	if err != nil {
		return errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH)
	}
	// pid (comm) state ppid pgrp session tty tpgid flags ...: comm may hold
	// spaces and parentheses, so the fields follow the last closing
	// parenthesis.
	text := string(raw)
	end := strings.LastIndex(text, ")")
	if end < 0 {
		return false
	}
	fields := strings.Fields(text[end+1:])
	if len(fields) < 7 {
		return false
	}
	if fields[0] == "Z" || fields[0] == "X" {
		return true
	}
	flags, err := strconv.ParseUint(fields[6], 10, 64)
	return err == nil && flags&pfExiting != 0
}

// threadHasOwnIDs reports whether every user and group ID of the thread (real,
// effective, saved, file system) is this account's own, from the Uid and Gid
// lines of its status. Anything unreadable is false.
func threadHasOwnIDs(threadDir string) bool {
	raw, err := os.ReadFile(filepath.Join(threadDir, "status"))
	if err != nil {
		return false
	}
	want := map[string]string{"Uid:": strconv.Itoa(os.Geteuid()), "Gid:": strconv.Itoa(os.Getegid())}
	seen := 0
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || want[fields[0]] == "" {
			continue
		}
		if len(fields) != 5 {
			return false
		}
		for _, id := range fields[1:] {
			if id != want[fields[0]] {
				return false
			}
		}
		seen++
	}
	return seen == 2
}

// Connect can finish before the gateway accepts the same held socket. Until
// accept() gives the accepted socket a file, its procfs row has inode 0 and
// the kernel may report UID 0 for it (sock_i_uid without a socket file), so
// that row proves nothing, not even for a root caller. Only an accepted
// row's real owner is proof; a foreign owner after accept is final.
func awaitPerUserLinuxSocket(ctx context.Context, self int, inspect func() (int, error)) error {
	lastErr := errConnectedSocketNotFound
	for {
		if ctx.Err() != nil {
			return lastErr
		}
		uid, err := inspect()
		switch {
		case err == nil && uid == self:
			return nil
		case err == nil:
			return errors.New("connected gateway socket belongs to another account")
		case errors.Is(err, errConnectedSocketNotFound), errors.Is(err, errConnectedSocketNotAccepted):
			lastErr = err
		default:
			return err
		}
		select {
		case <-ctx.Done():
			return lastErr
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// errConnectedSocketNotAccepted is an exact accepted reverse tuple the
// gateway has not accept()ed yet: its owner is provisional.
var errConnectedSocketNotAccepted = errors.New("connected gateway server socket is not accepted yet")

// findConnectedTCPUID reads the kernel's accepted server socket, identified
// by both endpoints. A listening-port lookup is insufficient: its owner can
// change while the old process still holds this connected client socket.
func findConnectedTCPUID(procNet string, client, server *net.TCPAddr) (int, error) {
	serverKey, serverTable, err := procTCPEndpoint(server)
	if err != nil {
		return -1, err
	}
	clientKey, clientTable, err := procTCPEndpoint(client)
	if err != nil || serverTable != clientTable {
		return -1, errors.New("connected gateway endpoints have different address families")
	}
	uid, err := readConnectedTCPUID(procNet, serverTable, clientKey, serverKey)
	if err == nil || !errors.Is(err, errConnectedSocketNotFound) || serverTable != "tcp" {
		return uid, err
	}
	// A dual-stack IPv6 listener records its accepted IPv4 socket in tcp6
	// using IPv4-mapped addresses, even though this client dialed tcp4.
	return readConnectedTCPUID(procNet, "tcp6", mappedTCP6Endpoint(client), mappedTCP6Endpoint(server))
}

func readConnectedTCPUID(procNet, table, clientKey, serverKey string) (int, error) {
	file, err := os.Open(filepath.Join(procNet, table))
	if err != nil {
		if table == "tcp6" && os.IsNotExist(err) {
			return -1, errConnectedSocketNotFound
		}
		return -1, fmt.Errorf("inspect connected gateway sockets: %w", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Scan() // header
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 || fields[3] != "01" ||
			!strings.EqualFold(fields[1], serverKey) || !strings.EqualFold(fields[2], clientKey) {
			continue
		}
		uid, err := strconv.Atoi(fields[7])
		if err != nil || uid < 0 {
			return -1, errors.New("connected gateway socket owner is invalid")
		}
		if inode, err := strconv.ParseUint(fields[9], 10, 64); err != nil {
			return -1, errors.New("connected gateway socket inode is invalid")
		} else if inode == 0 {
			return -1, errConnectedSocketNotAccepted
		}
		return uid, nil
	}
	if err := scanner.Err(); err != nil {
		return -1, fmt.Errorf("inspect connected gateway sockets: %w", err)
	}
	return -1, errConnectedSocketNotFound
}

func mappedTCP6Endpoint(addr *net.TCPAddr) string {
	ip := addr.IP.To4()
	return fmt.Sprintf("0000000000000000FFFF0000%02X%02X%02X%02X:%04X",
		ip[3], ip[2], ip[1], ip[0], addr.Port)
}

func procTCPEndpoint(addr *net.TCPAddr) (string, string, error) {
	if addr == nil || addr.Port < 1 || addr.Port > 65535 {
		return "", "", errors.New("invalid connected gateway endpoint")
	}
	ip := addr.IP.To4()
	table := "tcp"
	if ip == nil {
		ip = addr.IP.To16()
		table = "tcp6"
	}
	if ip == nil {
		return "", "", errors.New("invalid connected gateway IP")
	}
	var encoded strings.Builder
	for offset := 0; offset < len(ip); offset += 4 {
		for index := offset + 3; index >= offset; index-- {
			fmt.Fprintf(&encoded, "%02X", ip[index])
		}
	}
	return fmt.Sprintf("%s:%04X", encoded.String(), addr.Port), table, nil
}
