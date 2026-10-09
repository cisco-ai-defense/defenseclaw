//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// The SID calls of the SSSD NSS responder.
//
// SSSD answers which security identifier (SID) it holds for a uid, a gid or a
// name over the public socket of its NSS responder: the calls
// libsss_nss_idmap makes (sss_nss_getsidbyuid and the rest). Any account may
// make them; the responder needs no privilege, unlike InfoPipe. This client
// speaks that protocol itself, without cgo, and never reads the SSSD memory
// cache. While SSSD is stopped or restarting that cache still answers passwd
// lookups, so a responder that does not answer is an error here, never "no
// such account" (GAP-0606).
//
// A packet is a header of four 32-bit words in host byte order (the length
// of the whole packet, the command, a status that is an errno or an SSSD
// error code, and a reserved word) followed by the body. A SID reply body is
// the number of results (0 when nothing was found), a reserved word, the id
// type and the SID as a NUL-terminated string.

const (
	sssCmdGetVersion       = 0x0001
	sssCmdSIDByName        = 0x0111 // users and groups; the fallback of sssCmdSIDByUserName
	sssCmdSIDByID          = 0x0112 // uids and gids; the fallback of the uid and gid calls
	sssCmdIDBySID          = 0x0114
	sssCmdSIDByUID         = 0x0118
	sssCmdSIDByGID         = 0x0119
	sssCmdSIDByUserName    = 0x011C
	sssNSSProtocolVersion  = 1
	sssHeaderSize          = 16
	sssMaxReply            = 64 << 10
	sssIDTypeUID           = 1
	sssIDTypeGID           = 2
	sssIDTypeBoth          = 3
	sssErrorBase           = 0x555D0000
	sssErrorMask           = 0xFFFF0000
	sssdNSSRequestDeadline = 2 * time.Second
	maxSIDLength           = 184
)

// sssdNSSSocket is the socket of the SSSD NSS responder. Tests replace it.
var sssdNSSSocket = "/var/lib/sss/pipes/nss"

// errSSSDCommandUnknown is a responder that closed the connection on a
// command: SSSD drops a client that sends a command it does not know.
var errSSSDCommandUnknown = errors.New("unixidentity: the SSSD NSS responder does not know the command")

// sssdNSS is one connection to the SSSD NSS responder. Its calls run one at
// a time, each within sssdNSSRequestDeadline, and a failed call closes it.
type sssdNSS struct {
	ctx  context.Context
	conn net.Conn
}

// dialSSSDNSS connects to the responder and checks its protocol version. A
// socket that is missing, refuses the connection or does not answer is an
// error: the account came from SSSD, so its responder should be there.
func dialSSSDNSS(ctx context.Context) (*sssdNSS, error) {
	if err := checkSSSDNSSSocket(sssdNSSSocket); err != nil {
		return nil, err
	}
	dialCtx, cancel := context.WithTimeout(ctx, sssdNSSRequestDeadline)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "unix", sssdNSSSocket)
	if err != nil {
		return nil, fmt.Errorf("unixidentity: SSSD NSS responder: %w", err)
	}
	c := &sssdNSS{ctx: ctx, conn: conn}
	body, err := c.request(sssCmdGetVersion, binary.NativeEndian.AppendUint32(nil, sssNSSProtocolVersion))
	if err != nil {
		c.Close()
		return nil, err
	}
	if len(body) < 4 || binary.NativeEndian.Uint32(body) != sssNSSProtocolVersion {
		c.Close()
		return nil, errors.New("unixidentity: the SSSD NSS responder speaks another protocol version")
	}
	return c, nil
}

// checkSSSDNSSSocket accepts a socket in a directory that only its owner
// may write, as SSSD creates /var/lib/sss/pipes.
func checkSSSDNSSSocket(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("unixidentity: SSSD NSS responder: %w", err)
	}
	if info.Mode().Type() != os.ModeSocket {
		return fmt.Errorf("unixidentity: %s is not a socket", path)
	}
	dir, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("unixidentity: SSSD NSS responder: %w", err)
	}
	if !dir.IsDir() || dir.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("unixidentity: %s is not a directory only its owner can write", filepath.Dir(path))
	}
	return nil
}

// Close closes the connection.
func (c *sssdNSS) Close() {
	if c != nil && c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
}

// request sends one command and returns the body of a reply whose status is
// 0. A non-zero status is an *sssdStatusError.
func (c *sssdNSS) request(cmd uint32, body []byte) ([]byte, error) {
	if c.conn == nil {
		return nil, errors.New("unixidentity: SSSD NSS connection closed after an earlier failure")
	}
	if err := c.ctx.Err(); err != nil {
		c.Close()
		return nil, err
	}
	deadline := time.Now().Add(sssdNSSRequestDeadline)
	if d, ok := c.ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = c.conn.SetDeadline(deadline)
	packet := make([]byte, sssHeaderSize, sssHeaderSize+len(body))
	binary.NativeEndian.PutUint32(packet[0:], uint32(sssHeaderSize+len(body)))
	binary.NativeEndian.PutUint32(packet[4:], cmd)
	packet = append(packet, body...)
	if _, err := c.conn.Write(packet); err != nil {
		c.Close()
		return nil, fmt.Errorf("unixidentity: SSSD NSS responder: %w", err)
	}
	header := make([]byte, sssHeaderSize)
	if _, err := io.ReadFull(c.conn, header); err != nil {
		c.Close()
		if errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET) {
			return nil, errSSSDCommandUnknown
		}
		return nil, fmt.Errorf("unixidentity: SSSD NSS responder: %w", err)
	}
	length := binary.NativeEndian.Uint32(header[0:])
	if length < sssHeaderSize || length > sssMaxReply || binary.NativeEndian.Uint32(header[4:]) != cmd {
		c.Close()
		return nil, errors.New("unixidentity: malformed SSSD NSS reply")
	}
	reply := make([]byte, length-sssHeaderSize)
	if _, err := io.ReadFull(c.conn, reply); err != nil {
		c.Close()
		return nil, fmt.Errorf("unixidentity: SSSD NSS responder: %w", err)
	}
	if status := binary.NativeEndian.Uint32(header[8:]); status != 0 {
		return nil, &sssdStatusError{status: status}
	}
	return reply, nil
}

// sssdStatusError is a reply that carries an errno or an SSSD error code.
type sssdStatusError struct{ status uint32 }

func (e *sssdStatusError) Error() string {
	if e.sssdCode() {
		return fmt.Sprintf("unixidentity: SSSD NSS responder error 0x%x", e.status)
	}
	return "unixidentity: SSSD NSS responder: " + syscall.Errno(e.status).Error()
}

// sssdCode reports an SSSD error code rather than an errno.
func (e *sssdStatusError) sssdCode() bool { return e.status&sssErrorMask == sssErrorBase }

// object sends a lookup whose reply names one object and returns the id
// type and the data of that reply, or ok false when the responder holds no
// such object or the object has no SID: SSSD answers an object without one,
// such as an account of a plain LDAP domain, with EINVAL. SSSD refuses a
// name lookup with an error code of its own when the name names a domain it
// does not have or one whose expression does not parse it; that says the
// name is not there too. Any other failure is an error. fallback is the older
// call that takes either kind of object, for an SSSD that does not know cmd.
func (c *sssdNSS) object(cmd, fallback uint32, body []byte) (uint32, []byte, bool, error) {
	reply, err := c.request(cmd, body)
	if errors.Is(err, errSSSDCommandUnknown) && fallback != 0 {
		var fresh *sssdNSS
		if fresh, err = dialSSSDNSS(c.ctx); err == nil {
			c.conn = fresh.conn
			reply, err = c.request(fallback, body)
		}
	}
	var status *sssdStatusError
	if errors.As(err, &status) {
		if status.status == uint32(syscall.ENOENT) || status.status == uint32(syscall.EINVAL) ||
			(status.sssdCode() && cmd == sssCmdSIDByUserName) {
			return 0, nil, false, nil
		}
	}
	if err != nil {
		return 0, nil, false, err
	}
	if len(reply) < 8 {
		return 0, nil, false, errors.New("unixidentity: malformed SSSD NSS reply")
	}
	switch binary.NativeEndian.Uint32(reply) {
	case 0:
		return 0, nil, false, nil
	case 1:
	default:
		return 0, nil, false, errors.New("unixidentity: SSSD NSS reply with more than one result")
	}
	if len(reply) < 13 {
		return 0, nil, false, errors.New("unixidentity: malformed SSSD NSS reply")
	}
	return binary.NativeEndian.Uint32(reply[8:]), reply[12:], true, nil
}

// sid sends a SID lookup and returns the SID, "" for none. types are the
// id types that answer what was asked; the older call may answer for an
// object of the other kind (a group whose gid is the uid asked for), which
// has no SID for what was asked.
func (c *sssdNSS) sid(cmd, fallback uint32, body []byte, types ...uint32) (string, error) {
	idType, data, ok, err := c.object(cmd, fallback, body)
	if err != nil || !ok {
		return "", err
	}
	if len(data) < 2 || data[len(data)-1] != 0 {
		return "", errors.New("unixidentity: malformed SSSD NSS SID reply")
	}
	sid := string(data[:len(data)-1])
	if !validSID(sid) {
		return "", fmt.Errorf("unixidentity: SSSD NSS reply carries an invalid SID %q", sid)
	}
	for _, want := range types {
		if idType == want {
			return sid, nil
		}
	}
	return "", nil
}

// uidOfSID returns the uid of the user SSSD maps sid to, or -1 when it
// maps it to none or to a group.
func (c *sssdNSS) uidOfSID(sid string) (int, error) {
	if !validSID(sid) {
		return -1, nil
	}
	idType, data, ok, err := c.object(sssCmdIDBySID, 0, append([]byte(sid), 0))
	if err != nil || !ok {
		return -1, err
	}
	if len(data) < 4 {
		return -1, errors.New("unixidentity: malformed SSSD NSS id reply")
	}
	if idType != sssIDTypeUID && idType != sssIDTypeBoth {
		return -1, nil
	}
	return int(binary.NativeEndian.Uint32(data)), nil
}

// sidByUID returns the SID SSSD holds for the user with uid, "" for none.
func (c *sssdNSS) sidByUID(uid int) (string, error) {
	if uid < 0 || uid > 4294967294 {
		return "", errors.New("unixidentity: uid out of range")
	}
	return c.sid(sssCmdSIDByUID, sssCmdSIDByID, binary.NativeEndian.AppendUint32(nil, uint32(uid)), sssIDTypeUID, sssIDTypeBoth)
}

// sidByGID returns the SID SSSD holds for the group with gid, "" for none.
func (c *sssdNSS) sidByGID(gid int) (string, error) {
	if gid < 0 || gid > 4294967294 {
		return "", errors.New("unixidentity: gid out of range")
	}
	return c.sid(sssCmdSIDByGID, sssCmdSIDByID, binary.NativeEndian.AppendUint32(nil, uint32(gid)), sssIDTypeGID, sssIDTypeBoth)
}

// sidOfUserInDomain returns the SID of the user SSSD holds as account in
// its domain domain, "" for none. The name goes in the domain\account form,
// which SSSD looks up in that domain only. SSSD looks a name with an @ that
// the named domain lacks up as a UPN or e-mail address in every domain
// (GAP-0605), so names that hold an @ or a backslash are never asked.
func (c *sssdNSS) sidOfUserInDomain(domain, account string) (string, error) {
	if domain == "" || account == "" || strings.ContainsAny(domain+account, "@\\\x00") || len(domain)+len(account) > 1024 {
		return "", nil
	}
	body := append([]byte(domain+`\`+account), 0)
	return c.sid(sssCmdSIDByUserName, sssCmdSIDByName, body, sssIDTypeUID, sssIDTypeBoth)
}

// validSID accepts the string form of a SID: S-1-<authority>-<sub>...
func validSID(sid string) bool {
	if len(sid) > maxSIDLength || !strings.HasPrefix(sid, "S-1-") {
		return false
	}
	for _, part := range strings.Split(sid[4:], "-") {
		if _, err := strconv.ParseUint(part, 10, 64); err != nil {
			return false
		}
	}
	return true
}

// sidDomain is the domain part of the SID of an account or group of an
// Active Directory or IPA domain (S-1-5-21-a-b-c of S-1-5-21-a-b-c-rid), ""
// for any other SID.
func sidDomain(sid string) string {
	if !strings.HasPrefix(sid, "S-1-5-21-") || strings.Count(sid, "-") != 7 {
		return ""
	}
	return sid[:strings.LastIndexByte(sid, '-')]
}
