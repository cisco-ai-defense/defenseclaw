// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package unixidentity

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// nslcd (nss-pam-ldapd) serves the ldap NSS module on a socket. getent
// reports an nslcd search that failed (LDAP unreachable, one search base
// out of several failing, a timeout) the way it reports one that found
// nothing: "no such account" and an initgroups line without a group. nslcd
// itself tells them apart: a search that completed ends its answer with
// NSLCD_RESULT_END, and one that failed closes the connection without it.
// DefenseClaw asks nslcd itself wherever an LDAP "nothing" decides who holds
// a uid, which groups list an account, or whether a twin exists (review of
// GAP-0550, GAP-1131).

// nslcdSockets are where nslcd serves the ldap NSS module, the current
// location first. Tests replace them.
var nslcdSockets = []string{"/run/nslcd/socket", "/var/run/nslcd/socket"}

// The nslcd protocol (nslcd.h): every integer is a big-endian int32, a
// string its length and its bytes.
const (
	nslcdVersion             = 0x00000002
	nslcdActionGroupByGID    = 0x00040002
	nslcdActionGroupByMember = 0x00040006
	nslcdActionPasswdByName  = 0x00080001
	nslcdActionPasswdByUID   = 0x00080002
	nslcdResultBegin         = 1
	nslcdResultEnd           = 2

	nslcdMaxString  = 64 << 10
	nslcdMaxMembers = 1 << 16
	nslcdTimeout    = 20 * time.Second
)

// errNSLCDIncomplete is an nslcd answer that ended without
// NSLCD_RESULT_END: the search did not complete, and what it left out is
// unknown.
var errNSLCDIncomplete = errors.New("nslcd did not complete the search (it ended its answer early)")

// nslcdQuery sends one request to nslcd and reads its entries with entry
// until NSLCD_RESULT_END. An answer without it is errNSLCDIncomplete.
func nslcdQuery(ctx context.Context, action int32, request []byte, entry func(*nslcdReader) error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, nslcdTimeout)
	defer cancel()
	var conn net.Conn
	var errs []error
	for _, path := range nslcdSockets {
		c, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
		if err == nil {
			conn = c
			break
		}
		errs = append(errs, err)
	}
	if conn == nil {
		return fmt.Errorf("unixidentity: nslcd does not answer: %w: %w", errors.Join(errs...), errDirectoryUnconfirmed)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	message := binary.BigEndian.AppendUint32(nil, nslcdVersion)
	message = binary.BigEndian.AppendUint32(message, uint32(action))
	if _, err := conn.Write(append(message, request...)); err != nil {
		return fmt.Errorf("unixidentity: nslcd request: %w: %w", err, errDirectoryUnconfirmed)
	}
	r := &nslcdReader{r: conn}
	if version := r.int32(); r.err == nil && version != nslcdVersion {
		return fmt.Errorf("unixidentity: nslcd answered protocol version %d: %w", version, errDirectoryUnconfirmed)
	}
	if answered := r.int32(); r.err == nil && answered != action {
		return fmt.Errorf("unixidentity: nslcd answered another request (%#x): %w", answered, errDirectoryUnconfirmed)
	}
	for r.err == nil {
		switch code := r.int32(); {
		case r.err != nil:
		case code == nslcdResultEnd:
			return nil
		case code == nslcdResultBegin:
			if err := entry(r); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unixidentity: nslcd answered result code %d: %w", code, errNSLCDIncomplete)
		}
	}
	return fmt.Errorf("unixidentity: %w: %w: %w", errNSLCDIncomplete, r.err, errDirectoryUnconfirmed)
}

// nslcdString encodes one string of a request.
func nslcdString(value string) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(value))), value...)
}

// nslcdReader reads the fields of an nslcd answer; the first error stops
// it.
type nslcdReader struct {
	r   io.Reader
	err error
}

func (r *nslcdReader) int32() int32 {
	if r.err != nil {
		return 0
	}
	var buf [4]byte
	if _, err := io.ReadFull(r.r, buf[:]); err != nil {
		r.err = err
		return 0
	}
	return int32(binary.BigEndian.Uint32(buf[:]))
}

func (r *nslcdReader) string() string {
	n := r.int32()
	if r.err != nil {
		return ""
	}
	if n < 0 || n > nslcdMaxString {
		r.err = fmt.Errorf("nslcd string of %d bytes", n)
		return ""
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r.r, buf); err != nil {
		r.err = err
		return ""
	}
	return string(buf)
}

// passwd reads a passwd entry: name, password, uid, gid, gecos, home,
// shell.
func (r *nslcdReader) passwd() Account {
	var account Account
	account.Name = r.string()
	_ = r.string()
	account.UID = int(r.int32())
	account.GID = int(r.int32())
	account.Gecos = r.string()
	account.Home = r.string()
	account.Shell = r.string()
	return account
}

// group reads a group entry: name, password, gid and members.
func (r *nslcdReader) group() (string, int) {
	name := r.string()
	_ = r.string()
	gid := int(r.int32())
	members := r.int32()
	if r.err == nil && (members < 0 || members > nslcdMaxMembers) {
		r.err = fmt.Errorf("nslcd group with %d members", members)
	}
	for i := int32(0); i < members && r.err == nil; i++ {
		_ = r.string()
	}
	return name, gid
}

// nslcdPasswd asks nslcd for the account of a name or, when byUID, of a uid
// (key); found is false when nslcd completed the search and holds none.
func nslcdPasswd(ctx context.Context, key string, byUID bool) (Account, bool, error) {
	accounts, err := nslcdPasswdAll(ctx, key, byUID)
	switch {
	case err != nil:
		return Account{}, false, err
	case len(accounts) == 0:
		return Account{}, false, nil
	case len(accounts) > 1:
		return Account{}, false, fmt.Errorf("unixidentity: nslcd holds %d accounts for %s", len(accounts), key)
	}
	return accounts[0], true, nil
}

// nslcdPasswdAll asks nslcd for every account of a name or, when byUID, of
// a uid (key), as its completed search returns them.
func nslcdPasswdAll(ctx context.Context, key string, byUID bool) ([]Account, error) {
	action, request := int32(nslcdActionPasswdByName), nslcdString(key)
	if byUID {
		uid, err := strconv.Atoi(key)
		if err != nil || uid < 0 {
			return nil, fmt.Errorf("unixidentity: invalid uid %q", key)
		}
		action, request = nslcdActionPasswdByUID, binary.BigEndian.AppendUint32(nil, uint32(uid))
	}
	var accounts []Account
	err := nslcdQuery(ctx, action, request, func(r *nslcdReader) error {
		account := r.passwd()
		if r.err == nil {
			if len(accounts) >= nslcdMaxMembers {
				return fmt.Errorf("unixidentity: nslcd holds more than %d accounts for %s", nslcdMaxMembers, key)
			}
			accounts = append(accounts, account)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return accounts, nil
}

// nslcdGroupByGID asks nslcd for the group of gid; found is false when
// nslcd completed the search and holds none.
func nslcdGroupByGID(ctx context.Context, gid int) (string, bool, error) {
	if gid < 0 {
		return "", false, fmt.Errorf("unixidentity: invalid gid %d", gid)
	}
	var names []string
	err := nslcdQuery(ctx, nslcdActionGroupByGID, binary.BigEndian.AppendUint32(nil, uint32(gid)), func(r *nslcdReader) error {
		name, _ := r.group()
		if r.err == nil && name != "" && len(names) < 1 {
			names = append(names, name)
		}
		return nil
	})
	if err != nil || len(names) == 0 {
		return "", false, err
	}
	return names[0], true, nil
}

// nslcdGroupsByMember asks nslcd for the gids of the groups that list name
// as a member, as initgroups does.
func nslcdGroupsByMember(ctx context.Context, name string) ([]int, error) {
	var ids []int
	err := nslcdQuery(ctx, nslcdActionGroupByMember, nslcdString(name), func(r *nslcdReader) error {
		_, gid := r.group()
		if r.err == nil {
			if len(ids) >= maxDirectoryGroups {
				return fmt.Errorf("unixidentity: in more than the %d groups DefenseClaw names", maxDirectoryGroups)
			}
			ids = append(ids, gid)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return ids, nil
}
