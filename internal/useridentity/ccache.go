// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package useridentity

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Kerberos credential caches, read directly.
//
// The hook reports the default principal of the user's credential cache as a
// claimed session fact. It never runs klist: a hook must not spawn a helper
// per tool call, and the binary on PATH is the agent's to choose. Instead it
// parses the cache itself:
//
//   - FILE: (and the current file of a DIR: collection) holds the default
//     principal right after the file header (MIT ccache formats 3 and 4);
//   - KCM: asks the KCM daemon (sssd-kcm on RHEL) over its Unix socket with
//     two read-only operations, GET_DEFAULT_CACHE and GET_PRINCIPAL;
//   - KEYRING: and API: are reported by type only.
//
// Nothing here is authentication: the user owns the cache and can put any
// principal in it.

var errCCacheFormat = errors.New("useridentity: unsupported credential cache format")

// kcmStatusError is KCM's own refusal of an operation, such as no default
// cache: an answer, unlike a transport failure.
type kcmStatusError struct {
	opcode uint16
	status int32
}

func (e kcmStatusError) Error() string {
	return fmt.Sprintf("useridentity: KCM operation %d failed with status %d", e.opcode, e.status)
}

// kcmReadSettled reports whether the outcome of a KCM read answers for the
// session: a principal, KCM's refusal or a malformed reply. A transport
// failure settles nothing; the common one is the deadline passing while a
// socket-activated sssd-kcm starts after its idle exit.
func kcmReadSettled(err error) bool {
	var status kcmStatusError
	return err == nil || errors.As(err, &status) || errors.Is(err, errCCacheFormat)
}

// maxCCacheComponents and maxCCacheString bound a principal so a corrupt or
// hostile cache cannot make the hook allocate without limit.
const (
	maxCCacheComponents = 16
	maxCCacheString     = 256
	// ccacheHeaderReadLimit is how much of a FILE ccache the parser reads:
	// the format header and the default principal, never the tickets.
	ccacheHeaderReadLimit = 8 << 10
)

// SplitCCacheName splits a ccache name into its upper-case type and
// residual: "KCM:1000:42" gives ("KCM", "1000:42"); a bare path is FILE.
func SplitCCacheName(name string) (kind, residual string) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", ""
	}
	if strings.HasPrefix(name, "/") {
		return CCacheFile, name
	}
	kind, residual, found := strings.Cut(name, ":")
	if !found {
		return CCacheFile, name
	}
	return strings.ToUpper(kind), residual
}

// ParseFileCCachePrincipal reads the default principal from the start of an
// MIT FILE credential cache (format versions 3 and 4, which every current
// MIT and Heimdal build writes).
func ParseFileCCachePrincipal(r io.Reader) (string, error) {
	reader := &ccacheReader{r: io.LimitReader(r, ccacheHeaderReadLimit)}
	if reader.u8() != 5 {
		return "", errCCacheFormat
	}
	version := reader.u8()
	if reader.err != nil {
		return "", reader.err
	}
	switch version {
	case 3:
	case 4:
		// A 16-bit length then that many bytes of header tags (the KDC
		// time offset); the principal follows.
		length := int(reader.u16())
		reader.skip(length)
	default:
		return "", errCCacheFormat
	}
	return reader.principal()
}

// KCM protocol (MIT krb5 kcm.h; implemented by sssd-kcm and Heimdal kcm).
const (
	kcmProtocolMajor       = 2
	kcmProtocolMinor       = 0
	kcmOpGetPrincipal      = 8
	kcmOpGetDefaultCache   = 20
	kcmMaxReply            = 64 << 10
	DefaultKCMSocketPath   = "/run/.heim_org.h5l.kcm-socket"
	LegacyKCMSocketPath    = "/var/run/.heim_org.h5l.kcm-socket"
	kcmRequestHeaderLength = 4
)

// KCMDefaultPrincipal asks a KCM daemon on conn for the default principal of
// cacheName, or of the caller's default cache when cacheName is empty. The
// daemon identifies the caller by its peer credentials, so a user only ever
// reads their own caches.
func KCMDefaultPrincipal(conn io.ReadWriter, cacheName string) (string, error) {
	if cacheName == "" {
		reply, err := kcmCall(conn, kcmOpGetDefaultCache, nil)
		if err != nil {
			return "", err
		}
		name, _, found := bytes.Cut(reply, []byte{0})
		if !found || len(name) == 0 || len(name) > maxCCacheString {
			return "", errCCacheFormat
		}
		cacheName = string(name)
	}
	if len(cacheName) > maxCCacheString || strings.IndexByte(cacheName, 0) >= 0 {
		return "", errCCacheFormat
	}
	reply, err := kcmCall(conn, kcmOpGetPrincipal, append([]byte(cacheName), 0))
	if err != nil {
		return "", err
	}
	reader := &ccacheReader{r: bytes.NewReader(reply)}
	return reader.principal()
}

// kcmCall sends one request and returns the reply payload. A request is the
// protocol version (one byte major, one byte minor), a 16-bit big-endian
// opcode and the operation's data, framed on the Unix socket by a 32-bit
// big-endian length. A reply is that length, a 32-bit transport status
// outside it, then the reply itself, which starts with the operation's own
// 32-bit status (MIT kcmio_unix_socket_read and kcmio_call; sssd-kcm
// answers the same way).
func kcmCall(conn io.ReadWriter, opcode uint16, data []byte) ([]byte, error) {
	request := make([]byte, 4, 4+kcmRequestHeaderLength+len(data))
	binary.BigEndian.PutUint32(request, uint32(kcmRequestHeaderLength+len(data)))
	request = append(request, kcmProtocolMajor, kcmProtocolMinor)
	request = binary.BigEndian.AppendUint16(request, opcode)
	request = append(request, data...)
	if _, err := conn.Write(request); err != nil {
		return nil, err
	}
	var header [8]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header[:4])
	if status := int32(binary.BigEndian.Uint32(header[4:])); status != 0 {
		return nil, kcmStatusError{opcode: opcode, status: status}
	}
	if size < 4 || size > kcmMaxReply {
		return nil, errCCacheFormat
	}
	reply := make([]byte, size)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return nil, err
	}
	if status := int32(binary.BigEndian.Uint32(reply[:4])); status != 0 {
		return nil, kcmStatusError{opcode: opcode, status: status}
	}
	return reply[4:], nil
}

// ccacheReader decodes the big-endian fields of ccache formats 3 and 4,
// which the KCM protocol reuses for principals.
type ccacheReader struct {
	r   io.Reader
	err error
}

func (c *ccacheReader) read(n int) []byte {
	if c.err != nil {
		return nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(c.r, buf); err != nil {
		c.err = err
		return nil
	}
	return buf
}

func (c *ccacheReader) u8() byte {
	if b := c.read(1); b != nil {
		return b[0]
	}
	return 0
}

func (c *ccacheReader) u16() uint16 {
	if b := c.read(2); b != nil {
		return binary.BigEndian.Uint16(b)
	}
	return 0
}

func (c *ccacheReader) u32() uint32 {
	if b := c.read(4); b != nil {
		return binary.BigEndian.Uint32(b)
	}
	return 0
}

func (c *ccacheReader) skip(n int) {
	if n > 0 {
		c.read(n)
	}
}

func (c *ccacheReader) counted() string {
	n := c.u32()
	if c.err != nil {
		return ""
	}
	if n > maxCCacheString {
		c.err = errCCacheFormat
		return ""
	}
	return string(c.read(int(n)))
}

// principal reads name type, component count, realm and components, and
// renders user@REALM (components joined by "/").
func (c *ccacheReader) principal() (string, error) {
	c.u32() // name type
	count := c.u32()
	if c.err == nil && (count == 0 || count > maxCCacheComponents) {
		c.err = errCCacheFormat
	}
	realm := c.counted()
	components := make([]string, 0, count)
	for i := uint32(0); c.err == nil && i < count; i++ {
		components = append(components, c.counted())
	}
	if c.err != nil {
		return "", c.err
	}
	principal := NormalizePrincipal(strings.Join(components, "/") + "@" + realm)
	if principal == "" {
		return "", errCCacheFormat
	}
	return principal, nil
}
