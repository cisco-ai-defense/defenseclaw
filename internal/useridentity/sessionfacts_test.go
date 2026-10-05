// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package useridentity

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func ccachePrincipalBytes(realm string, components ...string) []byte {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, uint32(1)) // KRB5_NT_PRINCIPAL
	_ = binary.Write(&buf, binary.BigEndian, uint32(len(components)))
	for _, part := range append([]string{realm}, components...) {
		_ = binary.Write(&buf, binary.BigEndian, uint32(len(part)))
		buf.WriteString(part)
	}
	return buf.Bytes()
}

func TestParseFileCCachePrincipal(t *testing.T) {
	var file bytes.Buffer
	file.Write([]byte{5, 4, 0, 12})                           // version 4, 12 bytes of header tags
	file.Write([]byte{0, 1, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0})    // KDC time offset tag
	file.Write(ccachePrincipalBytes("corp.example", "alice")) // default principal
	file.Write([]byte("credentials follow"))
	got, err := ParseFileCCachePrincipal(&file)
	if err != nil || got != "alice@CORP.EXAMPLE" {
		t.Fatalf("FILE ccache principal = %q, %v; want alice@CORP.EXAMPLE", got, err)
	}
	if _, err := ParseFileCCachePrincipal(bytes.NewReader([]byte{5, 1, 0, 0})); err == nil {
		t.Fatal("format version 1 parsed")
	}
}

// fakeKCM answers the two read-only KCM operations like sssd-kcm.
type fakeKCM struct {
	replies [][]byte
	ops     []uint16
	out     bytes.Buffer
}

func (k *fakeKCM) Write(p []byte) (int, error) {
	// 4-byte length, major 2, minor 0, 2-byte opcode, data.
	if p[4] != 2 || p[5] != 0 {
		panic("unexpected KCM protocol version")
	}
	k.ops = append(k.ops, binary.BigEndian.Uint16(p[6:8]))
	reply := k.replies[0]
	k.replies = k.replies[1:]
	// Length, transport status, then the reply with its own status word,
	// as sssd-kcm writes it.
	_ = binary.Write(&k.out, binary.BigEndian, uint32(4+len(reply)))
	_ = binary.Write(&k.out, binary.BigEndian, uint32(0))
	_ = binary.Write(&k.out, binary.BigEndian, uint32(0))
	k.out.Write(reply)
	return len(p), nil
}

func (k *fakeKCM) Read(p []byte) (int, error) { return k.out.Read(p) }

func TestKCMDefaultPrincipal(t *testing.T) {
	kcm := &fakeKCM{replies: [][]byte{
		[]byte("1201:4242\x00"),
		ccachePrincipalBytes("DCLAB.TEST", "dcad-alice"),
	}}
	got, err := KCMDefaultPrincipal(kcm, "")
	if err != nil || got != "dcad-alice@DCLAB.TEST" {
		t.Fatalf("KCM principal = %q, %v", got, err)
	}
	if len(kcm.ops) != 2 || kcm.ops[0] != kcmOpGetDefaultCache || kcm.ops[1] != kcmOpGetPrincipal {
		t.Fatalf("KCM operations = %v, want GET_DEFAULT_CACHE then GET_PRINCIPAL", kcm.ops)
	}
}

func TestSessionFactsHeaderAllowlist(t *testing.T) {
	header := EncodeSessionFactsHeader(ClaimedSessionHeader{Session: SessionFacts{
		Kind: SessionSSH, TTY: "pts/3", LogindSession: "12", ClientAddr: "192.0.2.10",
		KerberosPrincipal: "alice@CORP.EXAMPLE", CCacheType: "KCM",
	}})
	if header != "v1;k=ssh;tty=pts/3;ls=12;ca=192.0.2.10;krb=alice@CORP.EXAMPLE;cc=KCM" {
		t.Fatalf("header = %q", header)
	}
	parsed, ok := ParseSessionFactsHeader("v1;k=ssh;tty=pts/3\r\nX-Evil: 1;krb=bob@corp.example;ca=not-an-ip;k=root")
	if !ok || parsed.Session.TTY != "" || parsed.Session.ClientAddr != "" || parsed.Session.Kind != "" ||
		parsed.Session.KerberosPrincipal != "bob@CORP.EXAMPLE" || parsed.Session.Assurance != AssuranceClaimed {
		t.Fatalf("parsed = %+v, %v", parsed, ok)
	}
}
