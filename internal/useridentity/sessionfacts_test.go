// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package useridentity

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
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

// macOS keeps the default ticket in an API: cache only its own klist reads.
// Recorded from /usr/bin/klist --json on macOS 15.8; only the top-level
// principal counts, never a ticket's.
func TestParseKlistJSONPrincipal(t *testing.T) {
	recorded := `{ "version" : 1, "cache" : "API:FF284205-CDB6-4352-B0DB-5E77C3A75D02", "principal" : "dcad-alice@DCLAB.TEST", "tickets" : [{"Issued" : "20261006200131","Expires" : "20261007060131","Principal" : "krbtgt/DCLAB.TEST@DCLAB.TEST"}]}`
	if got := parseKlistJSONPrincipal([]byte(recorded)); got != "dcad-alice@DCLAB.TEST" {
		t.Fatalf("klist principal = %q", got)
	}
	if got := parseKlistJSONPrincipal([]byte(`{"version":1,"tickets":[{"Principal":"krbtgt/DCLAB.TEST@DCLAB.TEST"}]}`)); got != "" {
		t.Fatalf("a ticket's principal was taken as the default: %q", got)
	}
}

// GAP-0095: a KCM read that failed in transit (the deadline passing while
// sssd-kcm starts) must not be cached as the session's answer; KCM's own
// refusal is an answer.
func TestKCMReadSettledOnlyByAnAnswer(t *testing.T) {
	_, err := KCMDefaultPrincipal(timedOutConn{}, "")
	if err == nil || kcmReadSettled(err) {
		t.Fatalf("timed-out KCM read: err %v settled %v, want an unsettled error", err, kcmReadSettled(err))
	}
	var refusal bytes.Buffer
	_ = binary.Write(&refusal, binary.BigEndian, uint32(4))
	_ = binary.Write(&refusal, binary.BigEndian, uint32(0))
	_ = binary.Write(&refusal, binary.BigEndian, int32(-1765328189)) // KRB5_FCC_NOFILE
	if _, err := KCMDefaultPrincipal(&kcmReplay{in: &refusal}, ""); err == nil || !kcmReadSettled(err) {
		t.Fatalf("KCM refusal: err %v, want a settled error", err)
	}
}

type timedOutConn struct{}

func (timedOutConn) Write(p []byte) (int, error) { return len(p), nil }
func (timedOutConn) Read([]byte) (int, error)    { return 0, os.ErrDeadlineExceeded }

type kcmReplay struct{ in *bytes.Buffer }

func (k *kcmReplay) Write(p []byte) (int, error) { return len(p), nil }
func (k *kcmReplay) Read(p []byte) (int, error)  { return k.in.Read(p) }

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

// A directory may assign a Unicode Kerberos principal or Windows UPN.
func TestSessionFactsHeaderUnicodePrincipal(t *testing.T) {
	facts := ClaimedSessionHeader{
		Session: SessionFacts{KerberosPrincipal: NormalizePrincipal("josé@corp.example")},
		UPN:     NormalizeUPN("Müller@corp.example"),
	}
	header := EncodeSessionFactsHeader(facts)
	if header != "v1;krb=jos%C3%A9@CORP.EXAMPLE;upn=m%C3%BCller@corp.example" {
		t.Fatalf("encoded Unicode facts = %q", header)
	}
	got, ok := ParseSessionFactsHeader(header)
	if !ok || got.Session.KerberosPrincipal != facts.Session.KerberosPrincipal || got.UPN != facts.UPN {
		t.Fatalf("parsed Unicode facts = %+v, %v", got, ok)
	}
}

// The Linux and macOS shell hooks cannot read a credential cache: they send
// the value `hook session-facts` cached for the same session variables, so
// the Kerberos principal reaches the gateway from them too (GAP-0027).
func TestShellHookSendsTheCachedKerberosPrincipal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows hooks read the logon session in-process")
	}
	home := t.TempDir()
	var cache bytes.Buffer
	cache.Write([]byte{5, 4, 0, 0})
	cache.Write(ccachePrincipalBytes("corp.example", "alice"))
	ccache := filepath.Join(home, "krb5cc")
	if err := os.WriteFile(ccache, cache.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("KRB5CCNAME", "FILE:"+ccache)
	t.Setenv("SSH_CONNECTION", "192.0.2.10 50000 192.0.2.1 22")
	t.Setenv("SSH_TTY", "/dev/pts/3")
	t.Setenv("XDG_SESSION_ID", "12")
	want := currentSessionFactsHeader(time.Now())
	if want != "v1;k=ssh;tty=pts/3;ls=12;ca=192.0.2.10;krb=alice@CORP.EXAMPLE;cc=FILE" {
		t.Fatalf("header = %q", want)
	}
	helper := filepath.Join("..", "gateway", "connector", "hooks", "_hardening.sh")
	command := exec.Command("/bin/bash", "-c", `source "$0"; defenseclaw_session_facts_value`, helper)
	// No gateway binary on PATH: the value must come from the cache.
	command.Env = append(os.Environ(), "PATH=/usr/bin:/bin")
	out, err := command.CombinedOutput()
	if err != nil || string(out) != want {
		t.Fatalf("shell hook sent %q (%v), want the cached %q", out, err, want)
	}
}

// GAP-0299: KRB5CCNAME is the user's. A FIFO it names, as a FILE: cache or
// a DIR: collection's primary file, has no writer, and waiting on it held
// every hook past the agent's deadline, so the tool call ran uninspected.
func TestSessionFactsDoNotWaitOnAFIFOCredentialCache(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows hooks read the logon session in-process")
	}
	dir := t.TempDir()
	fifo := filepath.Join(dir, "primary")
	if out, err := exec.Command("mkfifo", fifo).CombinedOutput(); err != nil {
		t.Fatalf("mkfifo: %v %s", err, out)
	}
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SSH_CONNECTION", "192.0.2.10 50000 192.0.2.1 22")
	t.Setenv("SSH_TTY", "")
	t.Setenv("XDG_SESSION_ID", "")
	for _, ccname := range []string{"FILE:" + fifo, "DIR:" + dir} {
		t.Setenv("KRB5CCNAME", ccname)
		done := make(chan string, 1)
		go func() { done <- currentSessionFactsHeader(time.Now()) }()
		select {
		case got := <-done:
			if got != "v1;k=ssh;ca=192.0.2.10" {
				t.Fatalf("%s: header = %q, want the SSH facts alone", ccname, got)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: the session facts read waited on a FIFO", ccname)
		}
	}
}

func TestCurrentSessionFactsHeaderRefreshesAfterTicketAppears(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix credential caches only")
	}
	home := t.TempDir()
	path := filepath.Join(home, "krb5cc")
	t.Setenv("HOME", home)
	t.Setenv("KRB5CCNAME", "FILE:"+path)
	t.Setenv("SSH_CONNECTION", "")
	t.Setenv("SSH_TTY", "")
	t.Setenv("XDG_SESSION_ID", "")
	first := CurrentSessionFactsHeader()
	var cache bytes.Buffer
	cache.Write([]byte{5, 4, 0, 0})
	cache.Write(ccachePrincipalBytes("corp.example", "alice"))
	if err := os.WriteFile(path, cache.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	second := CurrentSessionFactsHeader()
	if first == second || second != "v1;k=local;krb=alice@CORP.EXAMPLE;cc=FILE" {
		t.Fatalf("session facts stayed at %q after a ticket appeared: %q", first, second)
	}
}
