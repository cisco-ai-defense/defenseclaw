//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
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
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

func TestLinuxLocalAccountsAndDirectoryConfiguration(t *testing.T) {
	dir := t.TempDir()
	origPasswd, origNSS := localPasswdPath, nsswitchPath
	t.Cleanup(func() { localPasswdPath, nsswitchPath = origPasswd, origNSS })
	localPasswdPath = filepath.Join(dir, "passwd")
	nsswitchPath = filepath.Join(dir, "nsswitch.conf")
	if err := os.WriteFile(localPasswdPath, []byte("alice:x:1000:1000::/home/alice:/bin/bash\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	local, err := LocalAccounts(context.Background())
	if err != nil || local["alice"] != 1000 || len(local) != 1 {
		t.Fatalf("LocalAccounts = %v, %v", local, err)
	}
	if DirectoryConfigured() {
		t.Fatal("a missing nsswitch.conf is glibc's files-only default")
	}
	if err := os.WriteFile(nsswitchPath, []byte("passwd: sss files systemd\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !DirectoryConfigured() {
		t.Fatal("an sss passwd source is a directory")
	}
	if err := os.Chmod(nsswitchPath, 0o000); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 && !DirectoryConfigured() {
		t.Fatal("an unreadable nsswitch.conf must be treated as a directory host")
	}
}

// Tests never ask the host's realmd; the ones about realms set hostRealms.
func init() {
	hostRealms = func(context.Context) ([]Realm, error) { return nil, nil }
	sambaConfPath = filepath.Join(os.TempDir(), "defenseclaw-test-no-smb.conf")
}

// A per-user gateway resolves the directory type of a winbind account from
// the realm realmd reports, as the root guardian does: only when the account
// name names that realm and its NSS backend. An SSSD account no joined SSSD
// realm holds by its SID gets no domain, realm or principal from its name
// (TestSSSDAccountTakesTheRealmOfItsSID). A local account
// SSSD's files provider answers for (the implicit files domain of RHEL 8)
// stays local: it was reported as the AD account lee@CORP.EXAMPLE.COM. A
// winbind account of the realm reports its DNS domain, as Windows does, not
// the NetBIOS name CORP; the NetBIOS domain of a trusted domain gets no
// realm facts. An nss_ldap account named by an e-mail address gets none
// either: it took the principal of an AD account of that name (GAP-0730).
// The account domain a DOMAIN\\user entry matches is the NetBIOS domain
// winbind reports or, for a bare name (use default domain = yes), confirms
// for the same uid; an nss_ldap CORP\\ivan gets none (GAP-0456, GAP-0814).
func TestDirectoryFactsForUIDTakesTheRealmFromRealmd(t *testing.T) {
	origNSS, origRealms, origPasswd := nsswitchPath, hostRealms, localPasswdPath
	t.Cleanup(func() { nsswitchPath, hostRealms, localPasswdPath = origNSS, origRealms, origPasswd })
	nsswitchPath = filepath.Join(t.TempDir(), "nsswitch.conf")
	localPasswdPath = filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(nsswitchPath, []byte("passwd: sss files winbind ldap systemd\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(localPasswdPath, []byte("lee:x:1000:70000::/home/lee:/bin/bash\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	hostRealms = func(context.Context) ([]Realm, error) {
		return []Realm{{Domain: "corp.example.com", Name: "CORP.EXAMPLE.COM", ServerSoftware: "active-directory",
			ClientSoftware: "winbind", NetBIOS: netBIOSName([]string{`CORP\%U`})}}, nil
	}
	accounts := map[int]string{
		70001: "alice@corp.example.com",
		70002: "bob@emea.corp.example.com",
		70003: "carol",
		70004: "dave@ldap.example.org",
		1000:  "lee",
		70005: `CORP\erin`,
		70006: `EMEA\frank`,
		70007: "gina@corp.example.com",
		70008: "hank",
		70009: `CORP\ivan`,
	}
	services := map[int]string{70005: "winbind", 70006: "winbind", 70007: "ldap", 70008: "winbind", 70009: "ldap"}
	startFakeSSSD(t, nil)
	f := &fakeRun{results: map[string]commandResult{"group 70000": {stdout: []byte("users:*:70000:\n")}}}
	for uid, name := range accounts {
		line := commandResult{stdout: []byte(name + ":*:" + strconv.Itoa(uid) + ":70000::/home/" + name + ":/bin/bash\n")}
		f.results["passwd "+strconv.Itoa(uid)] = line
		service := services[uid]
		if service == "" {
			service = "sss"
		}
		f.results["-s "+service+" passwd "+strconv.Itoa(uid)] = line
		f.results["-s "+service+" passwd "+name] = line
		f.results["initgroups "+name] = commandResult{stdout: []byte(name + " 70000\n")}
	}
	f.results[`-s winbind passwd CORP\hank`] = f.results["-s winbind passwd 70008"]
	type view struct {
		directory                                       useridentity.Directory
		source, domain, realm, principal, accountDomain string
	}
	ad, sssd := useridentity.DirectoryActiveDirectory, useridentity.SourceSSSD
	want := map[int]view{
		70001: {"", sssd, "", "", "", ""},
		70002: {"", sssd, "", "", "", ""},
		70003: {"", sssd, "", "", "", ""},
		70004: {"", sssd, "", "", "", ""},
		1000:  {useridentity.DirectoryLocal, useridentity.SourceNSSFiles, "", "", "", ""},
		70005: {ad, useridentity.SourceWinbind, "corp.example.com", "CORP.EXAMPLE.COM", "erin@corp.example.com", "CORP"},
		70006: {ad, useridentity.SourceWinbind, "emea", "", "", "EMEA"},
		70007: {useridentity.DirectoryLDAP, useridentity.SourceNSSLDAP, "", "", "", ""},
		70008: {ad, useridentity.SourceWinbind, "corp.example.com", "CORP.EXAMPLE.COM", "hank@corp.example.com", "CORP"},
		70009: {useridentity.DirectoryLDAP, useridentity.SourceNSSLDAP, "", "", "", ""},
	}
	r := newFakeNSS(f)
	for uid, expected := range want {
		facts, err := r.DirectoryFactsForUID(uid, time.Now())
		if err != nil {
			t.Fatalf("uid %d: %v", uid, err)
		}
		got := view{facts.Directory, facts.Source, facts.Domain, facts.Realm, facts.Principal, facts.AccountDomain}
		if got != expected || facts.Assurance != useridentity.AssuranceVerified {
			t.Errorf("uid %d (%s) = %+v, want %+v, verified", uid, accounts[uid], facts, expected)
		}
	}
	// With winbind use default domain only the names of other domains are
	// qualified, and realmd reports the format %U.
	if realm, ok := realmFor("emea", useridentity.SourceWinbind, []Realm{{Domain: "corp.example.com", ClientSoftware: "winbind", NetBIOS: netBIOSName([]string{"%U"})}}); ok {
		t.Errorf("a trusted NetBIOS domain took the realm %+v", realm)
	}
}

// fakeSSSD serves the SID calls of the SSSD NSS responder on a socket of its
// own. sids maps "uid:N", "gid:N" and `name:domain\account` to the SID SSSD
// holds, and "sid:SID" to the uid SSSD maps the SID to; it answers any other
// object as SSSD answers one without a SID.
type fakeSSSD struct {
	ln     net.Listener
	sids   map[string]string
	errors map[string]uint32
}

func startFakeSSSD(t *testing.T, sids map[string]string) *fakeSSSD {
	return startFakeSSSDWithErrors(t, sids, nil)
}

func startFakeSSSDWithErrors(t *testing.T, sids map[string]string, statuses map[string]uint32) *fakeSSSD {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nss")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	orig := sssdNSSSocket
	sssdNSSSocket = path
	f := &fakeSSSD{ln: ln, sids: sids, errors: statuses}
	t.Cleanup(func() { sssdNSSSocket = orig; ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(conn)
		}
	}()
	return f
}

// stop closes the socket, as a stopped or restarting SSSD does.
func (f *fakeSSSD) stop() { f.ln.Close() }

func (f *fakeSSSD) serve(conn net.Conn) {
	defer conn.Close()
	for {
		header := make([]byte, sssHeaderSize)
		if _, err := io.ReadFull(conn, header); err != nil {
			return
		}
		body := make([]byte, binary.NativeEndian.Uint32(header)-sssHeaderSize)
		if _, err := io.ReadFull(conn, body); err != nil {
			return
		}
		cmd, status, idType := binary.NativeEndian.Uint32(header[4:]), uint32(0), uint32(sssIDTypeUID)
		var key string
		switch cmd {
		case sssCmdGetVersion:
		case sssCmdSIDByUID:
			key = "uid:" + strconv.Itoa(int(binary.NativeEndian.Uint32(body)))
		case sssCmdSIDByGID:
			key, idType = "gid:"+strconv.Itoa(int(binary.NativeEndian.Uint32(body))), sssIDTypeGID
		case sssCmdSIDByUserName:
			key = "name:" + strings.TrimSuffix(string(body), "\x00")
		case sssCmdIDBySID:
			key = "sid:" + strings.TrimSuffix(string(body), "\x00")
		default:
			return
		}
		var reply []byte
		switch sid, ok := f.sids[key]; {
		case cmd == sssCmdGetVersion:
			reply = binary.NativeEndian.AppendUint32(nil, sssNSSProtocolVersion)
		case f.errors[key] != 0:
			status = f.errors[key]
		case ok:
			reply = binary.NativeEndian.AppendUint32(nil, 1)
			reply = binary.NativeEndian.AppendUint32(reply, 0)
			reply = binary.NativeEndian.AppendUint32(reply, idType)
			if cmd == sssCmdIDBySID {
				uid, _ := strconv.Atoi(sid)
				reply = binary.NativeEndian.AppendUint32(reply, uint32(uid))
			} else {
				reply = append(append(reply, sid...), 0)
			}
		default:
			status = uint32(syscall.EINVAL)
		}
		out := make([]byte, sssHeaderSize, sssHeaderSize+len(reply))
		binary.NativeEndian.PutUint32(out, uint32(sssHeaderSize+len(reply)))
		binary.NativeEndian.PutUint32(out[4:], cmd)
		binary.NativeEndian.PutUint32(out[8:], status)
		if _, err := conn.Write(append(out, reply...)); err != nil {
			return
		}
	}
}

// An SSSD account takes the realm and principal of a joined domain only
// when SSSD holds a SID for its uid and a user of its name with that SID in
// the domain, asked as domain\name. Names prove nothing: SSSD answers a
// name@domain the domain lacks with a UPN or e-mail search in every domain,
// which confirmed the LDAP frank (mail frank@corp.example.com) and the LDAP
// erin@corp.example.com in the AD domain (GAP-0605, GAP-0568); a short LDAP
// name gets no AD realm (GAP-0497), nor does an account of another domain
// with its own SID that shares an AD account name, or one that copies an AD
// account SID, which SSSD maps to the AD account uid. A SID-less CORP\\ivan
// gets no domain from its name (GAP-0814); the AD alice gets the NetBIOS
// domain SSSD confirms for her SID (GAP-0456). The AD alice keeps
// trusted-domain memberships returned for her qualified name, plus local
// groups listing alice (GAP-0729), split as glibc splits them: after a
// comma and a space, but not as the last member of a CRLF line (GAP-0815). The LDAP carol does not get the AD
// groups returned for her ambiguous short name (GAP-0563). A local group
// listing alice@corp.example.com belongs to an account with that exact name.
// An SSSD that is stopped while its memory cache still answers the uid
// fails the lookup instead of dropping the realm and groups (GAP-0606).
func TestSSSDAccountTakesTheRealmOfItsSID(t *testing.T) {
	origNSS, origRealms, origPasswd, origGroup := nsswitchPath, hostRealms, localPasswdPath, localGroupPath
	t.Cleanup(func() {
		nsswitchPath, hostRealms, localPasswdPath, localGroupPath = origNSS, origRealms, origPasswd, origGroup
	})
	dir := t.TempDir()
	nsswitchPath, localPasswdPath, localGroupPath = filepath.Join(dir, "nsswitch.conf"), filepath.Join(dir, "passwd"), filepath.Join(dir, "group")
	for path, content := range map[string]string{nsswitchPath: "passwd: files sss\n", localPasswdPath: "", localGroupPath: "docker:x:7000:alice\nwheel:x:10:alice@corp.example.com\n" +
		"staff:x:7001:bob, alice\ncrlf:x:7002:bob,alice\r\n"} {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	hostRealms = func(context.Context) ([]Realm, error) {
		return []Realm{{Domain: "corp.example.com", Name: "CORP.EXAMPLE.COM",
			ServerSoftware: "active-directory", ClientSoftware: "sssd"}}, nil
	}
	const corp, other, emea, ldapChild = "S-1-5-21-1-2-3", "S-1-5-21-7-8-9", "S-1-5-21-4-5-6", "S-1-5-21-8-9-10"
	sssd := startFakeSSSD(t, map[string]string{
		"uid:80001": corp + "-1101", `name:corp.example.com\alice`: corp + "-1101", "sid:" + corp + "-1101": "80001",
		`name:corp.example.com\carol`: corp + "-1103",
		"uid:80006":                   other + "-1104", `name:corp.example.com\dave`: corp + "-1104",
		"uid:80007": emea + "-1107", `name:emea.corp.example.com\gail`: emea + "-1107", `name:corp.example.com\gail`: emea + "-1107", "sid:" + emea + "-1107": "80007",
		`name:ldap.corp.example.com\alice`: ldapChild + "-1109", "uid:80009": ldapChild + "-1109", "sid:" + ldapChild + "-1109": "80009",
		"uid:80008": corp + "-1108", `name:corp.example.com\hank`: corp + "-1108", "sid:" + corp + "-1108": "90008",
		"uid:80011": emea + "-1111", `name:emea.corp.example.com\ken`: emea + "-1111", "sid:" + emea + "-1111": "80011",
		"gid:5000": corp + "-513", "gid:5300": other + "-1201", `name:CORP\alice`: corp + "-1101",
	})
	line := func(name string, uid int) commandResult {
		id := strconv.Itoa(uid)
		return commandResult{stdout: []byte(name + ":*:" + id + ":" + id + "::/home/" + name + ":/bin/bash\n")}
	}
	f := &fakeRun{results: map[string]commandResult{
		"initgroups corp.example.com\\alice": {stdout: []byte("corp.example.com\\alice 80001 5000 5300\n")},
		"group 5000 7000 80001":              {stdout: []byte("domain users:*:5000:\ndocker:*:7000:\nalice:*:80001:\n")},
		"group 5000 5300 7000 7001 80001":    {stdout: []byte("domain users:*:5000:\ntrusted-admins:*:5300:\ndocker:*:7000:\nstaff:*:7001:\nalice:*:80001:\n")},
		"initgroups carol":                   {stdout: []byte("carol 80003 5000 5100\n")},
		"group 5100 80003":                   {stdout: []byte("ldap-devs:*:5100:\ncarol:*:80003:\n")},
	}}
	accounts := map[int]string{80001: "alice", 80002: "bob", 80003: "carol", 80004: "frank", 80005: "erin@corp.example.com",
		80006: "dave", 80007: "gail@emea.corp.example.com", 80008: "hank", 80009: "alice@ldap.corp.example.com", 80010: `CORP\ivan`, 80011: "ken"}
	for uid, name := range accounts {
		f.results["passwd "+strconv.Itoa(uid)] = line(name, uid)
		f.results["-s sss passwd "+strconv.Itoa(uid)] = line(name, uid)
	}
	// SSSD answers these names with the account itself through its UPN and
	// e-mail search, and the name carol with the AD carol.
	f.results["-s sss passwd frank@corp.example.com"] = line("frank", 80004)
	f.results["-s sss passwd erin@corp.example.com"] = line("erin@corp.example.com", 80005)
	f.results["-s sss passwd carol@corp.example.com"] = line("carol", 90003)
	r := newFakeNSS(f)
	ad := useridentity.DirectoryActiveDirectory
	checkFacts := func(want map[int]useridentity.DirectoryFacts) {
		t.Helper()
		for uid, want := range want {
			facts, err := r.DirectoryFactsWithoutGroupsForUID(uid, time.Now())
			want.Source = useridentity.SourceSSSD
			got := useridentity.DirectoryFacts{Source: facts.Source, Directory: facts.Directory, Domain: facts.Domain,
				Realm: facts.Realm, Principal: facts.Principal, AccountDomain: facts.AccountDomain}
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Errorf("uid %d (%s) = %+v, %v; want %+v (trusted children %q)", uid, accounts[uid], got, err, want,
					useridentity.TrustedADChildDomains())
			}
		}
	}
	// The child-domain accounts gail and ken get nothing while their domain
	// is not listed, though SSSD holds their SIDs and the parent-domain name
	// lookup of gail answers her SID (GAP-1255).
	checkFacts(map[int]useridentity.DirectoryFacts{
		80001: {Directory: ad, Domain: "corp.example.com", Realm: "CORP.EXAMPLE.COM", Principal: "alice@corp.example.com", AccountDomain: "CORP"},
		80002: {}, 80003: {}, 80004: {}, 80005: {}, 80006: {}, 80007: {}, 80008: {}, 80009: {}, 80010: {}, 80011: {},
	})
	// Listed, emea takes the realm of its own name and the directory type of
	// the joined parent; the LDAP domain below the joined one stays untrusted.
	t.Cleanup(func() { useridentity.SetTrustedADChildDomains(nil) })
	useridentity.SetTrustedADChildDomains([]string{"EMEA.corp.example.com."})
	emeaFacts := func(name string) useridentity.DirectoryFacts {
		return useridentity.DirectoryFacts{Directory: ad, Domain: "emea.corp.example.com", Realm: "EMEA.CORP.EXAMPLE.COM",
			Principal: name + "@emea.corp.example.com"}
	}
	checkFacts(map[int]useridentity.DirectoryFacts{80007: emeaFacts("gail"), 80011: emeaFacts("ken"), 80009: {}})
	useridentity.SetTrustedADChildDomains(nil)
	for uid, want := range map[int][]string{80001: {"domain users", "trusted-admins", "docker", "staff", "alice"}, 80003: {"ldap-devs", "carol"}} {
		if facts, err := r.DirectoryFactsForUID(uid, time.Now()); err != nil || !reflect.DeepEqual(facts.Groups, want) {
			t.Errorf("uid %d groups = %q, %v; want %q", uid, facts.Groups, err, want)
		}
	}
	// The guardian places an account without a SID by InfoPipe's domain of
	// its uid: the joined domain gives its realm, another domain none, nor
	// does a name that carries another domain.
	for _, tc := range []struct {
		name, domain, realm string
	}{{"bob", "corp.example.com", "CORP.EXAMPLE.COM"}, {"bob", "ldaplab", ""}, {"erin@example.org", "corp.example.com", ""},
		{"alice@ldap.corp.example.com", "ldap.corp.example.com", ""}, {"bob", "emea.corp.example.com", ""}} {
		var facts useridentity.DirectoryFacts
		if err := ApplyHeldSSSDDomain(context.Background(), &facts, tc.name, tc.domain, ""); err != nil || facts.Realm != tc.realm {
			t.Errorf("ApplyHeldSSSDDomain(%s in %s) = %+v, %v; want realm %q", tc.name, tc.domain, facts, err, tc.realm)
		}
	}
	sssd.stop()
	for _, uid := range []int{80001, 80003} {
		if facts, err := r.DirectoryFactsForUID(uid, time.Now()); err == nil {
			t.Errorf("uid %d with SSSD stopped = %+v, want an error", uid, facts)
		}
	}
}

func TestFailedRealmdQueryDoesNotCacheEmptyRealms(t *testing.T) {
	realmCache.mu.Lock()
	oldRealms, oldFetched := realmCache.realms, realmCache.fetched
	realmCache.realms, realmCache.fetched = nil, time.Time{}
	realmCache.mu.Unlock()
	t.Cleanup(func() {
		realmCache.mu.Lock()
		realmCache.realms, realmCache.fetched = oldRealms, oldFetched
		realmCache.mu.Unlock()
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cachedRealms(ctx)
	realmCache.mu.Lock()
	fetched := realmCache.fetched
	realmCache.mu.Unlock()
	if !fetched.IsZero() {
		t.Fatal("a failed realmd query was cached as an empty answer")
	}
	oldRealmsFn, oldNSS, oldPasswd := hostRealms, nsswitchPath, localPasswdPath
	t.Cleanup(func() { hostRealms, nsswitchPath, localPasswdPath = oldRealmsFn, oldNSS, oldPasswd })
	hostRealms = func(context.Context) ([]Realm, error) { return nil, context.DeadlineExceeded }
	dir := t.TempDir()
	nsswitchPath, localPasswdPath = filepath.Join(dir, "nsswitch.conf"), filepath.Join(dir, "passwd")
	if err := os.WriteFile(nsswitchPath, []byte("passwd: sss files\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(localPasswdPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	const name = "alice@corp.example.com"
	startFakeSSSD(t, map[string]string{"uid:80001": "S-1-5-21-1-2-3-1101", "sid:S-1-5-21-1-2-3-1101": "80001"})
	f := &fakeRun{results: map[string]commandResult{
		"passwd 80001":        {stdout: []byte(name + ":*:80001:80001::/home/alice:/bin/bash\n")},
		"-s sss passwd 80001": {stdout: []byte(name + ":*:80001:80001::/home/alice:/bin/bash\n")},
		"initgroups " + name:  {stdout: []byte(name + " 80001\n")},
		"group 80001":         {stdout: []byte(name + ":*:80001:\n")},
	}}
	if facts, err := newFakeNSS(f).DirectoryFactsForUID(80001, time.Now()); err == nil {
		t.Fatalf("realmd failure produced cacheable facts: %+v", facts)
	}
}

// A failed flat-domain lookup cannot produce verified facts without the
// account domain used by a DOMAIN\user profile assignment.
func TestWinbindAccountDomainLookupFailure(t *testing.T) {
	dir := t.TempDir()
	oldNSS, oldPasswd, oldRealms := nsswitchPath, localPasswdPath, hostRealms
	t.Cleanup(func() { nsswitchPath, localPasswdPath, hostRealms = oldNSS, oldPasswd, oldRealms })
	nsswitchPath, localPasswdPath = filepath.Join(dir, "nsswitch.conf"), filepath.Join(dir, "passwd")
	if err := os.WriteFile(nsswitchPath, []byte("passwd: files winbind\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(localPasswdPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	hostRealms = func(context.Context) ([]Realm, error) {
		return []Realm{{Domain: "corp.example.com", Name: "CORP.EXAMPLE.COM", ClientSoftware: "winbind",
			ServerSoftware: "active-directory", NetBIOS: "CORP"}}, nil
	}
	const account = "alice:*:80001:80001::/home/alice:/bin/bash\n"
	lookupErr := syscall.EIO
	f := &fakeRun{results: map[string]commandResult{
		"passwd 80001":            {stdout: []byte(account)},
		"-s winbind passwd 80001": {stdout: []byte(account)},
	}, errs: map[string]error{`-s winbind passwd CORP\alice`: lookupErr}}
	facts, err := newFakeNSS(f).DirectoryFactsWithoutGroupsForUID(80001, time.Now())
	if !errors.Is(err, lookupErr) || facts.Assurance == useridentity.AssuranceVerified {
		t.Fatalf("failed NetBIOS lookup: facts = %+v, err = %v", facts, err)
	}
}

// SSSD may confirm the account's DNS realm and then fail the flat-domain
// lookup. That partial answer must not become cacheable verified facts.
func TestSSSDAccountDomainLookupFailure(t *testing.T) {
	dir := t.TempDir()
	oldNSS, oldPasswd, oldRealms := nsswitchPath, localPasswdPath, hostRealms
	t.Cleanup(func() { nsswitchPath, localPasswdPath, hostRealms = oldNSS, oldPasswd, oldRealms })
	nsswitchPath, localPasswdPath = filepath.Join(dir, "nsswitch.conf"), filepath.Join(dir, "passwd")
	if err := os.WriteFile(nsswitchPath, []byte("passwd: files sss\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(localPasswdPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	hostRealms = func(context.Context) ([]Realm, error) {
		return []Realm{{Domain: "corp.example.com", Name: "CORP.EXAMPLE.COM", ClientSoftware: "sssd",
			ServerSoftware: "active-directory", NetBIOS: "CORP"}}, nil
	}
	const sid = "S-1-5-21-1-2-3-1101"
	startFakeSSSDWithErrors(t, map[string]string{
		"uid:80001": sid, "sid:" + sid: "80001",
		`name:corp.example.com\alice`: sid,
	}, map[string]uint32{`name:CORP\alice`: uint32(syscall.EIO)})
	const account = "alice:*:80001:80001::/home/alice:/bin/bash\n"
	f := &fakeRun{results: map[string]commandResult{
		"passwd 80001":        {stdout: []byte(account)},
		"-s sss passwd 80001": {stdout: []byte(account)},
	}}
	facts, err := newFakeNSS(f).DirectoryFactsWithoutGroupsForUID(80001, time.Now())
	if err == nil || facts.Assurance == useridentity.AssuranceVerified {
		t.Fatalf("failed SSSD flat-domain lookup: facts = %+v, err = %v", facts, err)
	}
}

// GAP-1095: a domain whose first DNS label is longer than 15 characters
// (Entra Domain Services) gets the flat name its controllers announce
// (adcli info), once SSSD holds the account's SID under it; the label is
// still never taken.
func TestSSSDAccountDomainTakesTheAnnouncedFlatName(t *testing.T) {
	dir := t.TempDir()
	oldNSS, oldPasswd, oldRealms, oldTool := nsswitchPath, localPasswdPath, hostRealms, adcliTool
	t.Cleanup(func() {
		nsswitchPath, localPasswdPath, hostRealms, adcliTool = oldNSS, oldPasswd, oldRealms, oldTool
		adcliShortNames.byDomain = nil
	})
	nsswitchPath, localPasswdPath = filepath.Join(dir, "nsswitch.conf"), filepath.Join(dir, "passwd")
	if err := os.WriteFile(nsswitchPath, []byte("passwd: files sss\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(localPasswdPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	const domain, flat, sid = "corp-entra-ds-01.example.com", "CORPENTRADS01", "S-1-5-21-4-5-6-1107"
	hostRealms = func(context.Context) ([]Realm, error) {
		return []Realm{{Domain: domain, Name: strings.ToUpper(domain), ClientSoftware: "sssd", ServerSoftware: "active-directory"}}, nil
	}
	adcliTool = func() (string, error) { return "/usr/sbin/adcli", nil }
	startFakeSSSD(t, map[string]string{
		"uid:80001": sid, "sid:" + sid: "80001",
		`name:` + domain + `\alice`: sid, `name:` + flat + `\alice`: sid,
	})
	const account = "alice:*:80001:80001::/home/alice:/bin/bash\n"
	f := &fakeRun{results: map[string]commandResult{
		"passwd 80001":        {stdout: []byte(account)},
		"-s sss passwd 80001": {stdout: []byte(account)},
		"info " + domain:      {stdout: []byte("[domain]\ndomain-name = " + domain + "\ndomain-short = " + flat + "\n")},
	}, errs: map[string]error{"info " + domain: errors.New("adcli temporarily unavailable")}}
	r := newFakeNSS(f)
	facts, err := r.DirectoryFactsWithoutGroupsForUID(80001, time.Now())
	if err == nil || facts.Assurance == useridentity.AssuranceVerified {
		t.Fatalf("failed adcli lookup: facts = %+v, err = %v", facts, err)
	}
	delete(f.errs, "info "+domain)
	facts, err = r.DirectoryFactsWithoutGroupsForUID(80001, time.Now())
	if err != nil || facts.AccountDomain != flat || facts.Domain != domain {
		t.Fatalf("facts = %+v, err = %v; want the account domain %s", facts, err, flat)
	}
}

func TestSSSDAccountKeepsGroupFromAnotherNSSService(t *testing.T) {
	dir := t.TempDir()
	oldPasswd, oldGroup, oldNSS := localPasswdPath, localGroupPath, nsswitchPath
	t.Cleanup(func() { localPasswdPath, localGroupPath, nsswitchPath = oldPasswd, oldGroup, oldNSS })
	localPasswdPath, localGroupPath, nsswitchPath = filepath.Join(dir, "passwd"), filepath.Join(dir, "group"), filepath.Join(dir, "nsswitch.conf")
	for path, content := range map[string]string{
		localPasswdPath: "",
		localGroupPath:  "",
		nsswitchPath:    "passwd: files sss\ngroup: files sss ldap\n",
	} {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	const sid = "S-1-5-21-1-2-3-1101"
	startFakeSSSD(t, map[string]string{"uid:1001": sid, "sid:" + sid: "1001"})
	account := "alice:x:1001:1001::/home/alice:/bin/bash\n"
	f := &fakeRun{results: map[string]commandResult{
		"passwd 1001":              {stdout: []byte(account)},
		"-s sss passwd 1001":       {stdout: []byte(account)},
		"initgroups alice":         {stdout: []byte("alice 1001 7001\n")},
		"-s ldap initgroups alice": {stdout: []byte("alice 7001\n")},
		"group 1001":               {stdout: []byte("alice:x:1001:\n")},
		"group 1001 7001":          {stdout: []byte("alice:x:1001:\nldap-admins:x:7001:\n")},
	}}
	facts, err := newFakeNSS(f).DirectoryFactsForUID(1001, time.Now())
	if err != nil || !reflect.DeepEqual(facts.Groups, []string{"alice", "ldap-admins"}) {
		t.Fatalf("SSSD account groups = %q, %v", facts.Groups, err)
	}
	f.results["-s ldap initgroups alice"] = commandResult{stdout: []byte("alice\n")}
	facts, err = newFakeNSS(f).DirectoryFactsForUID(1001, time.Now())
	if err != nil || !reflect.DeepEqual(facts.Groups, []string{"alice"}) {
		t.Fatalf("without LDAP membership, groups = %q, %v", facts.Groups, err)
	}
}

// A failed domain-qualified initgroups lookup can fall back to an ambiguous
// short name. A local group must list this account before it can rescue a
// SID-less gid from that result.
func TestSSSDFallbackRequiresLocalGroupMembership(t *testing.T) {
	origGroup, origNSS := localGroupPath, nsswitchPath
	t.Cleanup(func() { localGroupPath, nsswitchPath = origGroup, origNSS })
	dir := t.TempDir()
	localGroupPath, nsswitchPath = filepath.Join(dir, "group"), filepath.Join(dir, "nsswitch.conf")
	if err := os.WriteFile(localGroupPath, []byte("strict:x:7001:bob\nshared:x:7002:alice\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nsswitchPath, []byte("initgroups: files sss\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := newFakeNSS(&fakeRun{results: map[string]commandResult{
		"initgroups corp.example.com\\alice": {exitCode: getentExitNotFound},
		"initgroups alice":                   {stdout: []byte("alice 5000 7001 7002\n")},
	}})
	account := Account{Name: "alice", GID: 5000}
	ids, qualified, err := r.accountGroupIDs(account, "corp.example.com")
	if err != nil || qualified {
		t.Fatalf("fallback groups = %v, qualified %t, err %v", ids, qualified, err)
	}
	startFakeSSSD(t, nil)
	sssd, err := dialSSSDNSS(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer sssd.Close()
	kept, err := r.sssdGroupsOfDomain(sssd, ids, account, "S-1-5-21-1-2-3")
	if err != nil || !reflect.DeepEqual(kept, []int{5000, 7002}) {
		t.Fatalf("verified gids = %v, err %v; want only primary and listed membership", kept, err)
	}
}
