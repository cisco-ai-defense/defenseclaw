// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gateway

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// Verified sessions on Linux.
//
// The hook claims its logind session id (XDG_SESSION_ID) and terminal. The
// gateway's sandbox (ProtectProc=invisible) hides the caller's /proc entry,
// so it asks systemd-logind instead: GetSession(id) over the system bus, and
// the session's User must be the kernel-verified peer uid. Only then are the
// session's kind, remote host and terminal reported as verified. Without
// logind, /run/utmp confirms a claimed terminal belongs to the peer's
// account. Only logind session ids are cached; a tty can be reused at logout.

const (
	logindService       = "org.freedesktop.login1"
	logindPath          = "/org/freedesktop/login1"
	logindGetSession    = "org.freedesktop.login1.Manager.GetSession"
	logindSessionIface  = "org.freedesktop.login1.Session"
	logindCallTimeout   = 2 * time.Second
	utmpPath            = "/run/utmp"
	sessionCacheKeySep  = "\x1f"
	maxClaimedTTYLength = 32
)

var (
	utmpSessionPath  = utmpPath
	peerSessionsOnce sync.Once
	peerSessions     *identityCache[useridentity.SessionFacts]
)

// verifyPeerSession confirms the claimed session for a verified peer.
func verifyPeerSession(uid int, name string, claimed useridentity.SessionFacts) (useridentity.SessionFacts, bool) {
	if uid < 0 {
		return useridentity.SessionFacts{}, false
	}
	key := ""
	switch {
	case claimed.LogindSession != "":
		key = strings.Join([]string{strconv.Itoa(uid), "ls", claimed.LogindSession}, sessionCacheKeySep)
	case claimed.TTY != "" && name != "":
		// A pts number is reusable immediately after logout. Read utmp on
		// every claim so a new login cannot inherit the prior address.
		session, err := utmpSessionFacts(claimed.TTY, name)
		return session, err == nil && session.Assurance == useridentity.AssuranceVerified
	default:
		return useridentity.SessionFacts{}, false
	}
	peerSessionsOnce.Do(func() {
		peerSessions = newIdentityCache(resolvePeerSession)
	})
	session, ok := peerSessions.get(key, true)
	if !ok || session.Empty() {
		return useridentity.SessionFacts{}, false
	}
	return session, true
}

func resolvePeerSession(key string) (useridentity.SessionFacts, error) {
	parts := strings.Split(key, sessionCacheKeySep)
	if len(parts) < 3 {
		return useridentity.SessionFacts{}, errors.New("malformed session key")
	}
	uid, err := strconv.Atoi(parts[0])
	if err != nil {
		return useridentity.SessionFacts{}, err
	}
	switch parts[1] {
	case "ls":
		session, err := logindSessionFacts(uid, parts[2])
		if err != nil {
			// A definitive answer (no such session, another user's) is
			// cached as "not verified"; a bus failure is retried.
			if errors.Is(err, errSessionNotOwned) {
				return useridentity.SessionFacts{}, nil
			}
			return useridentity.SessionFacts{}, err
		}
		return session, nil
	}
	return useridentity.SessionFacts{}, errors.New("malformed session key")
}

var errSessionNotOwned = errors.New("session does not belong to the peer")

var (
	logindBusMu sync.Mutex
	logindBus   *dbus.Conn
)

func logindConn(ctx context.Context) (*dbus.Conn, error) {
	logindBusMu.Lock()
	defer logindBusMu.Unlock()
	if logindBus != nil && logindBus.Connected() {
		return logindBus, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// godbus Auth and Hello can wait for a bus reply without honoring the
	// call context. Closing the connection on deadline interrupts both.
	connCtx, cancel := context.WithCancel(context.Background())
	stop := context.AfterFunc(ctx, cancel)
	conn, err := dbus.ConnectSystemBus(dbus.WithContext(connCtx))
	stop()
	if err != nil {
		cancel()
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		cancel()
		return nil, err
	}
	logindBus = conn
	return conn, nil
}

// logindSessionFacts reads one session's properties and checks its owner.
func logindSessionFacts(uid int, id string) (useridentity.SessionFacts, error) {
	ctx, cancel := context.WithTimeout(context.Background(), logindCallTimeout)
	defer cancel()
	conn, err := logindConn(ctx)
	if err != nil {
		return useridentity.SessionFacts{}, err
	}
	var path dbus.ObjectPath
	if err := conn.Object(logindService, logindPath).CallWithContext(ctx, logindGetSession, 0, id).Store(&path); err != nil {
		if dbusErrorName(err) == "org.freedesktop.login1.NoSuchSession" {
			return useridentity.SessionFacts{}, errSessionNotOwned
		}
		return useridentity.SessionFacts{}, err
	}
	var props map[string]dbus.Variant
	if err := conn.Object(logindService, path).CallWithContext(ctx, "org.freedesktop.DBus.Properties.GetAll", 0, logindSessionIface).Store(&props); err != nil {
		return useridentity.SessionFacts{}, err
	}
	if sessionUser(props["User"]) != uid {
		return useridentity.SessionFacts{}, errSessionNotOwned
	}
	remote, _ := props["Remote"].Value().(bool)
	remoteHost, _ := props["RemoteHost"].Value().(string)
	service, _ := props["Service"].Value().(string)
	tty, _ := props["TTY"].Value().(string)
	kind, _ := props["Type"].Value().(string)
	facts := useridentity.SessionFacts{LogindSession: id, Assurance: useridentity.AssuranceVerified}
	switch {
	case remote && service == "sshd":
		facts.Kind = useridentity.SessionSSH
	case remote && strings.Contains(service, "xrdp"):
		facts.Kind = useridentity.SessionRDP
	case !remote && kind == "tty":
		facts.Kind = useridentity.SessionConsole
	case !remote && (kind == "x11" || kind == "wayland" || kind == "mir"):
		facts.Kind = useridentity.SessionLocal
	}
	if remote {
		if ip := net.ParseIP(strings.TrimSpace(remoteHost)); ip != nil {
			facts.ClientAddr = ip.String()
		}
	}
	if tty = strings.TrimPrefix(strings.TrimSpace(tty), "/dev/"); tty != "" && len(tty) <= maxClaimedTTYLength {
		facts.TTY = tty
	}
	return facts, nil
}

func dbusErrorName(err error) string {
	var value dbus.Error
	if errors.As(err, &value) {
		return value.Name
	}
	var pointer *dbus.Error
	if errors.As(err, &pointer) && pointer != nil {
		return pointer.Name
	}
	return ""
}

// sessionUser decodes logind's User property, a (uo) struct.
func sessionUser(v dbus.Variant) int {
	switch value := v.Value().(type) {
	case []interface{}:
		if len(value) >= 1 {
			if uid, ok := value[0].(uint32); ok {
				return int(uid)
			}
		}
	}
	return -1
}

// utmpSessionFacts confirms a claimed terminal from /run/utmp: a login
// record on that line for the peer's account.
func utmpSessionFacts(tty, name string) (useridentity.SessionFacts, error) {
	return utmpSessionFactsFrom(utmpSessionPath, tty, name)
}

func utmpSessionFactsFrom(path, tty, name string) (useridentity.SessionFacts, error) {
	file, err := os.Open(path)
	if err != nil {
		return useridentity.SessionFacts{}, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, utmpMaxBytes))
	if err != nil {
		return useridentity.SessionFacts{}, err
	}
	for _, entry := range parseUtmp(data, binary.NativeEndian) {
		if entry.Line != tty || entry.User != name {
			continue
		}
		facts := useridentity.SessionFacts{TTY: tty, Assurance: useridentity.AssuranceVerified}
		if entry.Host != "" {
			facts.Kind = useridentity.SessionSSH
			if entry.Addr != nil && !entry.Addr.IsUnspecified() {
				facts.ClientAddr = entry.Addr.String()
			} else if ip := net.ParseIP(entry.Host); ip != nil {
				facts.ClientAddr = ip.String()
			}
		} else if strings.HasPrefix(tty, "tty") {
			facts.Kind = useridentity.SessionConsole
		}
		return facts, nil
	}
	return useridentity.SessionFacts{}, nil
}
