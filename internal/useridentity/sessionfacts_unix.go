// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package useridentity

import (
	"bufio"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	kcmDialTimeout = 200 * time.Millisecond
	// kcmCallTimeout covers a socket-activated sssd-kcm starting after its
	// idle exit, which took about 0.4 s on RHEL 9; a running KCM answers in
	// milliseconds.
	kcmCallTimeout = 2 * time.Second
	krb5ConfPath   = "/etc/krb5.conf"
	maxKrb5Conf    = 256 << 10
)

func currentSessionFactsHeader(now time.Time) string {
	ccname, platformDefault := ccacheNameFromEnv(os.Getenv)
	kind, residual := SplitCCacheName(ccname)
	mtime := ccacheModTime(kind, residual)
	key := strings.Join([]string{
		ccname, mtime, os.Getenv("XDG_SESSION_ID"), os.Getenv("SSH_CONNECTION"), os.Getenv("SSH_TTY"),
	}, "|")
	envKey := SessionFactsEnvKey(os.Getenv)
	cachePath := ""
	if home, err := os.UserHomeDir(); err == nil && filepath.IsAbs(home) {
		cachePath = filepath.Join(home, ".defenseclaw", SessionFactsCacheFileName)
		if header, ok := cachedSessionFactsHeader(cachePath, key, envKey, now); ok {
			return header
		}
	}
	facts := SessionFromSSHEnv(os.Getenv)
	principal, ccType, settled := readDefaultPrincipal(kind, residual)
	if principal == "" && ((ccType != CCacheKeyring && ccType != CCacheAPI) || platformDefault) {
		// No readable cache: report no type rather than the default name's.
		ccType = ""
	}
	facts.KerberosPrincipal, facts.CCacheType = principal, ccType
	if facts.Kind == "" && !facts.Empty() {
		facts.Kind = SessionLocal
	}
	header := EncodeSessionFactsHeader(ClaimedSessionHeader{Session: facts})
	if cachePath != "" {
		written := now
		if !settled {
			// A KCM read that failed in transit is not the session's
			// answer: it is reused for sessionFactsRetryAfter, not the TTL.
			written = now.Add(sessionFactsRetryAfter - SessionFactsCacheTTL)
		}
		_ = writeSessionFactsCache(cachePath, key, envKey, header, written)
	}
	return header
}

// ccacheNameFromEnv is KRB5CCNAME, else the krb5.conf default_ccache_name,
// else the platform default (API: on macOS, FILE:/tmp/krb5cc_<uid>
// elsewhere); platformDefault reports the last case. KEYRING: and API:
// caches cannot be read, so their type is reported only when the user or
// the administrator named them.
func ccacheNameFromEnv(getenv func(string) string) (name string, platformDefault bool) {
	if name := strings.TrimSpace(getenv("KRB5CCNAME")); name != "" {
		return name, false
	}
	if name := krb5ConfDefaultCCacheName(krb5ConfPath, 0); name != "" {
		return expandCCacheName(name), false
	}
	if runtime.GOOS == "darwin" {
		return "API:", true
	}
	return "FILE:/tmp/krb5cc_" + strconv.Itoa(os.Getuid()), true
}

// krb5ConfDefaultCCacheName reads default_ccache_name from the [libdefaults]
// section of a krb5.conf and the files it includes, in reading order. Like
// MIT for a single-valued relation, the first value found wins.
func krb5ConfDefaultCCacheName(path string, depth int) string {
	if depth > 3 {
		return ""
	}
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()
	scanner := bufio.NewScanner(io.LimitReader(file, maxKrb5Conf))
	section := ""
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if strings.HasPrefix(line, "includedir ") {
			dir := strings.TrimSpace(strings.TrimPrefix(line, "includedir "))
			entries, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				if !krb5IncludeName(entry.Name()) {
					continue
				}
				if name := krb5ConfDefaultCCacheName(filepath.Join(dir, entry.Name()), depth+1); name != "" {
					return name
				}
			}
			continue
		}
		if strings.HasPrefix(line, "include ") {
			if name := krb5ConfDefaultCCacheName(strings.TrimSpace(strings.TrimPrefix(line, "include ")), depth+1); name != "" {
				return name
			}
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.Trim(line, "[] ")
			continue
		}
		if section != "libdefaults" {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if found && strings.TrimSpace(key) == "default_ccache_name" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// krb5IncludeName mirrors MIT's includedir filter: names of letters,
// digits, dashes and underscores, or ending in .conf.
func krb5IncludeName(name string) bool {
	if strings.HasSuffix(name, ".conf") {
		return true
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return name != ""
}

// expandCCacheName expands the krb5.conf tokens a default ccache name uses.
func expandCCacheName(name string) string {
	uid := strconv.Itoa(os.Getuid())
	replacer := strings.NewReplacer(
		"%{uid}", uid, "%{euid}", strconv.Itoa(os.Geteuid()), "%{USERID}", uid,
		"%{TEMP}", os.TempDir(), "%{null}", "",
	)
	return replacer.Replace(name)
}

func ccacheModTime(kind, residual string) string {
	path := ""
	switch kind {
	case CCacheFile:
		path = residual
	case CCacheDir:
		path = strings.TrimPrefix(residual, ":")
	}
	if path == "" {
		return ""
	}
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return strconv.FormatInt(info.ModTime().UnixNano(), 10)
}

// readDefaultPrincipal reads the default principal of the named cache. It
// returns the cache type even when the principal cannot be read; settled is
// false when a KCM read failed in transit and may answer on a retry.
func readDefaultPrincipal(kind, residual string) (principal, ccType string, settled bool) {
	switch kind {
	case CCacheFile:
		return readFileCCachePrincipal(residual), CCacheFile, true
	case CCacheDir:
		return readDirCCachePrincipal(residual), CCacheDir, true
	case CCacheKCM:
		principal, settled = readKCMPrincipal(residual)
		return principal, CCacheKCM, settled
	case CCacheKeyring:
		return "", CCacheKeyring, true
	case CCacheAPI:
		return "", CCacheAPI, true
	}
	return "", "", true
}

func readFileCCachePrincipal(path string) string {
	if path == "" || !filepath.IsAbs(path) {
		return ""
	}
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()
	if info, err := file.Stat(); err != nil || !info.Mode().IsRegular() {
		return ""
	}
	principal, err := ParseFileCCachePrincipal(file)
	if err != nil {
		return ""
	}
	return principal
}

// readDirCCachePrincipal handles DIR:<dir> (the collection's primary file
// names the current cache) and DIR::<file> (one cache of a collection).
func readDirCCachePrincipal(residual string) string {
	if strings.HasPrefix(residual, ":") {
		return readFileCCachePrincipal(strings.TrimPrefix(residual, ":"))
	}
	data, err := os.ReadFile(filepath.Join(residual, "primary"))
	if err != nil || len(data) > 256 {
		return ""
	}
	name := strings.TrimSpace(string(data))
	if name == "" || strings.ContainsAny(name, "/\\") {
		return ""
	}
	return readFileCCachePrincipal(filepath.Join(residual, name))
}

// readKCMPrincipal asks the first KCM socket that accepts for the default
// principal. No socket accepting settles the answer (no KCM on this host);
// a dial or call that timed out or broke off does not (kcmReadSettled).
func readKCMPrincipal(cacheName string) (principal string, settled bool) {
	settled = true
	for _, socket := range []string{DefaultKCMSocketPath, LegacyKCMSocketPath} {
		conn, err := net.DialTimeout("unix", socket, kcmDialTimeout)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				settled = false
			}
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(kcmCallTimeout))
		principal, err = KCMDefaultPrincipal(conn, cacheName)
		_ = conn.Close()
		if err != nil {
			return "", kcmReadSettled(err)
		}
		return principal, true
	}
	return "", settled
}
