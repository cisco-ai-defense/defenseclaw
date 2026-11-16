// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/inventory/ideplugins"
)

// IDEAppDataSpoolDirName is the folder, beside the identity spool, where the
// managed Windows enumerator publishes the IDE inventory of each enrolled
// account whose AppData folder redirection moved: the gateway service is
// granted the AppData folders inside the profile only, so the enumerator,
// which runs as LocalSystem, reads that account's IDEs with the scan's own
// confinement and publishes them where the gateway can read them
// (GAP-1249).
const IDEAppDataSpoolDirName = "ide-appdata"

// IDEAppDataSpoolRecordVersion is the record format version.
const IDEAppDataSpoolRecordVersion = 1

const maxIDEAppDataSpoolRecordBytes = 16 << 20

// IDEAppDataSpoolRecord is the IDE inventory of one account whose roaming
// or local AppData is redirected.
type IDEAppDataSpoolRecord struct {
	Version int `json:"version"`
	// Key is the SID of the account; it must match the file name.
	Key  string `json:"key"`
	Home string `json:"home"`
	// RoamingAppData and LocalAppData are the redirected folders the scan
	// read, "" for one that is not redirected.
	RoamingAppData string               `json:"roaming_app_data,omitempty"`
	LocalAppData   string               `json:"local_app_data,omitempty"`
	UpdatedAt      time.Time            `json:"updated_at"`
	Installs       []ideplugins.Install `json:"installs"`
}

// IDEAppDataSpoolDir is the spool folder below the hook guardian
// authorization folder.
func IDEAppDataSpoolDir(authorizationDir string) string {
	if strings.TrimSpace(authorizationDir) == "" {
		return ""
	}
	return filepath.Join(authorizationDir, IDEAppDataSpoolDirName)
}

// ReadIDEAppDataSpool returns the record published for sid, after trust
// (when set) validates the record file.
func ReadIDEAppDataSpool(dir, sid string, trust func(path, label string) error) (IDEAppDataSpoolRecord, error) {
	var record IDEAppDataSpoolRecord
	key := strings.ToUpper(strings.TrimSpace(sid))
	if dir == "" || !strings.HasPrefix(key, "S-1-") || !validIdentitySpoolKey(key) {
		return record, os.ErrNotExist
	}
	file := filepath.Join(dir, key+".json")
	info, err := os.Lstat(file)
	if err != nil {
		return record, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxIDEAppDataSpoolRecordBytes {
		return record, errors.New("ide appdata spool record is not a regular file within the size limit")
	}
	if trust != nil {
		if err := trust(file, "ide appdata spool record"); err != nil {
			return record, err
		}
	}
	f, err := os.Open(file)
	if err != nil {
		return record, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxIDEAppDataSpoolRecordBytes+1))
	if err != nil {
		return record, err
	}
	if len(data) > maxIDEAppDataSpoolRecordBytes {
		return record, errors.New("ide appdata spool record exceeds the size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return IDEAppDataSpoolRecord{}, fmt.Errorf("parse ide appdata spool record: %w", err)
	}
	if record.Version != IDEAppDataSpoolRecordVersion {
		return IDEAppDataSpoolRecord{}, fmt.Errorf("unsupported ide appdata spool record version %d", record.Version)
	}
	if !strings.EqualFold(record.Key, key) {
		return IDEAppDataSpoolRecord{}, errors.New("ide appdata spool record names another account")
	}
	return record, nil
}

// RedirectedAppDataFolder returns the folder a User Shell Folders value
// (AppData or Local AppData, as the account's registry holds it) names for
// the profile home of user, or "" when it is the profile's own defaultRel
// folder or names nothing. %USERPROFILE% and %USERNAME% are expanded with
// the account's values; no other variable is, since the enumerator's own
// environment is not the account's. refused says why a value is not used:
// a network or device path (AppData on a file share is not inventoried:
// the enumerator would read it as the computer account), another variable,
// or no absolute local path.
func RedirectedAppDataFolder(value, home, user, defaultRel string) (folder, refused string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", ""
	}
	value = replaceFoldVariable(value, "%USERPROFILE%", strings.TrimRight(strings.TrimSpace(home), `\`))
	if _, bare, ok := strings.Cut(user, `\`); ok {
		user = bare
	}
	value = replaceFoldVariable(value, "%USERNAME%", strings.TrimSpace(user))
	switch {
	case strings.Contains(value, "%"):
		return "", "names an environment variable other than USERPROFILE or USERNAME"
	case strings.HasPrefix(value, `\\`) || strings.HasPrefix(value, "//"):
		return "", "is a network or device path; AppData on a network share is not inventoried"
	}
	if folder, refused = windowsAbsoluteFolder(value, false); refused != "" {
		return "", refused
	}
	if strings.EqualFold(folder, windowsCleanPath(strings.TrimSpace(home)+`\`+defaultRel)) {
		return "", ""
	}
	return folder, ""
}

// windowsAbsoluteFolder cleans an absolute Windows folder path, on any
// platform: a drive path, and when network is set also a share path
// (\\server\share\...) and the \\?\ and \\.\ forms of either. A ".." never
// climbs above the drive or the share. refused says why value is not one.
func windowsAbsoluteFolder(value string, network bool) (folder, refused string) {
	value = strings.ReplaceAll(strings.TrimSpace(value), "/", `\`)
	if network && strings.HasPrefix(value, `\\`) {
		share := value[2:]
		if len(share) >= 2 && (share[0] == '?' || share[0] == '.') && share[1] == '\\' {
			share = share[2:]
			if len(share) < 4 || !asciiEqualFold(share[:4], `UNC\`) {
				// \\?\D:\... is the drive path; any other device is no folder.
				if folder, refused = windowsAbsoluteFolder(share, false); refused != "" {
					return "", "is a device path, not a folder"
				}
				return folder, ""
			}
			share = share[4:]
		}
		server, rest, _ := strings.Cut(share, `\`)
		name, rest, _ := strings.Cut(rest, `\`)
		for _, part := range []string{server, name} {
			if part == "" || part == "." || part == ".." || strings.ContainsAny(part, `:*?"<>|`) {
				return "", `is not a share path (\\server\share\folder)`
			}
		}
		folder = `\\` + server + `\` + name
		if cleaned := path.Clean("/" + strings.ReplaceAll(rest, `\`, "/")); cleaned != "/" {
			folder += strings.ReplaceAll(cleaned, "/", `\`)
		}
		return folder, ""
	}
	if len(value) < 3 || !isASCIIDriveLetter(value[0]) || value[1] != ':' || value[2] != '\\' {
		return "", "is not an absolute local path"
	}
	folder = windowsCleanPath(value)
	if len(folder) < 3 || folder[1] != ':' || folder[2] != '\\' {
		// ".." above the drive root leaves no absolute path.
		return "", "is not an absolute local path"
	}
	return folder, ""
}

// replaceFoldVariable replaces each ASCII-case-insensitive occurrence of
// variable (upper-case ASCII) in value with with. It compares bytes, so a
// value whose other characters change length when upper-cased cannot shift
// the match, and with is not searched again.
func replaceFoldVariable(value, variable, with string) string {
	var out strings.Builder
	for i := 0; i < len(value); {
		if i+len(variable) <= len(value) && asciiEqualFold(value[i:i+len(variable)], variable) {
			out.WriteString(with)
			i += len(variable)
			continue
		}
		out.WriteByte(value[i])
		i++
	}
	return out.String()
}

func asciiEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if 'a' <= x && x <= 'z' {
			x -= 'a' - 'A'
		}
		if 'a' <= y && y <= 'z' {
			y -= 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

func isASCIIDriveLetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// windowsCleanPath cleans a drive path the way Windows reads it, on any
// platform.
func windowsCleanPath(p string) string {
	return strings.ReplaceAll(path.Clean(strings.ReplaceAll(p, `\`, "/")), "/", `\`)
}

// ideAppDataDue is a profile whose record a cycle reads again: name is its
// spool file, published the time of its current record, zero when it has
// none.
type ideAppDataDue struct {
	name      string
	published time.Time
}

// scanIDEAppDataDue reads the due profiles, the one without a record first
// and then the oldest record first, until spent reports the cycle's budget
// used. publish reads and writes one profile's record and reports whether
// it wrote it. It returns, by name, whether each due profile keeps a
// record: one it published, or one not read in this cycle that has a
// current record. Reading the oldest first lets the budget reach every
// profile in turn; in the manifest's order, the first profiles took it
// every time they were due again and the last ones were never read
// (GAP-1249).
func scanIDEAppDataDue(due []ideAppDataDue, spent func() bool, publish func(ideAppDataDue) bool) map[string]bool {
	ordered := append([]ideAppDataDue(nil), due...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].published.Before(ordered[j].published) })
	keep := make(map[string]bool, len(ordered))
	for _, item := range ordered {
		if spent() {
			keep[item.name] = !item.published.IsZero()
			continue
		}
		keep[item.name] = publish(item)
	}
	return keep
}
