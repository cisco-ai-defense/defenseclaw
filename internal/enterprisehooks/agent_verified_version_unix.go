//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// UnixAgentStamp identifies one installed agent executable without reading
// it: where it is and the file's device, inode, size, modification time and
// change time. The change time cannot be set by an unprivileged process, so
// a replaced or rewritten binary never keeps the stamp it had.
type UnixAgentStamp struct {
	Path     string `json:"path"`
	Dev      uint64 `json:"dev"`
	Ino      uint64 `json:"ino"`
	Size     int64  `json:"size"`
	ModNs    int64  `json:"mod_ns"`
	ChangeNs int64  `json:"change_ns"`
}

// unixAgentStampOf stamps the file path names (a link is followed, so a link
// retargeted at another binary gets another stamp). False when path is not a
// regular file.
func unixAgentStampOf(path string) (UnixAgentStamp, bool) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return UnixAgentStamp{}, false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return UnixAgentStamp{}, false
	}
	return UnixAgentStamp{
		Path: path, Dev: uint64(st.Dev), Ino: uint64(st.Ino), Size: info.Size(),
		ModNs: info.ModTime().UnixNano(), ChangeNs: unixStatChangeNs(st),
	}, true
}

// unixAgentSourceStamp stamps source, the executable a version read ran, when
// it is one of connector's own CLI candidates in home: the executable a failed
// version read names in its reason (UnixAgentUnversionedReasonPrefix), so the
// stamp taken after a read that worked and the stamp of the copy a later
// failed read names are the same kind of thing. False for any other path: a
// version that did not come from a run of the connector's own CLI (package
// metadata, a stamp, a generic alias) is bound to no file. It reads file
// metadata only.
func unixAgentSourceStamp(home, connector, source string) (UnixAgentStamp, bool) {
	probe, ok := unixAgentProbes[strings.ToLower(strings.TrimSpace(connector))]
	if !ok || len(probe.binaries) == 0 || !filepath.IsAbs(source) || filepath.Clean(source) != source {
		return UnixAgentStamp{}, false
	}
	for _, candidate := range unixAgentBinaryCandidates(filepath.Clean(home), probe.binaries[0]) {
		if candidate == source && unixAgentExecutablePresent(candidate) {
			return unixAgentStampOf(candidate)
		}
	}
	return UnixAgentStamp{}, false
}

// unixUnversionedReasonPath is the executable an installed-without-version
// reason names. Empty for a reason that carries anything after the path (a
// copy discovery did not run because other accounts can change it).
func unixUnversionedReasonPath(reason string) string {
	path, ok := strings.CutPrefix(reason, UnixAgentUnversionedReasonPrefix)
	if !ok || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ""
	}
	return path
}

// UnixVerifiedAgentCarryCycles is how many consecutive enumeration cycles a
// version read that worked once is kept for an executable whose stamp has not
// changed, when the read fails again. The read is a bounded run of
// `<cli> --version` as the user; it can fail for a moment while the host is
// busy (an ensure, a gateway restart) with the agent running and unchanged.
// After this many failures in a row the account is reported unverified with
// the reason of the read, so a copy that really stopped answering is not kept
// verified.
const UnixVerifiedAgentCarryCycles = 3

// unixVerifiedAgentsMax bounds the records read back from the state file.
const unixVerifiedAgentsMax = 4096

// UnixAgentOwner is the account identity a verified version belongs to: the
// kernel uid, the home path and the home directory inode. It is the identity
// the enumerator already uses to tell a reused or recreated account from the
// one it enrolled (sameUnixIdentity), so a user name that is deleted and
// created again, or a home that is recreated, never inherits the version an
// earlier account run printed (what a CLI prints can depend on the account
// that runs it). A zero home inode means the inode is unknown, as everywhere
// else in the enumerator (sameUnixIdentity): two unknowns are not the same
// home, so an owner without an inode proves nothing and is never recorded,
// loaded or matched.
type UnixAgentOwner struct {
	UID       int    `json:"uid"`
	Home      string `json:"home"`
	HomeInode uint64 `json:"home_inode,omitempty"`
}

// known is true when the owner names a home by path and by a real inode, the
// only owner two cycles can compare.
func (o UnixAgentOwner) known() bool {
	return o.HomeInode != 0 && filepath.IsAbs(o.Home) && filepath.Clean(o.Home) == o.Home
}

// UnixVerifiedAgent is the last version read that worked for one (user,
// connector), the account identity it was read for and the stamp of the
// executable whose run supplied it.
type UnixVerifiedAgent struct {
	Version  string         `json:"version"`
	Owner    UnixAgentOwner `json:"owner"`
	Stamp    UnixAgentStamp `json:"stamp"`
	Failures int            `json:"failures,omitempty"`
}

func (v UnixVerifiedAgent) valid() bool {
	return ValidUnixAgentVersion(v.Version) && filepath.IsAbs(v.Stamp.Path) && filepath.Clean(v.Stamp.Path) == v.Stamp.Path &&
		v.Owner.known() &&
		v.Failures >= 0 && v.Failures <= UnixVerifiedAgentCarryCycles
}

// carryVerifiedAgentVersions keeps a verified contract across a failed
// version read. For each connector it records the version a read returned
// together with the stamp of the CLI whose run supplied it (sources names that
// executable per connector; a version from anywhere else is recorded against
// no file) and the identity of the account it was read for. When a later read
// finds a CLI installed but prints no version, and that CLI is the same file
// as the one the recorded read ran, for the same uid, home and a known, equal
// home inode, the recorded version stands in, for at most UnixVerifiedAgentCarryCycles cycles in a
// row. A CLI that never supplied a version, a changed or missing file, a
// reason with anything but the bare path, or a connector with no record gets
// no stand-in: it stays unverified, as before. Nothing is marked protected
// that no read ever verified.
func carryVerifiedAgentVersions(state *UnixEnumeratorState, user, home string, owner UnixAgentOwner, connectors []string, versions, reasons, sources map[string]string, logf EnumerationLogger) map[string]string {
	if state == nil {
		return versions
	}
	for _, conn := range connectors {
		conn = strings.ToLower(strings.TrimSpace(conn))
		key := unixRowKey(user, conn)
		if key == "" {
			continue
		}
		if version := versions[conn]; version != "" {
			if stamp, ok := unixAgentSourceStamp(home, conn, sources[conn]); ok && owner.known() && ValidUnixAgentVersion(version) {
				if state.VerifiedAgents == nil {
					state.VerifiedAgents = map[string]UnixVerifiedAgent{}
				}
				state.VerifiedAgents[key] = UnixVerifiedAgent{Version: version, Owner: owner, Stamp: stamp}
			} else {
				delete(state.VerifiedAgents, key)
			}
			continue
		}
		reason := reasons[conn]
		known, recorded := state.VerifiedAgents[key]
		if !recorded {
			continue
		}
		if !owner.known() || known.Owner != owner || !UnixAgentInstalledWithoutVersion(reason) {
			delete(state.VerifiedAgents, key)
			continue
		}
		path := unixUnversionedReasonPath(reason)
		now, ok := unixAgentStampOf(path)
		if path == "" || !ok || now != known.Stamp {
			delete(state.VerifiedAgents, key)
			continue
		}
		if known.Failures >= UnixVerifiedAgentCarryCycles {
			continue
		}
		known.Failures++
		state.VerifiedAgents[key] = known
		if versions == nil {
			versions = map[string]string{}
		}
		versions[conn] = known.Version
		delete(reasons, conn)
		logfSafely(logf, user, "("+user+", "+conn+") version read failed; "+path+" is unchanged since it read "+known.Version+", keeping that version ("+
			strconv.Itoa(known.Failures)+"/"+strconv.Itoa(UnixVerifiedAgentCarryCycles)+")")
	}
	return versions
}
