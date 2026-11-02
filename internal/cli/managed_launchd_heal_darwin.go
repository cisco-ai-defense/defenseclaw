//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// LaunchDaemon labels of the managed services.
const (
	managedGatewayLabel    = "com.cisco.secureclient.defenseclaw"
	managedGuardianLabel   = managedGatewayLabel + ".hook-guardian"
	managedEnumeratorLabel = managedGatewayLabel + ".hook-enumerator"
)

// Fixed macOS locations, replaced in tests.
var (
	managedLaunchDaemonsDir = "/Library/LaunchDaemons"
	managedLogDir           = "/Library/Logs/Cisco/SecureClient/DefenseClaw"
	launchctlCommandTimeout = 10 * time.Second
	// managedPeerAbsentGrace is how long a peer must stay unloaded, or its
	// plist missing, before it is bootstrapped or restored. The installer
	// and the uninstaller boot the services out one after another; the
	// grace keeps a healer from racing them back in.
	managedPeerAbsentGrace = 90 * time.Second
	// managedLaunchdHealInterval throttles the heal to once per interval
	// however often the guardian passes.
	managedLaunchdHealInterval = 30 * time.Second
	// managedBackgroundItemsTTL is how long a Background Items reading is
	// reused; sfltool is slow.
	managedBackgroundItemsTTL = 15 * time.Minute
	// managedLogRotateSize is the size at which a service log is rotated.
	managedLogRotateSize  int64 = 10 << 20
	managedLogGenerations       = 3

	launchctlRunner = runLaunchctl
	btmDumpRunner   = runSfltoolDumpBTM
	managedHealNow  = time.Now
)

// managedLaunchdPeer is one LaunchDaemon a service heals.
type managedLaunchdPeer struct {
	label string
}

func (peer managedLaunchdPeer) plistPath() string {
	return filepath.Join(managedLaunchDaemonsDir, peer.label+".plist")
}

// managedLaunchdPeersFor returns the jobs role heals: the guardian heals the
// gateway and the enumerator, the gateway heals the guardian. Neither can
// heal its own plist once launchd refuses it at boot.
func managedLaunchdPeersFor(role managedServiceRole) []managedLaunchdPeer {
	switch role {
	case managedServiceGuardian:
		return []managedLaunchdPeer{{label: managedGatewayLabel}, {label: managedEnumeratorLabel}}
	case managedServiceGateway:
		return []managedLaunchdPeer{{label: managedGuardianLabel}}
	}
	return nil
}

// managedLogNamesFor returns the log files role rotates: its own, and for the
// guardian also the short-lived enumerator's.
func managedLogNamesFor(role managedServiceRole) []string {
	switch role {
	case managedServiceGuardian:
		return []string{"hook-guardian.log", "hook-guardian.err.log", "hook-enumerator.log", "hook-enumerator.err.log"}
	case managedServiceGateway:
		return []string{"gateway.log", "gateway.err.log"}
	}
	return nil
}

// managedLogFiles are the log files launchd and the installer write in the
// shared log folder.
var managedLogFiles = []string{
	"gateway.log", "gateway.err.log",
	"hook-guardian.log", "hook-guardian.err.log",
	"hook-enumerator.log", "hook-enumerator.err.log",
	"install.log", "uninstall.log",
}

// managedLaunchdHealState is what the heal remembers between passes.
type managedLaunchdHealState struct {
	mu          sync.Mutex
	lastHeal    time.Time
	absentSince map[string]time.Time
	btmChecked  time.Time
	btmDisabled map[string]bool
}

var managedLaunchdHeal = &managedLaunchdHealState{}

// healManagedLaunchdPlatform heals what launchd needs to start the peer
// services: the shared log folder and its log files, the peers' plists
// (owner, mode, flags, ACL and, against the installer's canonical copy,
// content), a disabled override, and a job that is not loaded. It also
// rotates role's own logs. At most one heal runs per interval.
func healManagedLaunchdPlatform(role managedServiceRole, layout managed.ManagedServiceLayout) {
	state := managedLaunchdHeal
	state.mu.Lock()
	defer state.mu.Unlock()
	now := managedHealNow()
	if !state.lastHeal.IsZero() && now.Sub(state.lastHeal) < managedLaunchdHealInterval {
		return
	}
	state.lastHeal = now

	healManagedLogFolder()
	rotateManagedLogs(managedLogNamesFor(role))

	peers := managedLaunchdPeersFor(role)
	if len(peers) == 0 {
		return
	}
	disabled, disabledKnown := launchctlDisabledLabels()
	btm := state.backgroundItemsDisabled(now)
	for _, peer := range peers {
		state.healPeer(peer, layout, now, disabled, disabledKnown, btm)
	}
}

func (state *managedLaunchdHealState) absentFor(key string, absent bool, now time.Time) time.Duration {
	if state.absentSince == nil {
		state.absentSince = map[string]time.Time{}
	}
	if !absent {
		delete(state.absentSince, key)
		return 0
	}
	since, ok := state.absentSince[key]
	if !ok {
		state.absentSince[key] = now
		return 0
	}
	return now.Sub(since)
}

func (state *managedLaunchdHealState) healPeer(
	peer managedLaunchdPeer,
	layout managed.ManagedServiceLayout,
	now time.Time,
	disabled map[string]bool,
	disabledKnown bool,
	btm map[string]bool,
) {
	plist := peer.plistPath()
	_, statErr := os.Lstat(plist)
	missing := errors.Is(statErr, os.ErrNotExist)
	if !missing {
		managed.RepairOwnedObject(managed.OwnedObject{
			Path: plist, Kind: managed.ObjectAdminFile, Mode: 0o644, MoveAsideStructural: true,
		})
		_, statErr = os.Lstat(plist)
		missing = errors.Is(statErr, os.ErrNotExist)
	}
	if missing && state.absentFor("plist:"+peer.label, true, now) < managedPeerAbsentGrace {
		return
	}
	state.absentFor("plist:"+peer.label, false, now)
	restoreLaunchDaemonPlist(peer, layout)

	if btm[peer.label] {
		managed.EmitResilienceEventOnce(peer.label, managed.MarkerPrereq, map[string]string{
			"check":  "launchd_background_item_disabled",
			"label":  peer.label,
			"remedy": "Allow the DefenseClaw item under System Settings > General > Login Items & Extensions, or allow it with a managed login items profile",
		})
		return
	}
	if disabledKnown && disabled[peer.label] {
		if _, err := launchctlRunner("enable", "system/"+peer.label); err != nil {
			managed.EmitResilienceEventOnce(peer.label, managed.MarkerDegraded, map[string]string{
				"label":  peer.label,
				"reason": "launchctl enable failed: " + err.Error(),
			})
		} else {
			managed.EmitResilienceEvent(managed.MarkerRepair, map[string]string{
				"label":  peer.label,
				"path":   plist,
				"reason": "launchd_disabled_override",
			})
		}
	}
	loaded, known := launchctlLabelLoaded(peer.label)
	if !known {
		return
	}
	if loaded {
		state.absentFor("job:"+peer.label, false, now)
		return
	}
	if state.absentFor("job:"+peer.label, true, now) < managedPeerAbsentGrace {
		return
	}
	if _, err := os.Lstat(plist); err != nil {
		return
	}
	if output, err := launchctlRunner("bootstrap", "system", plist); err != nil {
		managed.EmitResilienceEventOnce(peer.label, managed.MarkerDegraded, map[string]string{
			"label":  peer.label,
			"path":   plist,
			"reason": "launchctl bootstrap failed: " + strings.TrimSpace(err.Error()+" "+string(output)),
		})
		return
	}
	state.absentFor("job:"+peer.label, false, now)
	managed.EmitResilienceEvent(managed.MarkerRepair, map[string]string{
		"label":  peer.label,
		"path":   plist,
		"reason": "launchd job was not loaded; bootstrapped",
	})
}

// managedCanonicalPlist is the installer's copy of a plist and its digest.
type managedCanonicalPlist struct {
	content []byte
	sum     string
}

// readCanonicalLaunchDaemonPlist reads <install>/etc/launchd/<label>.plist
// and checks it against <label>.plist.sha256. A missing or unverifiable copy
// is reported to the caller, never used.
func readCanonicalLaunchDaemonPlist(layout managed.ManagedServiceLayout, label string) (managedCanonicalPlist, string) {
	if layout.Home == "" {
		return managedCanonicalPlist{}, "the managed install root is unknown"
	}
	copyPath := filepath.Join(layout.Home, "etc", "launchd", label+".plist")
	content, err := safefile.ReadRegularFileBounded(copyPath, 1<<20)
	if err != nil {
		return managedCanonicalPlist{}, "canonical copy unavailable: " + err.Error()
	}
	recorded, err := safefile.ReadRegularFileBounded(copyPath+".sha256", 4096)
	if err != nil {
		return managedCanonicalPlist{}, "canonical digest unavailable: " + err.Error()
	}
	fields := strings.Fields(string(recorded))
	if len(fields) == 0 {
		return managedCanonicalPlist{}, "canonical digest is empty"
	}
	want := strings.ToLower(fields[0])
	sum := sha256.Sum256(content)
	got := hex.EncodeToString(sum[:])
	if got != want {
		managed.EmitResilienceEventOnce(copyPath, managed.MarkerBoundary, map[string]string{
			"path":   copyPath,
			"sha256": got,
			"want":   want,
			"reason": "the canonical plist copy does not match its recorded digest; it is not used",
		})
		return managedCanonicalPlist{}, "canonical copy does not match its digest"
	}
	return managedCanonicalPlist{content: content, sum: got}, ""
}

// restoreLaunchDaemonPlist restores a plist whose content differs from the
// installer's canonical copy, or that is missing, and logs the changed keys
// as a boundary finding. Without a verified canonical copy the content is
// left as it is and that is logged once.
func restoreLaunchDaemonPlist(peer managedLaunchdPeer, layout managed.ManagedServiceLayout) {
	plist := peer.plistPath()
	canonical, unavailable := readCanonicalLaunchDaemonPlist(layout, peer.label)
	if unavailable != "" {
		managed.EmitResilienceEventOnce(plist, managed.MarkerAccept, map[string]string{
			"path":   plist,
			"label":  peer.label,
			"reason": "plist content not verified: " + unavailable,
		})
		return
	}
	installed, err := safefile.ReadRegularFileBounded(plist, 1<<20)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return
	}
	if err == nil {
		sum := sha256.Sum256(installed)
		if hex.EncodeToString(sum[:]) == canonical.sum {
			return
		}
	}
	changed := "plist missing"
	if err == nil {
		changed = strings.Join(changedPlistKeys(installed, canonical.content), ",")
	}
	if writeErr := writeLaunchDaemonPlist(plist, canonical.content); writeErr != nil {
		managed.EmitResilienceEventOnce(plist, managed.MarkerDegraded, map[string]string{
			"path":   plist,
			"label":  peer.label,
			"reason": "could not restore the plist from its canonical copy: " + writeErr.Error(),
		})
		return
	}
	managed.EmitResilienceEvent(managed.MarkerBoundary, map[string]string{
		"path":         plist,
		"label":        peer.label,
		"changed_keys": changed,
		"action":       "restored",
		"reason":       "plist content differed from the installer's canonical copy",
	})
}

// writeLaunchDaemonPlist publishes content at path as a new root:wheel 0644
// inode by rename, so whatever was at path is replaced, never written
// through.
func writeLaunchDaemonPlist(path string, content []byte) error {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".defenseclaw-")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := temp.Write(content); err != nil {
		_ = temp.Close()
		return err
	}
	if os.Geteuid() == 0 {
		if err := temp.Chown(0, 0); err != nil {
			_ = temp.Close()
			return err
		}
	}
	if err := temp.Chmod(0o644); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// changedPlistKeys names the top-level plist keys whose values differ
// between installed and canonical, for the boundary line.
func changedPlistKeys(installed, canonical []byte) []string {
	have, haveErr := plistTopLevelValues(installed)
	want, wantErr := plistTopLevelValues(canonical)
	if haveErr != nil || wantErr != nil {
		return []string{"unparseable"}
	}
	var changed []string
	for key, value := range want {
		if have[key] != value {
			changed = append(changed, key)
		}
	}
	for key := range have {
		if _, ok := want[key]; !ok {
			changed = append(changed, key)
		}
	}
	sort.Strings(changed)
	if len(changed) == 0 {
		return []string{"formatting"}
	}
	return changed
}

// plistTopLevelValues maps each key of a property list's top-level dict to
// a normalized rendering of its value.
func plistTopLevelValues(data []byte) (map[string]string, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.Strict = false
	values := map[string]string{}
	depth := 0
	inDict := false
	key := ""
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		switch element := token.(type) {
		case xml.StartElement:
			depth++
			switch {
			case depth == 2 && element.Name.Local == "dict":
				inDict = true
			case inDict && depth == 3 && element.Name.Local == "key":
				var name string
				if err := decoder.DecodeElement(&name, &element); err != nil {
					return nil, err
				}
				depth--
				key = strings.TrimSpace(name)
			case inDict && depth == 3:
				var buffer bytes.Buffer
				if err := renderPlistValue(decoder, element, &buffer); err != nil {
					return nil, err
				}
				depth--
				values[key] = buffer.String()
				key = ""
			}
		case xml.EndElement:
			if depth == 2 && inDict {
				inDict = false
			}
			depth--
		}
	}
	if len(values) == 0 {
		return nil, errors.New("no top-level plist dict")
	}
	return values, nil
}

// renderPlistValue writes start's subtree with insignificant whitespace
// dropped.
func renderPlistValue(decoder *xml.Decoder, start xml.StartElement, out *bytes.Buffer) error {
	out.WriteString("<" + start.Name.Local + ">")
	for {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		switch element := token.(type) {
		case xml.StartElement:
			if err := renderPlistValue(decoder, element, out); err != nil {
				return err
			}
		case xml.CharData:
			out.WriteString(strings.TrimSpace(string(element)))
		case xml.EndElement:
			out.WriteString("</" + element.Name.Local + ">")
			return nil
		}
	}
}

// healManagedLogFolder recreates the shared log folder when it is missing
// (launchd does not create the parent of StandardErrorPath) and re-stamps it
// and the log files in it, clearing uchg and uappnd. A missing Secure Client
// parent folder is created; an existing one is never touched.
func healManagedLogFolder() {
	if !managed.SelfRepairEnabled() {
		return
	}
	for _, parent := range managedLogParents() {
		if _, err := os.Lstat(parent); errors.Is(err, os.ErrNotExist) {
			if err := unix.Mkdir(parent, 0o755); err != nil && !errors.Is(err, unix.EEXIST) {
				managed.EmitResilienceEventOnce(parent, managed.MarkerDegraded, map[string]string{
					"path":   parent,
					"reason": "could not recreate the log folder's parent: " + err.Error(),
				})
				return
			}
		}
	}
	objects := []managed.OwnedObject{{
		Path: managedLogDir, Kind: managed.ObjectLogDirectory, MoveAsideStructural: true, Recreate: true,
	}}
	for _, name := range managedLogFiles {
		objects = append(objects, managed.OwnedObject{
			Path: filepath.Join(managedLogDir, name), Kind: managed.ObjectRuntimeFile, MoveAsideStructural: true,
		})
	}
	managed.RepairOwnedObjects(objects)
}

// managedLogParents lists the folders above the log folder, outermost first,
// up to /Library/Logs, which the OS owns.
func managedLogParents() []string {
	var parents []string
	for dir := filepath.Dir(managedLogDir); dir != filepath.Dir(dir) && dir != "/Library/Logs" && dir != "/Library"; dir = filepath.Dir(dir) {
		parents = append([]string{dir}, parents...)
	}
	return parents
}

// rotateManagedLogs rotates each named log in the log folder once it grows
// past managedLogRotateSize. launchd holds these files open as the
// services' stdout and stderr, so the content is copied to <name>.1 (older
// generations shift up) and the live file is truncated in place.
func rotateManagedLogs(names []string) {
	for _, name := range names {
		path := filepath.Join(managedLogDir, name)
		if err := rotateManagedLog(path); err != nil {
			managed.EmitResilienceEventOnce(path, managed.MarkerDegraded, map[string]string{
				"path":   path,
				"reason": "log rotation failed: " + err.Error(),
			})
		}
	}
}

func rotateManagedLog(path string) error {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < managedLogRotateSize {
		return err
	}
	for generation := managedLogGenerations; generation > 1; generation-- {
		older := fmt.Sprintf("%s.%d", path, generation-1)
		if _, err := os.Lstat(older); err == nil {
			if err := os.Rename(older, fmt.Sprintf("%s.%d", path, generation)); err != nil {
				return err
			}
		}
	}
	temp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".rotate-")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer func() { _ = os.Remove(tempName) }()
	if _, err := io.Copy(temp, io.NewSectionReader(file, 0, info.Size())); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Chmod(0o640); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempName, path+".1"); err != nil {
		return err
	}
	if err := file.Truncate(0); err != nil {
		return err
	}
	managed.EmitResilienceEvent(managed.MarkerRepair, map[string]string{
		"path":   path,
		"reason": fmt.Sprintf("log rotated at %d bytes", info.Size()),
	})
	return nil
}

// launchctlDisabledLabels reads `launchctl print-disabled system`. known is
// false when launchctl could not be run.
func launchctlDisabledLabels() (map[string]bool, bool) {
	output, err := launchctlRunner("print-disabled", "system")
	if err != nil {
		return nil, false
	}
	return parseLaunchctlDisabled(output), true
}

// parseLaunchctlDisabled parses lines of the form `"label" => disabled` (or
// `=> true` on older releases).
func parseLaunchctlDisabled(output []byte) map[string]bool {
	disabled := map[string]bool{}
	for _, line := range strings.Split(string(output), "\n") {
		label, value, ok := strings.Cut(line, "=>")
		if !ok {
			continue
		}
		label = strings.Trim(strings.TrimSpace(label), `"`)
		switch strings.TrimSpace(value) {
		case "disabled", "true":
			disabled[label] = true
		case "enabled", "false":
			disabled[label] = false
		}
	}
	return disabled
}

// launchctlLabelLoaded reports whether label is loaded in the system domain.
// known is false when launchctl failed for a reason other than "not found".
func launchctlLabelLoaded(label string) (loaded, known bool) {
	_, err := launchctlRunner("print", "system/"+label)
	if err == nil {
		return true, true
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 113 {
		return false, true
	}
	return false, false
}

// backgroundItemsDisabled reports the labels Background Task Management has
// switched off. DefenseClaw never overrides that choice; it reports the
// prerequisite. The reading is cached because sfltool is slow.
func (state *managedLaunchdHealState) backgroundItemsDisabled(now time.Time) map[string]bool {
	if state.btmDisabled != nil && now.Sub(state.btmChecked) < managedBackgroundItemsTTL {
		return state.btmDisabled
	}
	output, err := btmDumpRunner()
	if err != nil {
		// Unknown: do not report a prerequisite on a failed read, and keep
		// the previous reading if there is one.
		if state.btmDisabled == nil {
			return map[string]bool{}
		}
		return state.btmDisabled
	}
	state.btmDisabled = parseBackgroundItemsDisabled(output, []string{managedGatewayLabel, managedGuardianLabel, managedEnumeratorLabel})
	state.btmChecked = now
	return state.btmDisabled
}

// parseBackgroundItemsDisabled reads `sfltool dumpbtm` records and reports
// which labels have a record whose disposition is disabled or disallowed. A
// record matches a label by its Identifier or by its plist URL.
func parseBackgroundItemsDisabled(output []byte, labels []string) map[string]bool {
	disabled := map[string]bool{}
	type record struct{ identifier, url, disposition string }
	var records []record
	var current *record
	for _, raw := range strings.Split(string(output), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "#") && strings.HasSuffix(line, ":") {
			records = append(records, record{})
			current = &records[len(records)-1]
			continue
		}
		if current == nil {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.TrimSpace(name) {
		case "Identifier":
			current.identifier = value
		case "URL":
			current.url = value
		case "Disposition":
			current.disposition = value
		}
	}
	for _, rec := range records {
		flags := rec.disposition
		if end := strings.Index(flags, "]"); end >= 0 {
			flags = flags[:end]
		}
		flags = strings.TrimPrefix(flags, "[")
		off := false
		for _, flag := range strings.Split(flags, ",") {
			switch strings.TrimSpace(flag) {
			case "disabled", "disallowed":
				off = true
			}
		}
		for _, label := range labels {
			if rec.identifier == label || strings.HasSuffix(rec.identifier, "."+label) ||
				strings.HasSuffix(rec.url, "/"+label+".plist") {
				disabled[label] = disabled[label] || off
			}
		}
	}
	return disabled
}

func runLaunchctl(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), launchctlCommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/launchctl", args...)
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	output, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return output, fmt.Errorf("launchctl %s timed out after %s", strings.Join(args, " "), launchctlCommandTimeout)
	}
	return output, err
}

func runSfltoolDumpBTM() ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), launchctlCommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/sfltool", "dumpbtm")
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	output, err := cmd.Output()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("sfltool dumpbtm timed out after %s", launchctlCommandTimeout)
	}
	return output, err
}

// startManagedPeerHealPlatform runs the gateway's side of the cross-heal on a
// ticker for the life of the process: the guardian's plist, the shared log
// folder and the gateway's own log rotation.
func startManagedPeerHealPlatform(ctx context.Context, role managedServiceRole) {
	if role != managedServiceGateway || ctx == nil {
		return
	}
	layout, ok := managed.PinnedManagedServiceLayout()
	if !ok || !managed.SelfRepairEnabled() {
		return
	}
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			healManagedLaunchdPlatform(role, layout)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}
