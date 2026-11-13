// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// pruneOldUnnamed is prune with a complete scan that names nothing, long
// after every folder was staged: the folder-shape rules alone decide.
func pruneOldUnnamed(fsys windowsHookImageFS, bin string, keep []string) windowsHookImagePruneReport {
	return pruneWindowsHookImages(fsys, bin, keep, windowsHookImagePrunePolicy{
		Scan: windowsHookImageConfigScan{Named: map[string][]string{}},
		Now:  time.Now(),
	})
}

// timedHookImageFS gives chosen paths a modification time (the stage time
// of a launch folder is its hook image's).
type timedHookImageFS struct {
	*fakeHookImageFS
	times map[string]time.Time
}

type timedHookImageInfo struct {
	fs.FileInfo
	at time.Time
}

func (i timedHookImageInfo) ModTime() time.Time { return i.at }

func (f timedHookImageFS) Lstat(path string) (fs.FileInfo, error) {
	info, err := f.fakeHookImageFS.Lstat(path)
	if err != nil {
		return nil, err
	}
	if at, ok := f.times[strings.ToLower(path)]; ok {
		return timedHookImageInfo{FileInfo: info, at: at}, nil
	}
	return info, nil
}

// threeReleases stages 1.0.10, 1.0.11 and 1.0.12 at the given times and
// returns their folder names.
func threeReleases(t *testing.T, staged [3]time.Time) (timedHookImageFS, [3]string) {
	t.Helper()
	f := timedHookImageFS{fakeHookImageFS: newFakeHookImageFS(), times: map[string]time.Time{}}
	var names [3]string
	for i, release := range []string{"1.0.10", "1.0.11", "1.0.12"} {
		hook, guard := installRelease(f.fakeHookImageFS, release)
		if report := stageRelease(t, f.fakeHookImageFS, hook, guard); !report.OK {
			t.Fatalf("stage %s = %+v", release, report)
		}
		names[i], _ = winpath.EnterpriseHookImageDigest(hook)
		f.times[strings.ToLower(launchDir(hook)+`\defenseclaw-hook.exe`)] = staged[i]
	}
	return f, names
}

func TestHookImagePruneKeepsAFolderAConfigStillNames(t *testing.T) {
	now := time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)
	old := now.Add(-60 * 24 * time.Hour)
	f, names := threeReleases(t, [3]time.Time{old, old.Add(time.Hour), old.Add(2 * time.Hour)})
	report := pruneWindowsHookImages(f, hookImageTestBin, nil, windowsHookImagePrunePolicy{
		Scan: windowsHookImageConfigScan{Named: map[string][]string{names[0]: {`C:\Users\a\.cursor\hooks.json`}}},
		Now:  now,
	})
	if !report.OK || len(report.Removed) != 1 || !strings.HasSuffix(report.Removed[0], names[1]) {
		t.Fatalf("prune = %+v; it must remove only the unnamed old folder", report)
	}
	if len(report.Retained) != 1 || report.Retained[0].Why != `named_by:C:\Users\a\.cursor\hooks.json` {
		t.Fatalf("retained = %+v", report.Retained)
	}
	if _, ok := f.get(winpath.EnterpriseHookImagesRoot(hookImageTestBin) + `\` + names[0]); !ok {
		t.Fatal("prune removed a folder a config still names")
	}
}

func TestHookImagePruneKeepsARecentlySupersededFolder(t *testing.T) {
	now := time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)
	// 1.0.10 staged long ago, superseded by 1.0.11 three days ago (a session
	// started on 1.0.10 may still run); 1.0.12 is current.
	f, names := threeReleases(t, [3]time.Time{now.Add(-90 * 24 * time.Hour), now.Add(-3 * 24 * time.Hour), now.Add(-time.Hour)})
	report := pruneOldUnnamedAt(f, now)
	if !report.OK || len(report.Removed) != 0 || len(report.Retained) != 2 {
		t.Fatalf("prune = %+v; nothing superseded under 14 days ago may go", report)
	}
	if want := "superseded_recently:" + now.Add(-3*24*time.Hour).Format(time.RFC3339); report.Retained[0].Why != want && report.Retained[1].Why != want {
		t.Fatalf("retained = %+v, want one %s", report.Retained, want)
	}
	// 15 days later both may go.
	later := pruneOldUnnamedAt(f, now.Add(15*24*time.Hour))
	if !later.OK || len(later.Removed) != 2 {
		t.Fatalf("prune 15 days later = %+v", later)
	}
	if _, ok := f.get(winpath.EnterpriseHookImagesRoot(hookImageTestBin) + `\` + names[2]); !ok {
		t.Fatal("prune removed the current folder")
	}
}

func pruneOldUnnamedAt(f timedHookImageFS, now time.Time) windowsHookImagePruneReport {
	return pruneWindowsHookImages(f, hookImageTestBin, nil, windowsHookImagePrunePolicy{
		Scan: windowsHookImageConfigScan{Named: map[string][]string{}},
		Now:  now,
	})
}

func TestHookImagePruneRemovesNothingOnAnIncompleteScan(t *testing.T) {
	now := time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)
	old := now.Add(-60 * 24 * time.Hour)
	f, _ := threeReleases(t, [3]time.Time{old, old, old})
	report := pruneWindowsHookImages(f, hookImageTestBin, nil, windowsHookImagePrunePolicy{
		Scan: windowsHookImageConfigScan{Named: map[string][]string{}, Incomplete: []string{`C:\Users\b\.codex\hooks.json: Access is denied.`}},
		Now:  now,
	})
	if !report.OK || len(report.Removed) != 0 || len(report.Retained) != 2 {
		t.Fatalf("prune = %+v; an incomplete scan removes nothing", report)
	}
	if report.Retained[0].Why != "scan_incomplete" || !strings.Contains(strings.Join(report.Notes, "\n"), "scan_incomplete: ") {
		t.Fatalf("prune = %+v", report)
	}
}

func TestHookImageFoldersNamedIn(t *testing.T) {
	body := `{"hooks":{"PreToolUse":[{"command":"\"C:\\Program Files\\Cisco\\DefenseClaw\\bin\\hooks\\0123456789abcdef\\defenseclaw-hook-guard.exe\" ..."}]}}
command = 'C:\Program Files\Cisco\DefenseClaw\bin\hooks\FEDCBA9876543210\defenseclaw-hook.exe hook'
c:/progra~1/cisco/defenseclaw/bin/hooks/aaaaaaaaaaaaaaaa/DefenseClaw-Hook.exe
C:\Program Files\Cisco\Other\bin\hooks\cccccccccccccccc\defenseclaw-hook.exe
hooks\dddddddddddddddd\defenseclaw-hook.exe
C:\Program Files\Cisco\DefenseClaw\bin\hooks\bbbbbbbbbbbbbbbb\other.exe
C:\Program Files\Cisco\DefenseClaw\bin\hooks\.staging-0123456789abcdef0123456789abcdef\defenseclaw-hook.exe
C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`
	// Only an absolute image path of this install's bin counts (the R3
	// family helper): not another install, a relative path, an 8.3 spelling,
	// another file name, a staging folder or the transition image.
	got := strings.Join(windowsHookImageFoldersNamedIn([]byte(body), hookImageTestBin), ",")
	if got != "0123456789abcdef,fedcba9876543210" {
		t.Fatalf("folders named = %s", got)
	}
	read := func(file windowsHookImageConfigFile) ([]byte, error) {
		switch file.Path {
		case `C:\a.json`, `C:\Users\u\.cursor\hooks.json`:
			return []byte(body), nil
		case `C:\held.json`, `C:\Users\u\.codex\hooks.json`:
			return nil, errors.New("The process cannot access the file because it is being used by another process.")
		}
		return nil, fs.ErrNotExist
	}
	scan := scanWindowsHookImageConfigFiles([]windowsHookImageConfigFile{
		{Path: `C:\a.json`}, {Path: `C:\gone.json`}, {Path: `C:\held.json`}, {Path: `C:\A.JSON`},
		{Path: `C:\Users\u\.cursor\hooks.json`, User: true, Home: `C:\Users\u`}, {Path: `C:\Users\u\.codex\hooks.json`, User: true, Home: `C:\Users\u`},
	}, hookImageTestBin, read)
	// A machine file that cannot be read voids the scan; an account file
	// that cannot be read is skipped and voids nothing.
	if len(scan.Named["0123456789abcdef"]) != 2 || len(scan.Incomplete) != 1 || !strings.HasPrefix(scan.Incomplete[0], `C:\held.json: `) ||
		len(scan.Skipped) != 1 || !strings.HasPrefix(scan.Skipped[0], `C:\Users\u\.codex\hooks.json: `) {
		t.Fatalf("scan = %+v", scan)
	}
	if !scan.UserFiles[`c:\users\u\.cursor\hooks.json`] || len(scan.NamedBySystem()["0123456789abcdef"]) != 1 {
		t.Fatalf("account files %v, by system %v", scan.UserFiles, scan.NamedBySystem())
	}
}

type fakeScanEntry struct {
	name string
	mode fs.FileMode
}

func (e fakeScanEntry) Name() string               { return e.name }
func (e fakeScanEntry) IsDir() bool                { return e.mode.IsDir() }
func (e fakeScanEntry) Type() fs.FileMode          { return e.mode.Type() }
func (e fakeScanEntry) Info() (fs.FileInfo, error) { return fakeScanInfo(e), nil }
func (e fakeScanEntry) String() string             { return e.name }

type fakeScanInfo fakeScanEntry

func (i fakeScanInfo) Name() string       { return i.name }
func (i fakeScanInfo) Size() int64        { return 1 }
func (i fakeScanInfo) Mode() fs.FileMode  { return i.mode }
func (i fakeScanInfo) ModTime() time.Time { return time.Time{} }
func (i fakeScanInfo) IsDir() bool        { return i.mode.IsDir() }
func (i fakeScanInfo) Sys() any           { return nil }

// The watched paths of a claudecode target include the machine folder
// C:\Program Files\ClaudeCode\managed-settings.d (review 2 P1-A): it is
// expanded to its regular files instead of being opened as a file, which
// failed on Windows and voided every scan.
func TestHookImageScanExpandsAWatchedFolder(t *testing.T) {
	dropIns := `C:\Program Files\ClaudeCode\managed-settings.d`
	entries := map[string]fs.FileMode{
		dropIns:                              fs.ModeDir,
		`C:\Users\u\.claude\settings.json`:   0,
		`C:\Users\u\.claude\link.json`:       fs.ModeSymlink,
		`C:\Users\u\.claude`:                 fs.ModeDir,
		`C:\ProgramData\Cursor\hooks.json`:   0,
		`C:\ProgramData\Cursor\reparse.json`: fs.ModeIrregular,
	}
	lstat := func(path string) (fs.FileInfo, error) {
		mode, ok := entries[path]
		if !ok {
			return nil, fs.ErrNotExist
		}
		return fakeScanInfo{name: path, mode: mode}, nil
	}
	readDir := func(path string) ([]fs.DirEntry, error) {
		if path != dropIns {
			return nil, errors.New("unexpected folder " + path)
		}
		return []fs.DirEntry{
			fakeScanEntry{"90-defenseclaw.json", 0},
			fakeScanEntry{".defenseclaw-managed-hooks.lock", 0},
			fakeScanEntry{"nested", fs.ModeDir},
			fakeScanEntry{"planted.json", fs.ModeSymlink},
		}, nil
	}
	files, incomplete, skipped := expandWindowsHookImageConfigFiles([]windowsHookImageConfigFile{
		{Path: dropIns},
		{Path: `C:\Users\u\.claude\settings.json`, User: true, Home: `C:\Users\u`},
		{Path: `C:\Users\u\.claude\link.json`, User: true, Home: `C:\Users\u`},
		{Path: `C:\Users\u\.claude\missing.json`, User: true, Home: `C:\Users\u`},
		{Path: `C:\ProgramData\Cursor\hooks.json`},
		{Path: `C:\ProgramData\Cursor\reparse.json`},
		{Path: dropIns},
	}, lstat, readDir, windowsHookImageAccountView(func(_, path string) (fs.FileInfo, []fs.DirEntry, error) {
		info, err := lstat(path)
		return info, nil, err
	}))
	var got []string
	for _, file := range files {
		got = append(got, fmt.Sprintf("%s|%v", file.Path, file.User))
	}
	want := []string{
		dropIns + `\90-defenseclaw.json|false`,
		`C:\Users\u\.claude\settings.json|true`,
		`C:\ProgramData\Cursor\hooks.json|false`,
	}
	if strings.Join(got, ";") != strings.Join(want, ";") {
		t.Fatalf("files = %v, want %v", got, want)
	}
	// A link in a machine folder voids the scan; an account's link is
	// skipped (never read).
	if len(incomplete) != 2 || !strings.Contains(incomplete[0], `planted.json`) || !strings.Contains(incomplete[1], `reparse.json`) {
		t.Fatalf("incomplete = %v", incomplete)
	}
	if len(skipped) != 1 || !strings.Contains(skipped[0], `link.json`) {
		t.Fatalf("skipped = %v", skipped)
	}
}

// retireFixture is a 1.0.10 install with a staged launch set, the
// deployment record of its images and a config scan the test drives.
type retireFixture struct {
	userFiles  map[string]bool
	fs         *fakeHookImageFS
	recorded   map[string]string
	named      []map[string][]string // one per Scan call; the last repeats
	scans      int
	markers    []string
	reconciled int
	restarted  int
	clock      time.Time
}

func newRetireFixture(t *testing.T) *retireFixture {
	t.Helper()
	f := newFakeHookImageFS()
	hook, guard := installRelease(f, "1.0.10")
	if report := stageRelease(t, f, hook, guard); !report.OK {
		t.Fatalf("stage = %+v", report)
	}
	return &retireFixture{fs: f, recorded: map[string]string{"hook": hook, "hook_guard": guard}, clock: time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)}
}

func (r *retireFixture) steps() windowsHookImageRetireSteps {
	return windowsHookImageRetireSteps{
		FS:             r.fs,
		Bin:            hookImageTestBin,
		RecordedSHA256: func(artifact string) (string, error) { return r.recorded[artifact], nil },
		WriteMarker: func(path string, body []byte) error {
			r.markers = append(r.markers, path)
			r.fs.file(path, string(body))
			return nil
		},
		ReconcileCodex:  func() error { r.reconciled++; return nil },
		RestartGuardian: func() error { r.restarted++; return nil },
		Scan: func() windowsHookImageConfigScan {
			index := min(r.scans, len(r.named)-1)
			r.scans++
			return windowsHookImageConfigScan{Named: r.named[index], UserFiles: r.userFiles}
		},
		Now:   func() time.Time { return r.clock },
		Sleep: func(d time.Duration) { r.clock = r.clock.Add(d) },
		Wait:  windowsHookImageRetireWait,
		Poll:  windowsHookImageRetirePoll,
	}
}

func TestHookImageRetireWithNoLaunchFolders(t *testing.T) {
	f := newFakeHookImageFS()
	installRelease(f, "1.0.9")
	r := &retireFixture{fs: f, named: []map[string][]string{{}}}
	report := retireWindowsHookImages(r.steps())
	if !report.OK || len(r.markers) != 0 || r.restarted != 0 {
		t.Fatalf("retire on a 1.0.9 layout = %+v", report)
	}
}

func TestHookImageRetireRefusesATransitionImageThatIsNotRecorded(t *testing.T) {
	r := newRetireFixture(t)
	r.named = []map[string][]string{{}}
	r.fs.file(hookImageTestBin+`\defenseclaw-hook-guard.exe`, "changed guard")
	report := retireWindowsHookImages(r.steps())
	if report.OK || report.Reason != windowsHookImageRetireRefused || len(r.markers) != 0 || r.restarted != 0 {
		t.Fatalf("retire = %+v; it must change nothing", report)
	}
}

func TestHookImageRetireRewritesEveryConfig(t *testing.T) {
	r := newRetireFixture(t)
	folder, _ := winpath.EnterpriseHookImageDigest(r.recorded["hook"])
	files := []string{`C:\ProgramData\OpenAI\Codex\requirements.toml`, `C:\Users\a\.cursor\hooks.json`}
	r.named = []map[string][]string{{folder: files}, {folder: files[1:]}, {}}
	report := retireWindowsHookImages(r.steps())
	if !report.OK || report.Marker == "" || len(r.markers) != 1 || r.reconciled != 1 || r.restarted != 1 {
		t.Fatalf("retire = %+v", report)
	}
	if strings.Join(report.Rewritten, ",") != strings.Join(files, ",") || len(report.StillNamed) != 0 {
		t.Fatalf("rewritten %v still %v", report.Rewritten, report.StillNamed)
	}
	// The writers name the transition set while the marker is there.
	image := winpath.ResolveEnterpriseHookImageWith(r.fs, hookImageTestBin)
	if image.State != winpath.EnterpriseHookImageRetired || image.Hook != hookImageTestBin+`\defenseclaw-hook.exe` ||
		image.Guard != hookImageTestBin+`\defenseclaw-hook-guard.exe` {
		t.Fatalf("resolve after retire = %+v", image)
	}
	if launch := winpath.ResolveEnterpriseHookLaunchSetWith(r.fs, hookImageTestBin); launch.State != winpath.EnterpriseHookImageRetired {
		t.Fatalf("writers resolve %+v after retire", launch)
	}
	// The folders stay for the sessions that still start them.
	if _, ok := r.fs.get(launchDir(r.recorded["hook"]) + `\defenseclaw-hook.exe`); !ok {
		t.Fatal("retire removed a launch image")
	}
	// A repeated retire keeps the marker and still succeeds.
	again := retireWindowsHookImages(r.steps())
	if !again.OK || len(r.markers) != 1 {
		t.Fatalf("second retire = %+v, markers %v", again, r.markers)
	}
}

func TestHookImageRetireIsPendingWhileAConfigStillNamesAFolder(t *testing.T) {
	r := newRetireFixture(t)
	folder, _ := winpath.EnterpriseHookImageDigest(r.recorded["hook"])
	r.named = []map[string][]string{{folder: {`C:\Users\c\.kiro\hooks.json`}}}
	report := retireWindowsHookImages(r.steps())
	if report.OK || report.Reason != windowsHookImageRetirePending || len(report.StillNamed) != 1 ||
		report.StillNamed[0].Folder != folder || report.StillNamed[0].File != `C:\Users\c\.kiro\hooks.json` {
		t.Fatalf("retire = %+v", report)
	}
	if r.scans < 3 {
		t.Fatalf("retire scanned %d times; it must wait for the guardian", r.scans)
	}
}

func TestHookImageStageClearsTheRetireMarker(t *testing.T) {
	r := newRetireFixture(t)
	r.named = []map[string][]string{{}}
	if report := retireWindowsHookImages(r.steps()); !report.OK {
		t.Fatalf("retire = %+v", report)
	}
	again := stageRelease(t, r.fs, r.recorded["hook"], r.recorded["hook_guard"])
	if !again.OK || !strings.Contains(strings.Join(again.Notes, "\n"), "removed the retire marker") {
		t.Fatalf("stage after retire = %+v", again)
	}
	if image := winpath.ResolveEnterpriseHookImageWith(r.fs, hookImageTestBin); image.State != winpath.EnterpriseHookImageStaged {
		t.Fatalf("resolve after the un-retiring stage = %+v", image)
	}
}

func TestHookImageStageKeepsTheMarkerWhenTheStartFails(t *testing.T) {
	r := newRetireFixture(t)
	r.named = []map[string][]string{{}}
	if report := retireWindowsHookImages(r.steps()); !report.OK {
		t.Fatalf("retire = %+v", report)
	}
	failed := stageWindowsHookImage(r.fs, &fakeHookImageStarter{build: hookImageTestBuild, fail: map[string]error{winpath.EnterpriseHookImageName: errors.New("blocked")}},
		windowsHookImageStageRequest{Bin: hookImageTestBin, HookSHA256: r.recorded["hook"], GuardSHA256: r.recorded["hook_guard"], Build: hookImageTestBuild})
	if failed.OK || failed.Reason != windowsHookImageStartFailed {
		t.Fatalf("stage = %+v", failed)
	}
	if image := winpath.ResolveEnterpriseHookImageWith(r.fs, hookImageTestBin); image.State != winpath.EnterpriseHookImageRetired {
		t.Fatalf("a failed stage un-retired: %+v", image)
	}
}

// An account file that still names a folder is the guardian's to rewrite at
// that account's next pass; retire does not wait for it (the older Setup
// reads only machine files) and reports it (review 2 P2-C).
func TestHookImageRetireDoesNotWaitForAnAccountFile(t *testing.T) {
	r := newRetireFixture(t)
	folder, _ := winpath.EnterpriseHookImageDigest(r.recorded["hook"])
	r.userFiles = map[string]bool{`c:\users\c\.kiro\hooks.json`: true}
	r.named = []map[string][]string{{folder: {`C:\Users\c\.kiro\hooks.json`}}}
	report := retireWindowsHookImages(r.steps())
	if !report.OK || len(report.StillNamed) != 0 || !strings.Contains(strings.Join(report.Notes, "\n"), "still_named_by_account_file: "+`C:\Users\c\.kiro\hooks.json`) {
		t.Fatalf("retire = %+v", report)
	}
}

// A writer that failed is in the report's error, not only a note
// (review 2 P3).
func TestHookImageRetireReportsAWriterError(t *testing.T) {
	r := newRetireFixture(t)
	r.named = []map[string][]string{{}}
	steps := r.steps()
	steps.RestartGuardian = func() error { return errors.New("the guardian service did not stop") }
	report := retireWindowsHookImages(steps)
	if !report.OK || !strings.Contains(report.Error, "guardian restart: the guardian service did not stop") {
		t.Fatalf("retire = %+v", report)
	}
	folder, _ := winpath.EnterpriseHookImageDigest(r.recorded["hook"])
	r.named = []map[string][]string{{folder: {`C:\ProgramData\OpenAI\Codex\requirements.toml`}}}
	r.scans = 0
	report = retireWindowsHookImages(steps)
	if report.OK || report.Reason != windowsHookImageRetirePending || !strings.Contains(report.Error, "guardian restart") {
		t.Fatalf("pending retire = %+v", report)
	}
}

// fakeAccountLinks is the decision the Windows account opener makes
// (winpath.OpenBelow's walk from the home's handle) over a table of elements
// and their reparse flags: the first link from the home down is
// winpath.ErrLinkBelowRoot naming it, a missing element fs.ErrNotExist.
func fakeAccountLinks(reparse map[string]bool) func(home, path string) error {
	return func(home, path string) error {
		elements, err := winpath.ElementsBelow(home, path)
		if err != nil {
			return err
		}
		for _, element := range elements {
			value, ok := reparse[strings.ToLower(element)]
			if !ok {
				return fs.ErrNotExist
			}
			if value {
				return fmt.Errorf("%w: %s", winpath.ErrLinkBelowRoot, element)
			}
		}
		return nil
	}
}

// fakeAccountView is viewWindowsHookImageAccountPath over fakes: links
// decides first, then lstat and (for a folder) readDir answer through the
// opened handle.
func fakeAccountView(links func(home, path string) error, lstat func(string) (fs.FileInfo, error), readDir func(string) ([]fs.DirEntry, error)) func(home, path string) (fs.FileInfo, []fs.DirEntry, error) {
	return windowsHookImageAccountView(func(home, path string) (fs.FileInfo, []fs.DirEntry, error) {
		if err := links(home, path); err != nil {
			return nil, nil, err
		}
		info, err := lstat(path)
		if err != nil || !info.IsDir() {
			return info, nil, err
		}
		children, err := readDir(path)
		return info, children, err
	})
}

// GAP-0265: SYSTEM resolves every folder between an account's home and an
// account file with its own rights, so a junction the account made in the
// middle (C:\Users\u\.codex -> anywhere) would point SYSTEM's read outside
// the home. Such a file is skipped (link_in_account_path), before it is
// listed or read, and never makes the scan incomplete; the plain account
// file and the machine files are still read.
func TestHookImageScanSkipsAnAccountFileBehindALink(t *testing.T) {
	home := `C:\Users\u`
	check := fakeAccountLinks(map[string]bool{
		`c:\users\u`:                        false,
		`c:\users\u\.claude`:                false,
		`c:\users\u\.claude\settings.json`:  false,
		`c:\users\u\.codex`:                 true,
		`c:\users\u\.codex\hooks.json`:      false,
		`c:\users\u\.claude\managed`:        true,
		`c:\users\u\.claude\managed\a.json`: false,
	})
	lstat := func(path string) (fs.FileInfo, error) {
		switch strings.ToLower(path) {
		case `c:\users\u\.claude\settings.json`, `c:\users\u\.codex\hooks.json`, `c:\program files\claudecode\managed-settings.json`:
			return fakeScanInfo{name: path}, nil
		case `c:\users\u\.claude\managed`:
			return fakeScanInfo{name: path, mode: fs.ModeDir}, nil
		}
		return nil, fs.ErrNotExist
	}
	readDir := func(path string) ([]fs.DirEntry, error) {
		return nil, errors.New("listed " + path + " behind a link")
	}
	files, incomplete, skipped := expandWindowsHookImageConfigFiles([]windowsHookImageConfigFile{
		{Path: `C:\Program Files\ClaudeCode\managed-settings.json`},
		{Path: home + `\.claude\settings.json`, User: true, Home: home},
		{Path: home + `\.codex\hooks.json`, User: true, Home: home},
		{Path: home + `\.claude\managed`, User: true, Home: home},
		{Path: home + `\.cursor\hooks.json`, User: true, Home: home},
		{Path: `C:\Users\v\.claude\settings.json`, User: true},
	}, lstat, readDir, fakeAccountView(check, lstat, readDir))
	if len(files) != 2 || files[0].Path != `C:\Program Files\ClaudeCode\managed-settings.json` || files[1].Path != home+`\.claude\settings.json` {
		t.Fatalf("files = %+v", files)
	}
	if len(incomplete) != 0 {
		t.Fatalf("an account link made the scan incomplete: %v", incomplete)
	}
	joined := strings.Join(skipped, "\n")
	if len(skipped) != 3 || !strings.Contains(skipped[0], `.codex\hooks.json: link_in_account_path: `) ||
		!strings.Contains(skipped[1], `.claude\managed: link_in_account_path: `) || !strings.Contains(joined, "without an account home") {
		t.Fatalf("skipped = %v", skipped)
	}
	// The reader makes the same decision (the Windows reader opens the file
	// from the home's handle, so a link swapped in after the expansion fails
	// inside the open): it is skipped too.
	body := []byte(`{"command":"C:\\Program Files\\Cisco\\DefenseClaw\\bin\\hooks\\0123456789abcdef\\defenseclaw-hook.exe"}`)
	afterSwap := fakeAccountLinks(map[string]bool{`c:\users\u`: false, `c:\users\u\.claude`: true})
	read := func(file windowsHookImageConfigFile) ([]byte, error) {
		if file.User {
			if err := windowsHookImageAccountPathError(afterSwap(file.Home, file.Path)); err != nil {
				return nil, err
			}
		}
		return body, nil
	}
	scan := scanWindowsHookImageConfigFiles(files, hookImageTestBin, read)
	if len(scan.Incomplete) != 0 || len(scan.Skipped) != 1 || !strings.Contains(scan.Skipped[0], "link_in_account_path") {
		t.Fatalf("scan = %+v", scan)
	}
	if got := scan.Named["0123456789abcdef"]; len(got) != 1 || got[0] != `C:\Program Files\ClaudeCode\managed-settings.json` {
		t.Fatalf("named = %v", scan.Named)
	}
}

// A skipped account file never blocks retire: the report notes it
// (skipped_unsafe: ... link_in_account_path) and retire ends ok when no
// machine file names a folder.
func TestHookImageRetireReportsAnAccountFileBehindALink(t *testing.T) {
	r := newRetireFixture(t)
	r.named = []map[string][]string{{}}
	steps := r.steps()
	scan := steps.Scan
	steps.Scan = func() windowsHookImageConfigScan {
		got := scan()
		got.Skipped = []string{`C:\Users\u\.codex\hooks.json: link_in_account_path: a link (reparse point) lies at or below the root: C:\Users\u\.codex; not read`}
		return got
	}
	report := retireWindowsHookImages(steps)
	if !report.OK || !strings.Contains(strings.Join(report.Notes, "\n"), `skipped_unsafe: C:\Users\u\.codex\hooks.json: link_in_account_path: `) {
		t.Fatalf("retire = %+v", report)
	}
}

// fakeVendorFS is a ProgramData vendor tree: each element (lower case) has
// a mode, an owner flag and, for a folder, its entries; listErr makes a
// folder unlistable. It records each folder listed.
type fakeVendorFS struct {
	modes    map[string]fs.FileMode
	admin    map[string]bool
	children map[string][]fakeScanEntry
	listErr  map[string]error
	// inspectErr makes the owner of an element unreadable (access denied:
	// SYSTEM is not the owner and has no READ_CONTROL on it).
	inspectErr map[string]error
	listed     []string
}

func (f *fakeVendorFS) vendor() windowsHookImageVendorFS {
	return windowsHookImageVendorFS{
		Inspect: func(root, path string) (winpath.BelowInfo, error) {
			if err := f.inspectErr[strings.ToLower(path)]; err != nil {
				return winpath.BelowInfo{}, err
			}
			mode, ok := f.modes[strings.ToLower(path)]
			if !ok {
				return winpath.BelowInfo{}, fs.ErrNotExist
			}
			return winpath.BelowInfo{Link: mode&fs.ModeSymlink != 0, Directory: mode.IsDir(), AdminOwned: f.admin[strings.ToLower(path)]}, nil
		},
		List: func(root, path string) ([]fs.DirEntry, error) {
			key := strings.ToLower(path)
			f.listed = append(f.listed, path)
			if err := f.listErr[key]; err != nil {
				return nil, err
			}
			if f.modes[key]&fs.ModeSymlink != 0 {
				return nil, fmt.Errorf("%w: %s", winpath.ErrLinkBelowRoot, path)
			}
			var out []fs.DirEntry
			for _, child := range f.children[key] {
				out = append(out, child)
			}
			return out, nil
		},
	}
}

func vendorFileLines(files []windowsHookImageConfigFile) string {
	var got []string
	for _, file := range files {
		got = append(got, fmt.Sprintf("%s|%v|%s|%s", file.Path, file.User, file.Home, file.Note))
	}
	return strings.Join(got, "\n")
}

// GAP-0265 P3-a: a standard user can create ProgramData\OpenAI\Codex or
// ProgramData\Cursor when they are absent. A file there is a machine file
// only when it and every folder from ProgramData down to it is owned by
// SYSTEM or Administrators; otherwise it is an account file (read below
// ProgramData), so one the user made unreadable is skipped and does not
// void the scan. Review 5: the folders are listed and inspected from
// ProgramData's handle (never by name), and a junction the user made at
// ProgramData\Cursor is not followed.
func TestHookImageVendorFilesInAUserOwnedFolderAreAccountFiles(t *testing.T) {
	programData := `C:\ProgramData`
	codex := &fakeVendorFS{
		modes: map[string]fs.FileMode{
			`c:\programdata\openai`:                         fs.ModeDir,
			`c:\programdata\openai\codex`:                   fs.ModeDir,
			`c:\programdata\openai\codex\requirements.toml`: 0,
			`c:\programdata\openai\codex\planted.toml`:      0,
			`c:\programdata\openai\codex\x.lock`:            0,
		},
		admin: map[string]bool{
			`c:\programdata\openai`:                         true,
			`c:\programdata\openai\codex`:                   true,
			`c:\programdata\openai\codex\requirements.toml`: true,
			`c:\programdata\openai\codex\x.lock`:            true,
		},
		children: map[string][]fakeScanEntry{
			`c:\programdata\openai\codex`: {{"requirements.toml", 0}, {"planted.toml", 0}, {"x.lock", 0}},
		},
	}
	files, problems := windowsHookImageVendorFiles(programData, programData+`\OpenAI\Codex`, 0, codex.vendor())
	want := strings.Join([]string{
		programData + `\OpenAI\Codex\requirements.toml|false||`,
		programData + `\OpenAI\Codex\planted.toml|true|` + programData + `|not_admin_owned: ` + programData + `\OpenAI\Codex\planted.toml`,
	}, "\n")
	if got := vendorFileLines(files); got != want || len(problems) != 0 {
		t.Fatalf("codex files =\n%s\nwant\n%s\nproblems %v", got, want, problems)
	}

	// A user-made ProgramData\Cursor: everything below it is the account's.
	cursor := &fakeVendorFS{
		modes: map[string]fs.FileMode{
			`c:\programdata\cursor`:                  fs.ModeDir,
			`c:\programdata\cursor\hooks.json`:       0,
			`c:\programdata\cursor\sub`:              fs.ModeDir,
			`c:\programdata\cursor\sub\unknown.json`: 0,
			`c:\programdata\cursor\link.json`:        fs.ModeSymlink,
		},
		admin: map[string]bool{`c:\programdata\cursor\hooks.json`: true},
		children: map[string][]fakeScanEntry{
			`c:\programdata\cursor`:     {{"hooks.json", 0}, {"sub", fs.ModeDir}, {"link.json", fs.ModeSymlink}},
			`c:\programdata\cursor\sub`: {{"unknown.json", 0}},
		},
	}
	files, problems = windowsHookImageVendorFiles(programData, programData+`\Cursor`, 1, cursor.vendor())
	note := `|true|` + programData + `|not_admin_owned: ` + programData + `\Cursor`
	want = strings.Join([]string{
		programData + `\Cursor\hooks.json` + note,
		programData + `\Cursor\sub\unknown.json` + note,
		programData + `\Cursor\link.json` + note,
	}, "\n")
	if got := vendorFileLines(files); got != want || len(problems) != 0 {
		t.Fatalf("cursor files =\n%s\nwant\n%s\nproblems %v", got, want, problems)
	}
	read := func(windowsHookImageConfigFile) ([]byte, error) {
		return nil, errors.New("Access is denied.")
	}
	scan := scanWindowsHookImageConfigFiles(files, hookImageTestBin, read)
	if len(scan.Incomplete) != 0 || len(scan.Skipped) != 3 || !strings.Contains(scan.Skipped[0], `hooks.json (not_admin_owned: C:\ProgramData\Cursor): Access is denied.`) {
		t.Fatalf("scan = %+v", scan)
	}
	// An admin-owned vendor file that cannot be read still voids the scan.
	machine := scanWindowsHookImageConfigFiles([]windowsHookImageConfigFile{{Path: programData + `\OpenAI\Codex\requirements.toml`}}, hookImageTestBin, read)
	if len(machine.Incomplete) != 1 {
		t.Fatalf("machine scan = %+v", machine)
	}
	// Missing vendor folders list nothing and are not a problem.
	if files, problems := windowsHookImageVendorFiles(programData, programData+`\Cursor`, 1, (&fakeVendorFS{}).vendor()); len(files) != 0 || len(problems) != 0 {
		t.Fatalf("missing vendor folder: %v %v", files, problems)
	}
}

// Review 5 P3-1: a junction at ProgramData\Cursor is never listed or
// followed. A user-made one is an account entry (the scan skips it as
// link_in_account_path, never incomplete); one owned by SYSTEM or
// Administrators makes the scan incomplete (link_at_machine_folder): only an
// administrator can make it, and what it points to is not known.
func TestHookImageVendorFolderThatIsALink(t *testing.T) {
	programData := `C:\ProgramData`
	user := &fakeVendorFS{modes: map[string]fs.FileMode{`c:\programdata\cursor`: fs.ModeDir | fs.ModeSymlink}}
	files, problems := windowsHookImageVendorFiles(programData, programData+`\Cursor`, 1, user.vendor())
	if len(problems) != 0 || len(files) != 1 || !files[0].User || files[0].Home != programData || files[0].Path != programData+`\Cursor` {
		t.Fatalf("user link: files %+v problems %v", files, problems)
	}
	// The scan then looks at it as an account path and skips it.
	view := windowsHookImageAccountView(func(home, path string) (fs.FileInfo, []fs.DirEntry, error) {
		return nil, nil, fmt.Errorf("%w: %s", winpath.ErrLinkBelowRoot, path)
	})
	_, incomplete, skipped := expandWindowsHookImageConfigFiles(files, nil, nil, view)
	if len(incomplete) != 0 || len(skipped) != 1 || !strings.Contains(skipped[0], windowsHookImageLinkInAccountPath) {
		t.Fatalf("user link expanded: incomplete %v skipped %v", incomplete, skipped)
	}
	admin := &fakeVendorFS{
		modes: map[string]fs.FileMode{`c:\programdata\cursor`: fs.ModeDir | fs.ModeSymlink},
		admin: map[string]bool{`c:\programdata\cursor`: true},
	}
	files, problems = windowsHookImageVendorFiles(programData, programData+`\Cursor`, 1, admin.vendor())
	if len(files) != 0 || len(problems) != 1 || !strings.Contains(problems[0], windowsHookImageLinkAtMachineFolder) {
		t.Fatalf("admin link: files %+v problems %v", files, problems)
	}
	// The admin link is never opened for listing; the user link only by
	// the handle-relative opener, which refuses it inside the open.
	if len(admin.listed) != 0 {
		t.Fatalf("an admin link was listed: %v", admin.listed)
	}
}

// One subfolder that cannot be listed does not hide its siblings: a machine
// one is a problem (the scan is incomplete), an account one becomes an
// account entry (skipped); the other folders are still listed and read.
func TestHookImageVendorListingGoesOnPastAnUnlistableFolder(t *testing.T) {
	programData := `C:\ProgramData`
	denied := errors.New("Access is denied.")
	vfs := &fakeVendorFS{
		modes: map[string]fs.FileMode{
			`c:\programdata\cursor`:              fs.ModeDir,
			`c:\programdata\cursor\a`:            fs.ModeDir,
			`c:\programdata\cursor\b`:            fs.ModeDir,
			`c:\programdata\cursor\c`:            fs.ModeDir,
			`c:\programdata\cursor\c\hooks.json`: 0,
			`c:\programdata\cursor\d`:            fs.ModeDir,
			`c:\programdata\cursor\d\x.json`:     0,
		},
		admin: map[string]bool{
			`c:\programdata\cursor`:              true,
			`c:\programdata\cursor\a`:            true,
			`c:\programdata\cursor\c`:            true,
			`c:\programdata\cursor\c\hooks.json`: true,
		},
		children: map[string][]fakeScanEntry{
			`c:\programdata\cursor`:   {{"a", fs.ModeDir}, {"b", fs.ModeDir}, {"c", fs.ModeDir}, {"d", fs.ModeDir}},
			`c:\programdata\cursor\c`: {{"hooks.json", 0}},
			`c:\programdata\cursor\d`: {{"x.json", 0}},
		},
		listErr: map[string]error{`c:\programdata\cursor\a`: denied, `c:\programdata\cursor\b`: denied},
	}
	files, problems := windowsHookImageVendorFiles(programData, programData+`\Cursor`, 1, vfs.vendor())
	want := strings.Join([]string{
		programData + `\Cursor\b|true|` + programData + `|not_admin_owned: ` + programData + `\Cursor\b`,
		programData + `\Cursor\c\hooks.json|false||`,
		programData + `\Cursor\d\x.json|true|` + programData + `|not_admin_owned: ` + programData + `\Cursor\d`,
	}, "\n")
	if got := vendorFileLines(files); got != want {
		t.Fatalf("files =\n%s\nwant\n%s", got, want)
	}
	if len(problems) != 1 || !strings.Contains(problems[0], `Cursor\a: Access is denied.`) {
		t.Fatalf("problems = %v", problems)
	}
}

// Review 5 P3-2: an account that can read a machine file can hold it open
// without read sharing. The read is retried, then reported as
// machine_file_busy (the scan is incomplete: nothing is pruned, retire stays
// pending until it is run again).
func TestHookImageMachineFileHeldWithoutSharingIsRetriedThenBusy(t *testing.T) {
	busy := errors.New("The process cannot access the file because it is being used by another process.")
	isBusy := func(err error) bool { return errors.Is(err, busy) }
	var waited []time.Duration
	sleep := func(d time.Duration) { waited = append(waited, d) }
	tries := 0
	body, err := readWindowsHookImageRetryingBusy(func() ([]byte, error) {
		tries++
		if tries < 3 {
			return nil, busy
		}
		return []byte("ok"), nil
	}, isBusy, sleep)
	if err != nil || string(body) != "ok" || tries != 3 || len(waited) != 2 {
		t.Fatalf("released after two tries: %q %v tries %d waited %v", body, err, tries, waited)
	}
	tries, waited = 0, nil
	_, err = readWindowsHookImageRetryingBusy(func() ([]byte, error) { tries++; return nil, busy }, isBusy, sleep)
	if err == nil || !errors.Is(err, busy) || !strings.HasPrefix(err.Error(), windowsHookImageMachineFileBusy+": ") || tries != len(windowsHookImageBusyRetries)+1 {
		t.Fatalf("held: %v after %d tries", err, tries)
	}
	// 1.5 s of waits in all: inside the 5 s per-file timeout of the reader.
	var total time.Duration
	for _, d := range waited {
		total += d
	}
	if total != 1500*time.Millisecond {
		t.Fatalf("retries wait %s, want 1.5s", total)
	}
	// Another error is not retried.
	tries = 0
	if _, err := readWindowsHookImageRetryingBusy(func() ([]byte, error) { tries++; return nil, errors.New("Access is denied.") }, isBusy, sleep); err == nil || tries != 1 {
		t.Fatalf("access denied retried: %v %d", err, tries)
	}
	_, held := readWindowsHookImageRetryingBusy(func() ([]byte, error) { return nil, busy }, isBusy, func(time.Duration) {})
	scan := scanWindowsHookImageConfigFiles([]windowsHookImageConfigFile{{Path: `C:\Program Files\ClaudeCode\managed-settings.json`}}, hookImageTestBin,
		func(windowsHookImageConfigFile) ([]byte, error) { return nil, held })
	if len(scan.Incomplete) != 1 || !strings.Contains(scan.Incomplete[0], `managed-settings.json: machine_file_busy: `) {
		t.Fatalf("busy machine file: %+v", scan)
	}
}

// Review 5 (second re-review): SYSTEM does not get READ_CONTROL on a folder
// or file a standard user made and set the ACL of, so the owner read fails
// with access denied. That must make the entry an account entry (skipped),
// never a problem: a user who runs mkdir ProgramData\Cursor and removes
// everyone else's access would otherwise keep every scan incomplete for good.
func TestHookImageVendorEntryWithAnUnreadableOwnerIsAnAccountEntry(t *testing.T) {
	programData := `C:\ProgramData`
	denied := errors.New("Access is denied.")
	// A user-made folder: the vendor folder itself.
	cursor := &fakeVendorFS{
		modes:      map[string]fs.FileMode{`c:\programdata\cursor`: fs.ModeDir, `c:\programdata\cursor\hooks.json`: 0},
		children:   map[string][]fakeScanEntry{`c:\programdata\cursor`: {{"hooks.json", 0}}},
		inspectErr: map[string]error{`c:\programdata\cursor`: denied},
	}
	files, problems := windowsHookImageVendorFiles(programData, programData+`\Cursor`, 0, cursor.vendor())
	want := programData + `\Cursor\hooks.json|true|` + programData + `|not_admin_owned: ` + programData + `\Cursor (owner unreadable)`
	if got := vendorFileLines(files); got != want || len(problems) != 0 {
		t.Fatalf("user-made folder: files =\n%s\nwant\n%s\nproblems %v", got, want, problems)
	}
	// A file a user dropped into an admin-owned vendor folder.
	codex := &fakeVendorFS{
		modes: map[string]fs.FileMode{
			`c:\programdata\openai`:                         fs.ModeDir,
			`c:\programdata\openai\codex`:                   fs.ModeDir,
			`c:\programdata\openai\codex\requirements.toml`: 0,
			`c:\programdata\openai\codex\planted.toml`:      0,
		},
		admin: map[string]bool{
			`c:\programdata\openai`:                         true,
			`c:\programdata\openai\codex`:                   true,
			`c:\programdata\openai\codex\requirements.toml`: true,
		},
		children:   map[string][]fakeScanEntry{`c:\programdata\openai\codex`: {{"requirements.toml", 0}, {"planted.toml", 0}}},
		inspectErr: map[string]error{`c:\programdata\openai\codex\planted.toml`: denied},
	}
	files, problems = windowsHookImageVendorFiles(programData, programData+`\OpenAI\Codex`, 0, codex.vendor())
	want = strings.Join([]string{
		programData + `\OpenAI\Codex\requirements.toml|false||`,
		programData + `\OpenAI\Codex\planted.toml|true|` + programData + `|not_admin_owned: ` + programData + `\OpenAI\Codex\planted.toml (owner unreadable)`,
	}, "\n")
	if got := vendorFileLines(files); got != want || len(problems) != 0 {
		t.Fatalf("planted file: files =\n%s\nwant\n%s\nproblems %v", got, want, problems)
	}
}
