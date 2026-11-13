// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
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
C:\Program Files\Cisco\DefenseClaw\bin\hooks\bbbbbbbbbbbbbbbb\other.exe
C:\Program Files\Cisco\DefenseClaw\bin\hooks\.staging-0123456789abcdef0123456789abcdef\defenseclaw-hook.exe
C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`
	got := strings.Join(windowsHookImageFoldersNamedIn([]byte(body)), ",")
	if got != "0123456789abcdef,aaaaaaaaaaaaaaaa,fedcba9876543210" {
		t.Fatalf("folders named = %s", got)
	}
	scan := scanWindowsHookImageConfigFiles([]string{`C:\a.json`, `C:\gone.json`, `C:\held.json`, `C:\A.JSON`}, func(path string) ([]byte, error) {
		switch path {
		case `C:\a.json`:
			return []byte(body), nil
		case `C:\held.json`:
			return nil, errors.New("The process cannot access the file because it is being used by another process.")
		}
		return nil, fs.ErrNotExist
	})
	if len(scan.Named["aaaaaaaaaaaaaaaa"]) != 1 || len(scan.Incomplete) != 1 || !strings.HasPrefix(scan.Incomplete[0], `C:\held.json: `) {
		t.Fatalf("scan = %+v", scan)
	}
}

// retireFixture is a 1.0.10 install with a staged launch set, the
// deployment record of its images and a config scan the test drives.
type retireFixture struct {
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
			return windowsHookImageConfigScan{Named: r.named[index]}
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
