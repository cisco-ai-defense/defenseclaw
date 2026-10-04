package watcher

import (
	"os"
	"path/filepath"
	"testing"
)

func pluginEventNames(events []InstallEvent) map[string]string {
	got := map[string]string{}
	for _, evt := range events {
		got[evt.Name] = evt.Path
	}
	return got
}

// GAP-2449: a category folder in a Hermes plugin root is a folder of plugins,
// not a plugin. The live path admits each plugin in it by its "plugin list"
// id instead of scanning (and quarantining) the folder, and an empty folder
// is watched until a plugin lands in it.
func TestLivePluginEventsExpandCategoryAndWaitOnEmptyFolder(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	cfg.Guardrail.Connector = "hermes"
	t.Setenv("HERMES_BUNDLED_PLUGINS", "")
	home := filepath.Dir(skillDir)
	user := filepath.Join(home, "plugins")
	bundled := filepath.Join(home, "hermes-agent", "plugins")
	write := func(dir string, files ...string) {
		t.Helper()
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if err := os.WriteFile(filepath.Join(dir, f), []byte("name: x\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	write(filepath.Join(user, "platforms", "demo"), "plugin.yaml", "__init__.py")
	write(filepath.Join(bundled, "platforms", "a2a"), "plugin.yaml")
	write(filepath.Join(user, "flat"), "__init__.py")
	w := New(cfg, nil, []string{user, bundled}, store, logger, nil, nil)

	if got := pluginEventNames(w.pendingInstallEvents(filepath.Join(user, "platforms"))); len(got) != 1 ||
		got["platforms/demo"] != filepath.Join(user, "platforms", "demo") {
		t.Fatalf("user category folder events = %v, want platforms/demo", got)
	}
	if got := pluginEventNames(w.pendingInstallEvents(filepath.Join(bundled, "platforms"))); len(got) != 1 ||
		got["a2a"] == "" {
		t.Fatalf("bundled platforms events = %v, want a2a", got)
	}
	// Hermes loads a folder only with its manifest (GAP-2471): it waits
	// until plugin.yaml lands, then it is one plugin.
	flat := filepath.Join(user, "flat")
	if events := w.pendingInstallEvents(flat); len(events) != 0 {
		t.Fatalf("flat folder without manifest events = %v, want none", events)
	}
	write(flat, "plugin.yaml")
	if queued, ok := w.waitingPluginEvent(filepath.Join(flat, "plugin.yaml")); !ok || queued != flat {
		t.Fatalf("manifest in waiting flat folder = %q, %v; want %q", queued, ok, flat)
	}
	if got := pluginEventNames(w.pendingInstallEvents(flat)); len(got) != 1 || got["flat"] != flat {
		t.Fatalf("flat plugin events = %v, want flat", got)
	}

	web := filepath.Join(user, "web")
	write(web)
	if events := w.pendingInstallEvents(web); len(events) != 0 {
		t.Fatalf("empty folder events = %v, want none (watched, not admitted)", events)
	}
	nested := filepath.Join(web, "later")
	write(nested)
	if queued, ok := w.waitingPluginEvent(nested); !ok || queued != nested {
		t.Fatalf("new folder in waiting category = %q, %v; want %q", queued, ok, nested)
	}
	if events := w.pendingInstallEvents(nested); len(events) != 0 {
		t.Fatalf("nested folder without manifest events = %v, want none", events)
	}
	write(nested, "plugin.yaml")
	queued, ok := w.waitingPluginEvent(filepath.Join(nested, "plugin.yaml"))
	if !ok || queued != nested {
		t.Fatalf("manifest in waiting folder = %q, %v; want %q", queued, ok, nested)
	}
	if got := pluginEventNames(w.pendingInstallEvents(queued)); len(got) != 1 || got["web/later"] != nested {
		t.Fatalf("nested plugin events = %v, want web/later", got)
	}
	// A file beside the plugins of a category folder re-admits none of them.
	write(web, "README.md")
	if queued, ok := w.waitingPluginEvent(filepath.Join(web, "README.md")); ok {
		t.Fatalf("file in category folder queued %q", queued)
	}
}

// GAP-2462: category folders that already exist when the watcher starts are
// watched like live-created ones, so a plugin added to them later reaches
// admission after a gateway restart.
func TestWatcherStartWaitsOnExistingCategoryFolders(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	cfg.Guardrail.Connector = "hermes"
	t.Setenv("HERMES_BUNDLED_PLUGINS", "")
	home := filepath.Dir(skillDir)
	user := filepath.Join(home, "plugins")
	bundled := filepath.Join(home, "hermes-agent", "plugins")
	write := func(dir string, files ...string) {
		t.Helper()
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if err := os.WriteFile(filepath.Join(dir, f), []byte("name: x\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	write(filepath.Join(user, "web"))
	write(filepath.Join(user, "memx", "later"))
	write(filepath.Join(user, "flat"), "__init__.py")
	write(filepath.Join(user, "manifested"), "plugin.yaml")
	write(filepath.Join(bundled, "platforms", "a2a"), "plugin.yaml")
	w := New(cfg, nil, []string{user, bundled}, store, logger, nil, nil)
	var watched []string
	w.addWatch = func(dir string) { watched = append(watched, dir) }
	w.watchExistingPluginFolders(user)
	w.watchExistingPluginFolders(bundled)

	for _, dir := range []string{
		filepath.Join(user, "web"), filepath.Join(user, "memx"),
		filepath.Join(user, "memx", "later"), filepath.Join(bundled, "platforms"),
		filepath.Join(user, "flat"),
	} {
		if _, ok := w.pluginWaiting[dir]; !ok {
			t.Errorf("%s not watched at start (watched %v)", dir, watched)
		}
	}
	for _, dir := range []string{
		filepath.Join(user, "manifested"), filepath.Join(bundled, "platforms", "a2a"),
	} {
		if _, ok := w.pluginWaiting[dir]; ok {
			t.Errorf("plugin %s watched as a category folder", dir)
		}
	}
	post := filepath.Join(user, "web", "post")
	write(post, "plugin.yaml")
	if queued, ok := w.waitingPluginEvent(post); !ok || queued != post {
		t.Fatalf("new plugin in pre-existing category = %q, %v; want %q", queued, ok, post)
	}
	if got := pluginEventNames(w.pendingInstallEvents(post)); got["web/post"] != post {
		t.Fatalf("events = %v, want web/post", got)
	}
	bundledNew := filepath.Join(bundled, "platforms", "fresh")
	write(bundledNew, "plugin.yaml")
	if queued, ok := w.waitingPluginEvent(bundledNew); !ok || queued != bundledNew {
		t.Fatalf("new bundled platform plugin = %q, %v; want %q", queued, ok, bundledNew)
	}
}

// GAP-2471: a Hermes folder that holds only notes is an empty category, as
// Hermes scan_directory sees it: created live it is watched, not admitted and
// quarantined as a plugin; present at start it is watched too, so a plugin
// added to it later is admitted by its category/name id. The rescan skips it.
func TestHermesNotesOnlyFolderIsACategory(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	cfg.Guardrail.Connector = "hermes"
	t.Setenv("HERMES_BUNDLED_PLUGINS", "")
	user := filepath.Join(filepath.Dir(skillDir), "plugins")
	write := func(dir string, files ...string) {
		t.Helper()
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if err := os.WriteFile(filepath.Join(dir, f), []byte("name: x\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	live := filepath.Join(user, "notesonly")
	write(live, "NOTES.txt")
	atStart := filepath.Join(user, "notes2")
	write(atStart, "NOTES.txt")
	w := New(cfg, nil, []string{user}, store, logger, nil, nil)
	w.addWatch = func(string) {}
	w.watchExistingPluginFolders(user)
	if _, ok := w.pluginWaiting[atStart]; !ok {
		t.Fatalf("notes-only folder at start not watched")
	}
	if events := w.pendingInstallEvents(live); len(events) != 0 {
		t.Fatalf("notes-only folder events = %v, want none (an empty category)", events)
	}
	if _, ok := w.pluginWaiting[live]; !ok {
		t.Fatalf("live notes-only folder not watched")
	}
	for _, target := range w.enumerateTargets() {
		if target.Path == live || target.Path == atStart {
			t.Fatalf("rescan target %s is a category folder", target.Path)
		}
	}
	added := filepath.Join(atStart, "vb14n")
	write(added, "plugin.yaml", "__init__.py")
	queued, ok := w.waitingPluginEvent(added)
	if !ok || queued != added {
		t.Fatalf("plugin in notes-only category = %q, %v; want %q", queued, ok, added)
	}
	if got := pluginEventNames(w.pendingInstallEvents(queued)); len(got) != 1 || got["notes2/vb14n"] != added {
		t.Fatalf("events = %v, want notes2/vb14n", got)
	}
}
