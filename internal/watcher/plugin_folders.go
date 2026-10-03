package watcher

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Plugin roots outside Claude Code hold plugins flat (<root>/<name>) or in
// category folders (<root>/<category>/<name>, Hermes plugins_discovery
// scan_directory). The live watcher used to admit every new direct child as
// one plugin, so a category folder was scanned as a plugin, refused by the
// scanner ("a folder of N plugins") and quarantined fail-closed with the
// plugins in it, and a still-empty folder was rejected and quarantined at
// once (GAP-2449). The rescan path already expands category folders
// (GAP-2411); these helpers give the live path the same view.

// pluginRootDepth returns the plugin root that holds path and how many levels
// below it path is (1 = <root>/<name>, 2 = <root>/<category>/<name>).
func (w *InstallWatcher) pluginRootDepth(path string) (string, int) {
	if watcherConnectorName(w.cfg) == "claudecode" {
		return "", 0
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", 0
	}
	for _, root := range w.pluginDirs {
		rootAbs, err := filepath.Abs(root)
		if err != nil {
			continue
		}
		rel, err := filepath.Rel(rootAbs, abs)
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		return root, len(strings.Split(rel, string(filepath.Separator)))
	}
	return "", 0
}

// waitForPluginFolder watches dir so that content or plugins added to it
// later reach admission (Run sets addWatch; it is nil in unit tests).
func (w *InstallWatcher) waitForPluginFolder(dir string) {
	if w.pluginWaiting == nil {
		w.pluginWaiting = make(map[string]struct{})
	}
	w.pluginWaiting[filepath.Clean(dir)] = struct{}{}
	if w.addWatch != nil {
		w.addWatch(dir)
	}
}

// waitingPluginEvent maps an fsnotify event below a plugin folder the watcher
// is waiting on to the path to admit: a new folder in a category folder is a
// plugin of its own; anything else re-checks the waiting folder.
func (w *InstallWatcher) waitingPluginEvent(path string) (string, bool) {
	parent := filepath.Clean(filepath.Dir(path))
	if _, ok := w.pluginWaiting[parent]; !ok {
		return "", false
	}
	if _, depth := w.pluginRootDepth(parent); depth == 1 {
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			if skipPluginChildDir(filepath.Base(path)) {
				return "", false
			}
			return path, true
		}
		// A file next to the plugins of a category folder changes none of
		// them; don't admit them all again.
		if len(pluginFolderChildren(parent)) > 0 {
			return "", false
		}
	}
	return parent, true
}

// pluginFolderEvents returns the admission events for a folder in a plugin
// root, or ok=false when path is not one. A folder with a manifest or with
// files is one plugin. A folder of plugins (a category folder) yields its
// plugins, named as "plugin list" names them. A folder with nothing to load
// yet (empty, only sub-folders, or a nested folder without its manifest) is
// watched instead of admitted.
func (w *InstallWatcher) pluginFolderEvents(path string) ([]InstallEvent, bool) {
	root, depth := w.pluginRootDepth(path)
	if depth < 1 || depth > 2 {
		return nil, false
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return nil, false
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, false
	}
	name := filepath.Base(path)
	if depth == 2 {
		category := filepath.Base(filepath.Dir(path))
		if !w.hermesBareCategory(root, category) {
			name = category + "/" + name
		}
	}
	plugin := []InstallEvent{{
		Type: InstallPlugin, Name: name, Path: path,
		Connector: watcherConnectorName(w.cfg), Timestamp: time.Now().UTC(),
	}}
	if hasPluginManifest(path) {
		delete(w.pluginWaiting, filepath.Clean(path))
		return plugin, true
	}
	if depth == 2 {
		// Hermes loads <root>/<category>/<name> only with its plugin.yaml:
		// admit it when the manifest lands.
		w.waitForPluginFolder(path)
		return []InstallEvent{}, true
	}
	var dirs []string
	files := false
	for _, e := range entries {
		if e.IsDir() {
			if !skipPluginChildDir(e.Name()) && !strings.HasPrefix(e.Name(), "_") {
				dirs = append(dirs, filepath.Join(path, e.Name()))
			}
			continue
		}
		files = true
	}
	if files && len(pluginFolderChildren(path)) == 0 {
		delete(w.pluginWaiting, filepath.Clean(path))
		return plugin, true
	}
	w.waitForPluginFolder(path)
	out := []InstallEvent{}
	for _, dir := range dirs {
		if w.isOwnPlugin(dir) {
			continue
		}
		children, _ := w.pluginFolderEvents(dir)
		out = append(out, children...)
	}
	return out, true
}
