//go:build windows

package zzfsnprobe

import (
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
)

func drain(w *fsnotify.Watcher) {
	for {
		select {
		case _, ok := <-w.Events:
			if !ok {
				return
			}
		case _, ok := <-w.Errors:
			if !ok {
				return
			}
		}
	}
}

// TestRemoveChurnUnderGC adds and removes directory watches while the GC
// runs constantly. PROBE_MODE=remove churns Add/Remove on one watcher;
// PROBE_MODE=close opens, fills and closes a watcher each round.
func TestRemoveChurnUnderGC(t *testing.T) {
	d, _ := time.ParseDuration(os.Getenv("PROBE_DURATION"))
	if d == 0 {
		d = 2 * time.Minute
	}
	mode := os.Getenv("PROBE_MODE")
	debug.SetGCPercent(1)
	root := t.TempDir()
	dirs := make([]string, 16)
	for i := range dirs {
		dirs[i] = filepath.Join(root, "d"+strconv.Itoa(i))
		if err := os.Mkdir(dirs[i], 0o700); err != nil {
			t.Fatal(err)
		}
	}
	var stop atomic.Bool
	sink := make([][]byte, 64)
	go func() {
		for i := 0; !stop.Load(); i++ {
			sink[i%len(sink)] = make([]byte, 208)
			if i%4096 == 0 {
				runtime.GC()
			}
		}
	}()
	defer stop.Store(true)
	newWatcher := func() *fsnotify.Watcher {
		w, err := fsnotify.NewWatcher()
		if err != nil {
			t.Fatal(err)
		}
		go drain(w)
		return w
	}
	deadline := time.Now().Add(d)
	iters := 0
	w := newWatcher()
	for time.Now().Before(deadline) {
		for _, dir := range dirs {
			if err := w.Add(dir); err != nil {
				t.Fatal(err)
			}
		}
		for i, dir := range dirs {
			_ = os.WriteFile(filepath.Join(dir, "f"), []byte(strconv.Itoa(iters+i)), 0o600)
			if mode == "remove" {
				_ = w.Remove(dir)
			}
		}
		if mode == "close" {
			closed := make(chan error, 1)
			go func(w *fsnotify.Watcher) { closed <- w.Close() }(w)
			select {
			case err := <-closed:
				if err != nil {
					t.Fatalf("Close: %v", err)
				}
			case <-time.After(30 * time.Second):
				t.Fatalf("Close did not return within 30s after %d rounds", iters)
			}
			w = newWatcher()
		}
		iters++
	}
	if err := w.Close(); err != nil {
		t.Fatalf("final Close: %v", err)
	}
	t.Logf("mode=%s iterations=%d", mode, iters)
}
