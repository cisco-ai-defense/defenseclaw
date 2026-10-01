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

// TestRemoveChurnUnderGC adds and removes directory watches while the GC
// runs constantly. A watch removed with a pending ReadDirectoryChangesW
// read becomes unreachable before its aborted completion is dequeued.
func TestRemoveChurnUnderGC(t *testing.T) {
	d, _ := time.ParseDuration(os.Getenv("PROBE_DURATION"))
	if d == 0 {
		d = 2 * time.Minute
	}
	mode := os.Getenv("PROBE_MODE") // "remove" or "close"
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
	deadline := time.Now().Add(d)
	iters := 0
	for time.Now().Before(deadline) {
		w, err := fsnotify.NewWatcher()
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
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
		}()
		for _, dir := range dirs {
			if err := w.Add(dir); err != nil {
				t.Fatal(err)
			}
		}
		for i, dir := range dirs {
			_ = os.WriteFile(filepath.Join(dir, "f"), []byte(strconv.Itoa(iters+i)), 0o600)
			if mode != "close" {
				_ = w.Remove(dir)
			}
		}
		_ = w.Close()
		<-done
		iters++
	}
	stop.Store(true)
	t.Logf("mode=%s iterations=%d", mode, iters)
}
