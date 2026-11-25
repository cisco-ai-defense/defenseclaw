package actionfacts

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// TestGAP0674WalksRunAtMostSlotsAtOnce is substrate-1:GAP-0674: the walks of
// a recursive search run at most max(2, GOMAXPROCS/4) at a time (GOMAXPROCS as
// the package started with, the cap of credentialPathWalkSlots), each with its
// credentialPathWalkWorkers readers. Before it, every hook call walked at
// once: on dc-win2, 2,048 calls of grep -r KEY mNNNN (each name a junction to
// one 2,047-folder tree under 2,000-character paths) put 72 to 179 walks in
// flight, 0.5 GB of found paths alive at once and a gateway peak of 1.3 GB, as
// against 0.45 GB for the same calls on 1.0.10. The test starts many walks of
// one tree and counts, from the goroutine stacks, how many readers of folders
// exist at once.
func TestGAP0674WalksRunAtMostSlotsAtOnce(t *testing.T) {
	root := t.TempDir()
	for i := range 24 {
		for j := range 24 {
			folder := filepath.Join(root, "d"+strconv.Itoa(i), "e"+strconv.Itoa(j))
			if err := os.MkdirAll(folder, 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.WriteFile(filepath.Join(root, "d3", "e4", ".env"), []byte("KEY=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The cap is fixed when the package starts, from GOMAXPROCS then. Read it
	// from the channel, not from GOMAXPROCS now: under go test -cpu N the two
	// differ (substrate-1:GAP-1113).
	slots := cap(credentialPathWalkSlots)
	walkers := 8 * slots
	var peak atomic.Int64
	stop := make(chan struct{})
	sampled := make(chan struct{})
	go func() {
		defer close(sampled)
		buf := make([]byte, 1<<22)
		for {
			select {
			case <-stop:
				return
			default:
			}
			// Yield, not a 1 ms timer: with one P (go test -cpu 1) the timer
			// goroutine waits behind the walkers' time slices and sees no
			// reader at all (substrate-1:GAP-1113). Between two samples the
			// readers run, or wait in a system call that frees the P.
			runtime.Gosched()
			n := runtime.Stack(buf, true)
			readers := int64(0)
			for _, one := range strings.Split(string(buf[:n]), "\n\n") {
				if strings.Contains(one, "(*credentialPathWalkBudget).scan") {
					readers++
				}
			}
			if readers > peak.Load() {
				peak.Store(readers)
			}
		}
	}()
	var wg sync.WaitGroup
	for range walkers {
		wg.Go(func() {
			for range 6 {
				walk := credentialPathWalk(credentialWalkBudgetUnbounded(), root, root, credentialWalkFilter{}, credentialPathWalkBounds, credentialWalkRoomAll())
				if len(walk.found) != 1 || walk.cut {
					t.Errorf("walk found %v cut %v, want the one .env and no cut", walk.found, walk.cut)
					return
				}
			}
		})
	}
	wg.Wait()
	close(stop)
	<-sampled
	if limit := int64(slots * credentialPathWalkWorkers); peak.Load() > limit {
		t.Fatalf("%d walkers had %d folder readers at once, want at most %d (%d walks of %d readers)", walkers, peak.Load(), limit, slots, credentialPathWalkWorkers)
	}
	if peak.Load() == 0 {
		if runtime.GOMAXPROCS(0) == 1 {
			// With one P (go test -cpu 1) the walks run one after the other
			// between two samples: the sampler sees no reader, and a count
			// of none says nothing of the limit (substrate-1:GAP-1113).
			t.Skip("with GOMAXPROCS 1 the sampler saw no folder reader: nothing to measure")
		}
		t.Fatal("the sampler saw no folder reader: the test measured nothing")
	}
}
