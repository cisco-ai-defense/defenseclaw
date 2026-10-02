# fsnotify v1.9.0 with a Windows completion fix

This is github.com/fsnotify/fsnotify v1.9.0 (BSD-3-Clause, see LICENSE)
without its tests and commands. The root go.mod replaces the upstream
module with this directory. Only backend_windows.go differs from v1.9.0.

On Windows, Remove and Close cancel a watch's pending ReadDirectoryChanges
call, close its handle and drop the watch at once. The cancelled call still
completes later. When it does:

- the kernel writes into the watch's OVERLAPPED and buffer, which the Go heap
  may already have freed and reused, and
- the reader re-arms the dropped watch and closes its handle value a second
  time. That value may by then belong to another object.

Under GC pressure a process that adds and removes watches fails with
"found bad pointer in Go heap" within seconds. The same failure is in
fsnotify v1.10.1. The changes:

- Every queued read is counted, and its watch stays reachable until the
  read's packet is dequeued.
- Packets for watches that are no longer registered are dropped.
- Close waits, for at most five seconds, for the packets of the reads it
  cancelled.
- sendError puts Close's handshake back, so Close no longer hangs when an
  error is reported during Close. Upstream issue #768 and pull request #769
  describe the double close and this hang.

Remove this directory and the replace directive once an upstream release
fixes these.
