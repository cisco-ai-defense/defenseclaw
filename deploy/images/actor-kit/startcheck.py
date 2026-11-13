#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""startcheck: start the pinned agent of an actor image with the config the kit rendered and fail if it refuses to start.

A pin bump can make the vendor binary reject a setting the kit passes (Codex 0.168.0 dropped approval_policy
"untrusted" and exited at launch: GAP-0202). The build pipeline runs this inside every image it builds, before the image is
published:

    docker run --rm --user 1000:1000 -v startcheck.py:/startcheck.py:ro --entrypoint python3 IMAGE /startcheck.py [seconds]

It reads relay.interactive from /etc/defenseclaw/actor-kit.json (the argv the relay starts in a terminal), starts it on a
pseudo-terminal in /work with HOME=/sandbox and the image environment, and watches it for N seconds (default 8). A healthy
agent is still running then, waiting at its screen or its sign-in prompt. The check FAILS (exit 1) when the agent exits
before N seconds, or prints a configuration refusal, and prints the screen. It needs no network and makes no model call.
Exit 0 pass, 1 fail, 2 cannot run (no config, no argv).
"""
import json, os, pty, re, select, signal, sys, time

REFUSAL = re.compile(r"(error loading config|invalid (config|setting)|unknown (option|flag|argument)|unrecognized (option|argument)|"
                     r"no longer supported|failed to (parse|load) (config|settings)|unexpected argument)", re.I)

def main():
    secs = float(sys.argv[1]) if len(sys.argv) > 1 else 8.0
    try:
        argv = json.load(open("/etc/defenseclaw/actor-kit.json"))["relay"]["interactive"]
    except Exception as e:
        print("startcheck: cannot read relay.interactive: %s" % e)
        return 2
    if not argv:
        print("startcheck: relay.interactive is empty")
        return 2
    env = dict(os.environ, HOME="/sandbox", TERM="xterm-256color")
    os.makedirs("/work", exist_ok=True)
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir("/work")
        try:
            os.execvpe(argv[0], argv, env)
        finally:
            os._exit(127)
    out, deadline, status = b"", time.time() + secs, None
    while time.time() < deadline:
        r, _, _ = select.select([fd], [], [], 0.3)
        if r:
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                chunk = b""
            if chunk:
                out += chunk
        done, st = os.waitpid(pid, os.WNOHANG)
        if done:
            status = st
            break
    if status is None:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
    text = re.sub(rb"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07", b"", out).decode("utf-8", "replace")
    tail = "\n".join(l.rstrip() for l in text.splitlines() if l.strip())[-1200:]
    bad = bool(REFUSAL.search(text))
    if status is not None:
        print("startcheck FAIL: %s exited before %.0f s (status %s)\n%s" % (argv[0], secs, status, tail))
        return 1
    if bad:
        print("startcheck FAIL: %s is running but printed a configuration refusal\n%s" % (argv[0], tail))
        return 1
    print("startcheck ok: %s still running after %.0f s\n%s" % (argv[0], secs, tail[-400:]))
    return 0

sys.exit(main())
