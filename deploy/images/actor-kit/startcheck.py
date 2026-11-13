#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""startcheck: start the pinned agent of an actor image with the config the kit rendered and fail if it refuses to start.

A pin bump can make the vendor binary reject a setting the kit passes (Codex 0.168.0 dropped approval_policy
"untrusted" and exited at launch: GAP-0202). Run this against every image `defenseclaw-gateway substrate template build`
produced, before the image is published (stk-redeploy does it right after the build; startcheck.sh runs it in an image):

    docker run --rm --network none --user 1000:1000 -v startcheck.py:/startcheck.py:ro --entrypoint python3 IMAGE /startcheck.py [seconds]

It reads /etc/defenseclaw/actor-kit.json and checks both argv the relay starts:

  relay.interactive  started on a pseudo-terminal in /work with HOME=/sandbox and the image environment, and watched for N
                     seconds (default 8). A healthy agent is still running then, waiting at its screen or its sign-in
                     prompt. FAILS when the agent exits before N seconds or prints a configuration refusal.
  relay.headless     the --task command, with {prompt} replaced by a one-word prompt, on a pipe with no input. With no
                     network it cannot reach a model, so it may stay up (retrying) or exit with a connection error: both
                     pass. It FAILS when it cannot be executed (126, 127), when it exits with a usage error (2 and a usage
                     text), or when it prints a configuration refusal. A connector with no headless mode passes.

The check prints the screen of a failure. It makes no model call: run it with --network none, as startcheck.sh does.
Exit 0 pass, 1 fail, 2 cannot run (no config, no interactive argv).
"""
import json, os, pty, re, select, signal, subprocess, sys, time

REFUSAL = re.compile(r"(error loading config|invalid (config|setting)|unknown (option|flag|argument|command|subcommand)|"
                     r"unrecognized (option|argument|arguments)|no longer supported|failed to (parse|load) (config|settings)|"
                     r"unexpected argument)", re.I)
WORK = "/work"
CONFIG = "/etc/defenseclaw/actor-kit.json"
USAGE = re.compile(r"\busage:", re.I)
ANSI = re.compile(rb"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07")


def tail_of(raw):
    text = ANSI.sub(b"", raw).decode("utf-8", "replace")
    return text, "\n".join(l.rstrip() for l in text.splitlines() if l.strip())[-1200:]


def check_interactive(argv, env, secs):
    """0 pass, 1 fail. Starts argv on a pty and watches it for secs seconds."""
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(WORK)
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
    text, tail = tail_of(out)
    if status is not None:
        print("startcheck FAIL: interactive %s exited before %.0f s (status %s)\n%s" % (argv[0], secs, status, tail))
        return 1
    if REFUSAL.search(text):
        print("startcheck FAIL: interactive %s is running but printed a configuration refusal\n%s" % (argv[0], tail))
        return 1
    print("startcheck ok: interactive %s still running after %.0f s\n%s" % (argv[0], secs, tail[-400:]))
    return 0


def check_headless(argv, env, secs):
    """0 pass, 1 fail. Runs the --task command with a fixed prompt and no input for at most secs seconds."""
    argv = [("startcheck" if a == "{prompt}" else a) for a in argv]
    try:
        proc = subprocess.Popen(argv, cwd=WORK, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, start_new_session=True)
    except OSError as e:
        print("startcheck FAIL: headless %s cannot be executed: %s" % (argv[0], e))
        return 1
    try:
        out, _ = proc.communicate(timeout=secs)
        code = proc.returncode
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        out, _ = proc.communicate()
        code = None
    text, tail = tail_of(out or b"")
    if code in (126, 127):
        print("startcheck FAIL: headless %s cannot be executed (status %s)\n%s" % (argv[0], code, tail))
        return 1
    if REFUSAL.search(text) or (code == 2 and USAGE.search(text)):
        print("startcheck FAIL: headless %s refused its arguments (status %s)\n%s" % (argv[0], code, tail))
        return 1
    state = "still running after %.0f s" % secs if code is None else "exited %s without a configuration refusal" % code
    print("startcheck ok: headless %s %s\n%s" % (argv[0], state, tail[-400:]))
    return 0


def main():
    secs = float(sys.argv[1]) if len(sys.argv) > 1 else 8.0
    try:
        relay = json.load(open(CONFIG))["relay"]
        interactive, headless = relay["interactive"], relay.get("headless") or []
    except Exception as e:
        print("startcheck: cannot read relay.interactive: %s" % e)
        return 2
    if not interactive:
        print("startcheck: relay.interactive is empty")
        return 2
    env = dict(os.environ, HOME="/sandbox", TERM="xterm-256color")
    os.makedirs(WORK, exist_ok=True)
    rc = check_interactive(interactive, env, secs)
    if headless:
        rc |= check_headless(headless, env, secs)
    else:
        print("startcheck ok: no headless mode for this connector")
    return rc


if __name__ == "__main__":
    sys.exit(main())
