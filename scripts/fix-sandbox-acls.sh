#!/usr/bin/env bash
# fix-sandbox-acls.sh — Repair POSIX ACLs on OpenClaw directories in sandbox mode.
#
# WHY THIS EXISTS
# ───────────────
# POSIX default ACLs on a directory only apply to files created (creat/mkdir)
# directly inside that directory.  Two common write patterns defeat them:
#
#   1. Atomic rename: Node.js writes a temp file (often in /tmp or the same dir
#      with a random suffix) then rename()s it to the target.  The renamed file
#      keeps permissions from the source directory — default ACLs never fire.
#
#   2. Explicit mode: open(path, O_CREAT, 0600) sets the file mode to 0600.
#      The kernel then sets the ACL mask to --- which zeroes out any
#      user:sandbox:rwx grant, even though the default ACL says mask::rwx.
#
# OpenClaw's Node.js gateway uses both patterns when saving openclaw.json,
# installing plugins, and creating backup files.
#
# WHY IT'S NOT ENABLED BY DEFAULT
# ────────────────────────────────
# In normal operation the sandbox user writes its OWN files and can read them
# just fine.  The ACL breakage only matters when:
#
#   - A root-privileged process (defenseclaw CLI, setup scripts) writes into
#     the sandbox user's config directory while the sandbox is running.
#
#   - An external tool or hook writes files with restrictive permissions into
#     a directory the sandbox user needs to read.
#
# The pre-sandbox.sh startup script already fixes ACLs before openclaw starts,
# which covers the common case.  Running this fixer continuously would mask
# permission bugs rather than surface them, and blindly granting rwx to every
# new file weakens the sandbox's security posture — the sandbox shouldn't
# automatically trust every file that appears in its directories.
#
# WHEN TO USE THIS
# ────────────────
# - One-shot repair after running defenseclaw CLI commands while sandbox is live:
#     sudo bash scripts/fix-sandbox-acls.sh
#
# - As a periodic cron/systemd timer if you have workflows that frequently
#   write into OpenClaw directories as root while the sandbox is running:
#     */5 * * * * /path/to/fix-sandbox-acls.sh
#
# - As a background loop alongside run-sandbox.sh (uncomment the loop below):
#     bash scripts/fix-sandbox-acls.sh --loop &
#
# USAGE
# ─────
#   bash scripts/fix-sandbox-acls.sh            # one-shot fix
#   bash scripts/fix-sandbox-acls.sh --loop     # fix every 30s until killed

set -uo pipefail

TARGETS=(
    /root/.openclaw
    /home/sandbox/.openclaw
)

fix_acls() {
    for d in "${TARGETS[@]}"; do
        [ -d "$d" ] || continue
        setfacl -R -m u:sandbox:rwX "$d" 2>/dev/null || true
        setfacl -R -d -m u:sandbox:rwX "$d" 2>/dev/null || true
        setfacl -R -m m::rwx "$d" 2>/dev/null || true
        setfacl -R -d -m m::rwx "$d" 2>/dev/null || true
    done
}

if [ "${1:-}" = "--loop" ]; then
    echo "fix-sandbox-acls: running in loop mode (every 30s, pid $$)"
    while true; do
        fix_acls
        sleep 30
    done
else
    fix_acls
    echo "fix-sandbox-acls: ACLs repaired on ${TARGETS[*]}"
fi
