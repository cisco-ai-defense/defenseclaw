#!/usr/bin/env python3
"""Remove fix-tracking comments (BLK-1 fix:, CRT-3 fix:, etc.) from source files.

Conservative strategy: only removes STANDALONE fix comments. Leaves mixed-content
blocks (fix tags embedded in documentation blocks) entirely untouched.

Usage:
    python scripts/remove_fix_comments.py --dry-run   # preview changes
    python scripts/remove_fix_comments.py              # apply changes
"""

import argparse
import os
import re

TAG = r'(?:BLK|CRT|HIGH|MEDIUM|LOW|MF|NEW|SF|BLOCKER|BUG|NF|W|C|H|M|L|B|S|P[012])-\d+'
MULTI_TAG = TAG + r'(?:/' + TAG + r')*'
FIX_SUFFIX = r'\s+(?:fix|Fix|NOTE|note|migration|tradeoff)\b'
TAG_FIX_RE = re.compile(MULTI_TAG + FIX_SUFFIX)

TARGETS = [
    "internal/fleet/",
    "internal/gateway/sidecar.go",
    "internal/gateway/api.go",
    "internal/gateway/model_router_feedback.go",
    "internal/gateway/model_router_feedback_test.go",
    "internal/routing/",
    "edge-connector/src/",
    "edge-connector/include/",
    "cli/defenseclaw/commands/cmd_edge_connector_cli.py",
    "cli/defenseclaw/commands/cmd_edge_install.py",
    "cli/defenseclaw/commands/cmd_setup_edge_connector.py",
    "cli/defenseclaw/commands/cmd_setup_mqtt.py",
    "cli/defenseclaw/commands/cmd_policy.py",
    "cli/defenseclaw/commands/cmd_status.py",
    "cli/defenseclaw/commands/cmd_setup.py",
    "cli/defenseclaw/audit_actions.py",
    "cli/defenseclaw/main.py",
]
EXTENSIONS = {".go", ".c", ".h", ".py"}


def collect_files(root):
    files = []
    for target in TARGETS:
        full = os.path.join(root, target)
        if os.path.isfile(full):
            if os.path.splitext(full)[1] in EXTENSIONS:
                files.append(full)
        elif os.path.isdir(full):
            for dirpath, _, filenames in os.walk(full):
                for fn in sorted(filenames):
                    if os.path.splitext(fn)[1] in EXTENSIONS:
                        files.append(os.path.join(dirpath, fn))
    return sorted(set(files))


def is_fix_start(text):
    return bool(TAG_FIX_RE.search(text[:140])) if text else False


def strip_fix_tag_inline(text):
    return TAG_FIX_RE.sub("", text, count=1).lstrip(": ")


def process_go_file(lines):
    result = []
    i = 0
    removed = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if stripped.startswith("//"):
            comment_text = stripped[2:].strip()
            if is_fix_start(comment_text):
                block_start = i
                i += 1
                while i < len(lines):
                    ns = lines[i].strip()
                    if not ns.startswith("//"):
                        break
                    nc = ns[2:].strip()
                    if is_fix_start(nc):
                        break
                    if nc == "":
                        break
                    i += 1
                removed += i - block_start
                continue
            result.append(line)
            i += 1
            continue

        if "//" in line and not stripped.startswith("//"):
            idx = line.index("//")
            ct = line[idx + 2:].strip()
            if is_fix_start(ct):
                result.append(line[:idx].rstrip() + "\n")
                removed += 1
                i += 1
                continue

        result.append(line)
        i += 1
    return result, removed


def process_c_file(lines):
    result = []
    i = 0
    removed = 0

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Case 1: Single-line /* ... */ on its own line
        if (stripped.startswith("/*") and stripped.endswith("*/")
                and stripped.count("/*") == 1 and stripped.count("*/") == 1):
            inner = stripped[2:-2].strip()
            if inner.startswith("*"):
                inner = inner[1:].strip()
            if is_fix_start(inner):
                removed += 1
                i += 1
                continue
            result.append(line)
            i += 1
            continue

        # Case 2: Multi-line block /* ... */ where the opening line starts with a fix tag
        # ONLY remove if the entire block is fix-tracking (opening line has fix tag)
        if stripped.startswith("/*") and "*/" not in stripped:
            inner = stripped[2:].strip()
            if inner.startswith("*"):
                inner = inner[1:].strip()

            if is_fix_start(inner):
                block_start = i
                i += 1
                while i < len(lines) and "*/" not in lines[i]:
                    i += 1
                if i < len(lines):
                    i += 1
                removed += i - block_start
                continue

            # NOT a fix-tagged opening — keep the entire block as-is
            result.append(line)
            i += 1
            while i < len(lines):
                result.append(lines[i])
                if "*/" in lines[i]:
                    i += 1
                    break
                i += 1
            continue

        # Case 3: Inline /* fix ... */ on a code line
        inline_re = re.compile(r'/\*\s*' + MULTI_TAG + FIX_SUFFIX + r'[^*]*\*/')
        m = inline_re.search(line)
        if m:
            before = line[:m.start()].rstrip()
            after = line[m.end():]
            rebuilt = before + after.rstrip() + "\n" if after.strip() else before + "\n"
            result.append(rebuilt)
            removed += 1
            i += 1
            continue

        # Case 4: C99 // comment on its own line
        if stripped.startswith("//"):
            ct = stripped[2:].strip()
            if is_fix_start(ct):
                removed += 1
                i += 1
                continue

        # Case 5: Inline // fix comment on a code line
        if "//" in line and not stripped.startswith("//") and not stripped.startswith("/*"):
            idx = line.index("//")
            ct = line[idx + 2:].strip()
            if is_fix_start(ct):
                result.append(line[:idx].rstrip() + "\n")
                removed += 1
                i += 1
                continue

        result.append(line)
        i += 1
    return result, removed


def process_py_file(lines):
    result = []
    i = 0
    removed = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if stripped.startswith("#"):
            ct = stripped[1:].strip()
            if is_fix_start(ct):
                block_start = i
                i += 1
                while i < len(lines):
                    ns = lines[i].strip()
                    if not ns.startswith("#"):
                        break
                    nc = ns[1:].strip()
                    if is_fix_start(nc):
                        break
                    if nc == "":
                        break
                    i += 1
                removed += i - block_start
                continue

        if "#" in line and not stripped.startswith("#") and not stripped.startswith('"'):
            in_str = None
            found = False
            for ci, ch in enumerate(line):
                if ch in ('"', "'") and (ci == 0 or line[ci - 1] != "\\"):
                    if in_str == ch:
                        in_str = None
                    elif in_str is None:
                        in_str = ch
                elif ch == "#" and in_str is None:
                    ct = line[ci + 1:].strip()
                    if is_fix_start(ct):
                        result.append(line[:ci].rstrip() + "\n")
                        removed += 1
                        i += 1
                        found = True
                    break
            if found:
                continue

        if stripped.startswith('"""') or stripped.startswith("'''"):
            doc_content = stripped[3:]
            if is_fix_start(doc_content):
                indent = line[:len(line) - len(line.lstrip())]
                cleaned = strip_fix_tag_inline(doc_content).lstrip()
                if cleaned:
                    result.append(indent + stripped[:3] + cleaned + "\n")
                    removed += 1
                    i += 1
                    continue

        result.append(line)
        i += 1
    return result, removed


def cleanup_blank_lines(lines):
    result = []
    blank_count = 0
    for line in lines:
        if line.strip() == "":
            blank_count += 1
            if blank_count <= 2:
                result.append(line)
        else:
            blank_count = 0
            result.append(line)
    return result


def process_file(filepath, dry_run=False):
    ext = os.path.splitext(filepath)[1]
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        original = f.readlines()

    if ext == ".go":
        processed, removed = process_go_file(original)
    elif ext in (".c", ".h"):
        processed, removed = process_c_file(original)
    elif ext == ".py":
        processed, removed = process_py_file(original)
    else:
        return 0, False

    processed = cleanup_blank_lines(processed)
    if removed == 0:
        return 0, False

    if not dry_run:
        with open(filepath, "w", encoding="utf-8") as f:
            f.writelines(processed)
    return removed, True


def main():
    parser = argparse.ArgumentParser(description="Remove fix-tracking comments")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--root", default=".")
    args = parser.parse_args()

    root = os.path.abspath(args.root)
    files = collect_files(root)
    total_removed = 0
    total_files = 0

    for fp in files:
        rel = os.path.relpath(fp, root)
        removed, changed = process_file(fp, dry_run=args.dry_run)
        if changed:
            total_files += 1
            total_removed += removed
            action = "would remove" if args.dry_run else "removed"
            print(f"  {rel}: {action} {removed} comment(s)")

    action = "Would remove" if args.dry_run else "Removed"
    print(f"\n{action} {total_removed} fix-tracking comments across {total_files} files.")


if __name__ == "__main__":
    main()
