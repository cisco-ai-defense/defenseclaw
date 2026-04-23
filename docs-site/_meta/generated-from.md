# Generated-from footer audit rulebook

Every hand-written MDX page under `docs-site/` ends with:

```mdx
---

<!-- generated-from: path/to/source1.go, path/to/source2.py -->
```

## Rules

1. The comment must be the last non-empty line of the file.
2. Paths are comma-separated, relative to the repo root.
3. Every listed path must exist at the time of the commit.
4. The CI job `make docs-check` validates this.

## Exemptions

Pages that are fully AUTOGEN'd (no hand-written narrative) use the AUTOGEN sentinel instead and omit the footer.

## Audit script (implementors)

```bash
# Every *.mdx under docs-site/ must either:
#  - end with a generated-from comment, OR
#  - contain only AUTOGEN blocks (no ## Usage, ## Overview, etc.)
find docs-site -name '*.mdx' | while read -r f; do
  if ! grep -q 'generated-from:' "$f"; then
    if ! grep -q 'BEGIN AUTOGEN' "$f"; then
      echo "MISSING FOOTER: $f"
      exit 1
    fi
  fi
done
```
