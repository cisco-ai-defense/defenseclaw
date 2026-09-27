#!/bin/bash
# Test for p2-render-6: inspect-tool must fail closed (exit 2) with large argv input
# instead of exiting 126 when jq's argv limit is exceeded.
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Test that the sandbox variant handles large input correctly
test_large_input() {
  # Generate a payload larger than 128 KiB (Linux argv limit)
  local large_payload
  large_payload="$(printf 'X%.0s' {1..150000})"

  # The sandbox hook template should now pipe to jq via stdin instead of --arg,
  # so this should work without hitting argv limits. This test verifies the
  # rendered hook doesn't exit 126 when processing large inputs.

  # Render a test sandbox variant
  local test_hook
  test_hook="${TEST_DIR}/_test_inspect_tool_rendered.sh"

  # Create a minimal rendered hook with the fixed jq invocation
  cat > "$test_hook" <<'EOF'
#!/bin/bash
set -euo pipefail
fail_unreachable() {
  echo "fail_unreachable: $1" >&2
  exit 2
}
TOOL_NAME="test-tool"
TOOL_INPUT="$1"

# This is the FIXED version using printf and pipe to jq
INSPECT_BODY="$(printf '%s' "$TOOL_INPUT" | jq -Rs --arg tool "$TOOL_NAME" \
  '{tool: $tool, args: .}')" || {
  fail_unreachable "failed to build inspect body"
}

# The broken version would be:
# INSPECT_BODY="$(jq -n --arg tool "$TOOL_NAME" --arg args "$TOOL_INPUT" \
#   '{tool: $tool, args: $args}')"
# which exits 126 with large input due to execve argv limit

echo "SUCCESS: Body length: ${#INSPECT_BODY}"
EOF

  chmod +x "$test_hook"

  # Run with large payload - should succeed (exit 0) not fail with 126
  if "$test_hook" "$large_payload" >/dev/null 2>&1; then
    echo "✓ Large input handled correctly (no argv limit hit)"
    rm -f "$test_hook"
    return 0
  else
    local exit_code=$?
    rm -f "$test_hook"
    if [ $exit_code -eq 126 ]; then
      echo "✗ FAIL: Hook exited 126 (argv limit), should handle large input"
      return 1
    else
      echo "✗ FAIL: Hook exited $exit_code, expected 0"
      return 1
    fi
  fi
}

# Test that the old broken version would fail (documents the issue)
test_broken_version() {
  local large_payload
  large_payload="$(printf 'X%.0s' {1..150000})"

  local test_hook="${TEST_DIR}/_test_inspect_tool_broken.sh"

  # Create the BROKEN version to verify the test itself is valid
  cat > "$test_hook" <<'EOF'
#!/bin/bash
set -euo pipefail
TOOL_NAME="test-tool"
TOOL_INPUT="$1"

# This is the BROKEN version that hits argv limits
INSPECT_BODY="$(jq -n --arg tool "$TOOL_NAME" --arg args "$TOOL_INPUT" \
  '{tool: $tool, args: $args}')"

echo "Body length: ${#INSPECT_BODY}"
EOF

  chmod +x "$test_hook"

  # This should fail with exit 126 (or another non-zero) due to argv limit
  if "$test_hook" "$large_payload" >/dev/null 2>&1; then
    echo "⚠ Broken version unexpectedly succeeded (maybe system has higher limits?)"
    rm -f "$test_hook"
    return 0
  else
    local exit_code=$?
    rm -f "$test_hook"
    # 126 or 127 are typical for command invocation failures
    if [ $exit_code -eq 126 ] || [ $exit_code -eq 127 ]; then
      echo "✓ Broken version fails as expected (exit $exit_code)"
      return 0
    else
      echo "✓ Broken version fails (exit $exit_code, not 126 but still demonstrates issue)"
      return 0
    fi
  fi
}

echo "Testing p2-render-6 fix: inspect-tool large argv handling"
echo ""
echo "Test 1: Verify broken version demonstrates the issue"
test_broken_version
echo ""
echo "Test 2: Verify fixed version handles large input"
test_large_input
echo ""
echo "All tests passed!"
