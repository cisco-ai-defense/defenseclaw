#!/bin/bash
# DefenseClaw Shield hook for Claude Code.
#
# Intercepts user prompts BEFORE they reach the LLM.
# Sends the prompt to the shield daemon for inspection.
# Exit 0 = allow, Exit 2 = block.
#
# Install: add to ~/.claude/settings.json hooks.UserPromptSubmit

SOCKET="${SHIELD_SOCKET:-$HOME/.defenseclaw-shield/shield.sock}"

# Read the hook input from stdin (Claude Code sends JSON).
INPUT=$(cat)

# Extract the user prompt from the hook payload.
PROMPT=$(echo "$INPUT" | python3 -c "
import json, sys, struct, socket, os

data = json.load(sys.stdin)
prompt = data.get('prompt', '')
if not prompt:
    sys.exit(0)

sock_path = os.environ.get('SHIELD_SOCKET', os.path.expanduser('~/.defenseclaw-shield/shield.sock'))

try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(2)
    s.connect(sock_path)

    host = b'api.anthropic.com:443'
    payload = json.dumps({'messages': [{'role': 'user', 'content': prompt}]}).encode()
    pid = os.getpid()

    body = struct.pack('<BIH', 0x01, pid, len(host)) + host + struct.pack('<I', len(payload)) + payload
    header = struct.pack('<I', len(body))
    s.sendall(header + body)

    verdict = s.recv(1)
    s.close()

    if verdict and verdict[0] == 0x01:
        # BLOCK
        print('BLOCKED')
        sys.exit(0)
    else:
        print('ALLOWED')
        sys.exit(0)
except Exception as e:
    # Fail-open: if daemon is unreachable, allow the request.
    print('ALLOWED')
    sys.exit(0)
" 2>/dev/null)

if [ "$PROMPT" = "BLOCKED" ]; then
    echo '{"error": "DefenseClaw Shield blocked this request — security policy violation detected. Check ~/.defenseclaw-shield/audit.jsonl for details."}' >&2
    exit 2
fi

exit 0
