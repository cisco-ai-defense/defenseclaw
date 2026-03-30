# Sandbox Debugging

## Important: Process Model and File Ownership

OpenClaw runs as a **child process** of `openshell-sandbox`. The sandbox
binary starts as root, creates the namespace, then drops privileges and
launches OpenClaw as the `sandbox` user.

During `defenseclaw sandbox init`, ownership of all OpenClaw files and
directories (`~/.openclaw/`) is changed to the `sandbox` user. This means
any manual edits to `openclaw.json`, skill files, or plugin configs must be
done as the `sandbox` user:

```bash
sudo -u sandbox vi /home/sandbox/.openclaw/openclaw.json
# or
sudo -u sandbox nano /home/sandbox/.openclaw/openclaw.json
```

Editing as root or another user will create files owned by the wrong user,
causing permission errors when OpenClaw tries to read or write them.

## Sandbox Won't Start

```bash
# Check service status and recent logs
systemctl status openshell-sandbox.service
journalctl -u openshell-sandbox --no-pager -n 50
```

**Common causes:**

| Symptom | Fix |
|---|---|
| `pre-sandbox.sh` fails | Orphan namespace or stale PID/lock file. Run `pre-sandbox.sh` manually to see the error. |
| `start-sandbox.sh` permission denied | Scripts not executable. `sudo chmod 755 /usr/local/lib/defenseclaw/*.sh` |
| `openshell-sandbox` not found | Binary missing. Re-run `defenseclaw sandbox init` to auto-install. |
| Namespace creation fails | Kernel doesn't support user namespaces or Landlock. Check `cat /proc/sys/kernel/unprivileged_userns_clone`. |

## Sidecar Can't Connect to Sandbox

```bash
# Test WebSocket connectivity from the host
curl -v http://10.200.0.2:18789
```

**Common causes:**

| Symptom | Fix |
|---|---|
| Connection refused | OpenClaw not running inside sandbox. Check sandbox logs. |
| Auth failure / handshake rejected | Device key not paired. Re-run `defenseclaw sandbox setup` to re-pair. |
| Timeout | veth pair not up. Check `ip link show \| grep veth-h`. |

## Network Issues Inside Sandbox

```bash
# Enter the sandbox namespace (find the PID first)
SANDBOX_PID=$(pgrep -f openshell-sandbox)
sudo nsenter -t $SANDBOX_PID -n -- bash

# Inside the namespace:
ip addr show           # should show 10.200.0.2
ping -c1 10.200.0.1    # host should be reachable
curl http://10.200.0.1:18970/health   # sidecar API
```

**DNS not working:**
```bash
# Check resolv.conf was bind-mounted
sudo nsenter -t $SANDBOX_PID -n -m -- cat /etc/resolv.conf

# Check iptables DNS rules
sudo nsenter -t $SANDBOX_PID -n -- iptables -L -n | grep 53
```

**Outbound blocked unexpectedly:**
Check the OpenShell policy files:
```bash
cat ~/.defenseclaw/openshell-policy.rego
cat ~/.defenseclaw/openshell-policy.yaml
```

The Rego policy controls which destinations each binary can reach. Connection
denials are logged to journald with a `CONNECT` event containing `action=deny`.

**Note:** Changes to OpenShell network policy files (`openshell-policy.rego`,
`openshell-policy.yaml`) only take effect after restarting the sandbox service:

```bash
sudo systemctl restart openshell-sandbox.service
```

## Skills/Plugins Not Loading

```bash
# Check watcher is running
curl http://10.200.0.1:18970/health | jq .watcher

# List skills the sidecar sees
defenseclaw skill list

# Check plugin registration
cat /home/sandbox/.openclaw/openclaw.json | jq .plugins
```

**Common causes:**

| Symptom | Fix |
|---|---|
| Watcher shows `error` | ACL issue. Run `sudo scripts/fix-sandbox-acls.sh`. |
| Skill blocked | Check block list: `defenseclaw block list`. Remove if false positive: `defenseclaw block remove <key>`. |
| Plugin not in list | Not registered in `openclaw.json`. Re-run `defenseclaw sandbox setup`. |

## Guardrail Proxy Issues

```bash
# Check guardrail is running
curl http://10.200.0.1:18970/health | jq .guardrail

# Test the proxy directly
curl -x http://10.200.0.1:4000 https://api.openai.com/v1/models
```

If LLM calls from inside the sandbox fail, verify the plugin's `baseUrl`
points to the host IP:
```bash
cat /home/sandbox/.openclaw/openclaw.json | jq '.plugins'
```

## Restart Loop

If the service keeps restarting (30s cycle):

```bash
# See why it's exiting
journalctl -u openshell-sandbox --no-pager -n 100

# Temporarily stop to investigate
sudo systemctl stop defenseclaw-sandbox.target
```

Check for resource issues (`dmesg | grep -i oom`), filesystem permission
problems, or invalid policy files.

## Ownership / Permission Errors

```bash
# Re-fix ownership
sudo chown -R sandbox:sandbox /home/sandbox/.openclaw

# Re-fix ACLs
sudo setfacl -R -m u:sandbox:rwX /home/sandbox/.openclaw

# Or use the bundled script
sudo scripts/fix-sandbox-acls.sh
```

## Collecting a Debug Bundle

```bash
# Gather everything in one shot
systemctl status openshell-sandbox.service > /tmp/dclaw-debug.txt
journalctl -u openshell-sandbox --no-pager -n 200 >> /tmp/dclaw-debug.txt
defenseclaw status >> /tmp/dclaw-debug.txt 2>&1
ip link show >> /tmp/dclaw-debug.txt
sudo iptables -t nat -L -n >> /tmp/dclaw-debug.txt
```
