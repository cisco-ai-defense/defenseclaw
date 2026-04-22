# DefenseClaw Local Observability Stack — moved

The compose-based Prometheus / Loki / Tempo / Grafana stack has moved to
the bundle tree so it can be shipped inside the wheel, seeded by
`defenseclaw init`, and driven from the CLI/TUI the same way the
local-Splunk bundle is.

New location:

    bundles/local_observability_stack/

Recommended entry point (preflights Docker, starts the stack, waits for
OTLP + Grafana readiness, writes `~/.defenseclaw/config.yaml` to point
the gateway at `127.0.0.1:4317`, then prints the URLs):

```bash
defenseclaw setup local-observability up
```

Tear down:

```bash
defenseclaw setup local-observability down    # keep volumes
defenseclaw setup local-observability reset   # drop TSDB / logs / traces
```

Raw compose access (unchanged surface, no CLI side-effects on
`config.yaml`):

```bash
cd bundles/local_observability_stack
./bin/openclaw-observability-bridge up    # or ./run.sh up (compat shim)
```
