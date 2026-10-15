#!/usr/bin/env python3
"""Network adapter calls must bind policy to an explicit delegated target."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for directory in (ROOT / "tools", ROOT / "integrations/homeassistant",
                  ROOT / "integrations/bubbaloop", ROOT / "integrations/espclaw"):
    sys.path.insert(0, str(directory))

from generic_hook import (CAP_ACTUATE, CAP_SENSOR_READ, Verdict)
from defenseclaw_ha import HAMCP_TOOL_CAP_MAP, HomeAssistantAdapter
from defenseclaw_bubbaloop import BUBBALOOP_TOOL_CAP_MAP, BubbaloopAdapter
from defenseclaw_espclaw import ESPCLAW_TOOL_CAP_MAP, ESPClawAdapter


class FakeConnector:
    def __init__(self):
        self.calls = []

    def evaluate(self, **kwargs):
        self.calls.append(kwargs)
        return Verdict.allow()


def fixture(adapter_class, **kwargs):
    connector = FakeConnector()
    adapter = adapter_class(connector=connector, **kwargs)
    forwarded = []
    adapter._mcp_request = lambda method, body: forwarded.append((method, body)) or {"ok": True}
    return adapter, connector, forwarded


def expect_local_block(adapter, connector, forwarded, tool, arguments):
    before = len(connector.calls)
    result = adapter.call_tool(tool, arguments)
    assert not result["allowed"], (tool, arguments, result)
    assert len(connector.calls) == before, (tool, connector.calls)
    assert not forwarded, (tool, forwarded)


def main():
    bubbaloop, bconnector, bforwarded = fixture(BubbaloopAdapter)
    public = {"url": "https://1.1.1.1/model"}
    assert bubbaloop.call_tool("http_fetch", public)["allowed"]
    assert bconnector.calls[-1]["destination"] == public["url"]
    assert len(bforwarded) == 1
    assert bubbaloop.call_tool("model_download", public)["allowed"]
    assert bconnector.calls[-1]["destination"] == public["url"]
    bforwarded.clear()
    for bad in ({}, {"url": "http://127.0.0.1/admin"},
                {"url": "https://example.com/path"},
                {"url": "https://1.1.1.1/a", "endpoint": "http://127.0.0.1"},
                {"url": "https://user@1.1.1.1/a"},
                {"url": "https://1.1.1.1:70000/a"},
                {"url": "https://1.1.1.1\\@127.0.0.1/a"}):
        expect_local_block(bubbaloop, bconnector, bforwarded, "http_fetch", bad)
    expect_local_block(bubbaloop, bconnector, bforwarded,
                       "mqtt_publish", {"broker_url": "mqtt://1.1.1.1:1883"})

    esp, econnector, eforwarded = fixture(ESPClawAdapter, host="localhost")
    ipv6 = {"url": "https://[2606:4700:4700::1111]/status"}
    assert esp.call_tool("http_request", ipv6)["allowed"]
    assert econnector.calls[-1]["destination"] == ipv6["url"]
    eforwarded.clear()
    expect_local_block(esp, econnector, eforwarded,
                       "http_request", {"url": "http://192.168.1.42/"})
    assert esp.call_tool("wifi_scan", {})["allowed"]
    assert ESPCLAW_TOOL_CAP_MAP["wifi_scan"] == CAP_SENSOR_READ
    assert econnector.calls[-1]["destination"] == ""

    ha, hconnector, hforwarded = fixture(HomeAssistantAdapter, host="localhost")
    assert ha.call_tool("get_integrations_manifest", {})["allowed"]
    assert HAMCP_TOOL_CAP_MAP["get_integrations_manifest"] == CAP_SENSOR_READ
    assert hconnector.calls[-1]["destination"] == ""
    assert HAMCP_TOOL_CAP_MAP["tts_speak"] == CAP_ACTUATE
    hforwarded.clear()
    expect_local_block(ha, hconnector, hforwarded,
                       "call_webhook", {"url": "https://1.1.1.1/hook"})
    assert BUBBALOOP_TOOL_CAP_MAP["http_fetch"] != CAP_SENSOR_READ
    print("adapter delegated targets: public HTTP(S) allowed for reviewed tools; "
          "private/hostname/missing/ambiguous/unsupported blocked")


if __name__ == "__main__":
    main()
