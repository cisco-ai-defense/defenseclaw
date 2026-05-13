import http.client
import http.server
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner
from defenseclaw.c3_agent_tokenomics.cli import build_payload_from_files
from defenseclaw.c3_agent_tokenomics.controls import control_event_from_action, evaluate_runtime_action
from defenseclaw.c3_agent_tokenomics.fixtures import default_galileo_payload, default_o11y_rows
from defenseclaw.c3_agent_tokenomics.galileo import merge_galileo_enrichment, summarize_galileo
from defenseclaw.c3_agent_tokenomics.galileo_config import galileo_config_from_env, resolve_galileo_project
from defenseclaw.c3_agent_tokenomics.mock_api import make_server
from defenseclaw.c3_agent_tokenomics.transform import build_summary, metric_point_from_row, normalize_token_type
from defenseclaw.commands.cmd_c3_tokenomics import c3_tokenomics


class C3AgentTokenomicsTests(unittest.TestCase):
    def setUp(self):
        self.rows = default_o11y_rows()
        self.galileo = default_galileo_payload()

    def test_token_type_aliases(self):
        self.assertEqual(normalize_token_type("cacheRead"), "cached")
        self.assertEqual(normalize_token_type("prompt"), "input")
        self.assertEqual(normalize_token_type("completion"), "output")

    def test_metric_point_accepts_o11y_dimension_names(self):
        point = metric_point_from_row(self.rows[0])
        self.assertEqual(point.agent_name, "incident-triage-agent")
        self.assertEqual(point.model, "gpt-4o-mini")
        self.assertEqual(point.token_type, "input")
        self.assertEqual(point.tokens, 14320)

    def test_missing_optional_dimensions_normalize_to_unknown(self):
        point = metric_point_from_row({"tokens": 7, "gen_ai.token.type": "prompt"})
        self.assertEqual(point.agent_name, "unknown")
        self.assertEqual(point.service_name, "unknown")
        self.assertEqual(point.provider, "unknown")
        self.assertEqual(point.tokens, 7)

    def test_o11y_summary_totals(self):
        payload = build_summary(self.rows, tenant_id="c3-demo-tenant", workspace_id="wayne-demo")
        s = payload["summary"]
        self.assertEqual(s["total_tokens"], 45150)
        self.assertEqual(s["input_tokens"], 29650)
        self.assertEqual(s["output_tokens"], 9350)
        self.assertEqual(s["cached_tokens"], 820)
        self.assertEqual(s["reasoning_tokens"], 3210)
        self.assertEqual(s["tool_tokens"], 2120)
        self.assertEqual(s["active_agents"], 3)
        self.assertEqual(s["session_count"], 5)
        self.assertEqual(payload["top_agents"][0]["agent_name"], "incident-triage-agent")
        self.assertEqual(payload["top_agents"][0]["tokens"], 23860)
        self.assertEqual(payload["top_agents"][0]["requests"], 12)
        self.assertIn("trace-a", payload["top_agents"][0]["trace_ids"])
        self.assertIn("trace-e", payload["top_agents"][0]["trace_ids"])

    def test_galileo_summary_counts_controls(self):
        o11y = build_summary(self.rows)
        g = summarize_galileo(self.galileo, o11y)
        self.assertEqual(g["project"], "clus-demo")
        self.assertEqual(g["project_id"], "0ba7b20d-8262-44c4-b230-547a0cd74b2b")
        self.assertEqual(g["log_stream"], "clus-demo")
        self.assertEqual(g["log_stream_id"], "82b893bd-fa1f-411e-81e8-e12ca66692ad")
        self.assertEqual(g["runtime_control_events"], 4)
        self.assertEqual(g["denies"], 1)
        self.assertEqual(g["warns"], 1)
        self.assertEqual(g["steers"], 1)
        self.assertEqual(g["human_reviews"], 1)
        self.assertEqual(g["failed_evals"], 2)
        self.assertEqual(g["evidence"][0]["join_key"], "trace_id")

    def test_merge_adds_runtime_cards_and_agent_blocks(self):
        o11y = build_summary(self.rows)
        merged = merge_galileo_enrichment(o11y, self.galileo)
        self.assertEqual(merged["schema_version"], "c3.agent_tokenomics.v0.2")
        self.assertEqual(merged["source"], "splunk_o11y_signalflow+galileo")
        self.assertEqual(merged["galileo"]["runtime_control_events"], 4)
        self.assertEqual(len(merged["runtime_governance_cards"]), 4)
        incident = next(a for a in merged["top_agents"] if a["agent_name"] == "incident-triage-agent")
        self.assertEqual(incident["galileo"]["denies"], 1)
        evidence = merged["runtime_governance_evidence"]
        self.assertEqual({row["decision"] for row in evidence}, {"deny", "human_review", "steer", "warn"})

    def test_local_control_simulator_is_deterministic(self):
        outcome = evaluate_runtime_action("delete prod deployment", target="terminal")
        self.assertEqual(outcome.decision, "deny")
        a = control_event_from_action("2026-05-09T16:00:00Z", "read file", target="filesystem")
        b = control_event_from_action("2026-05-09T16:00:00Z", "read file", target="filesystem")
        self.assertEqual(a["control_id"], b["control_id"])
        self.assertEqual(a["decision"], "allow")

    def test_cli_builder_and_click_command_write_valid_json(self):
        payload = build_payload_from_files(include_galileo=True)
        self.assertEqual(payload["galileo"]["denies"], 1)
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "summary.json"
            result = CliRunner().invoke(c3_tokenomics, ["generate", "--include-galileo", "--output", str(out)])
            self.assertEqual(result.exit_code, 0, result.output)
            data = json.loads(out.read_text())
            self.assertEqual(data["galileo"]["human_reviews"], 1)

    def test_galileo_env_overrides_fixture_metadata_without_leaking_key(self):
        env = {
            "GALILEO_API_KEY": "test-key-not-real",
            "GALILEO_PROJECT": "clus-demo-live",
            "GALILEO_LOG_STREAM": "agent-watch-live",
        }
        with patch.dict(os.environ, env):
            payload = build_payload_from_files(include_galileo=True)
        self.assertEqual(payload["galileo"]["project"], "clus-demo-live")
        self.assertIsNone(payload["galileo"]["project_id"])
        self.assertEqual(payload["galileo"]["log_stream"], "agent-watch-live")
        self.assertIsNone(payload["galileo"]["log_stream_id"])
        self.assertNotIn(env["GALILEO_API_KEY"], json.dumps(payload))

    def test_galileo_env_can_pin_created_project_id(self):
        env = {
            "GALILEO_PROJECT": "clus-demo",
            "GALILEO_PROJECT_ID": "0ba7b20d-8262-44c4-b230-547a0cd74b2b",
            "GALILEO_LOG_STREAM": "clus-demo",
            "GALILEO_LOG_STREAM_ID": "82b893bd-fa1f-411e-81e8-e12ca66692ad",
        }
        with patch.dict(os.environ, env):
            payload = build_payload_from_files(include_galileo=True)
        self.assertEqual(payload["galileo"]["project"], "clus-demo")
        self.assertEqual(payload["galileo"]["project_id"], env["GALILEO_PROJECT_ID"])
        self.assertEqual(payload["galileo"]["log_stream"], "clus-demo")
        self.assertEqual(payload["galileo"]["log_stream_id"], env["GALILEO_LOG_STREAM_ID"])

    def test_galileo_check_command_redacts_api_key(self):
        env = {"GALILEO_API_KEY": "test-key-not-real", "GALILEO_PROJECT": "clus-demo"}
        with patch.dict(os.environ, env):
            result = CliRunner().invoke(c3_tokenomics, ["galileo-check"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn('"api_key_configured": true', result.output)
        self.assertNotIn(env["GALILEO_API_KEY"], result.output)

    def test_mock_api_health_and_enriched_summary(self):
        server = make_server("127.0.0.1", 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            host, port = server.server_address
            conn = http.client.HTTPConnection(host, port, timeout=5)
            conn.request("GET", "/healthz")
            health = conn.getresponse()
            self.assertEqual(health.status, 200)
            health_data = json.loads(health.read())
            self.assertEqual(health_data["status"], "ok")
            self.assertIn("galileo", health_data["integrations"])

            conn.request("GET", "/v1/c3/agent-tokenomics/summary?include_galileo=true")
            response = conn.getresponse()
            self.assertEqual(response.status, 200)
            data = json.loads(response.read())
            self.assertEqual(data["galileo"]["runtime_control_events"], 4)
            self.assertTrue(data["debug"]["internal_only"])
            self.assertIn("api_key_configured", data["debug"]["galileo"])
        finally:
            server.shutdown()
            server.server_close()

    def test_galileo_live_project_check_uses_api_key_header(self):
        seen: dict[str, object] = {}

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                seen["path"] = self.path
                seen["api_key"] = self.headers.get("Galileo-API-Key")
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
                seen["body"] = body
                response = {
                    "projects": [
                        {
                            "id": "project-123",
                            "name": "clus-demo",
                            "num_logstreams": 1,
                            "log_streams": [{"id": "stream-123", "name": "agent-watch"}],
                        }
                    ],
                    "total_count": 1,
                }
                raw = json.dumps(response).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *_args):
                return

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            cfg = galileo_config_from_env(
                api_base=f"http://{server.server_address[0]}:{server.server_address[1]}",
                api_key="test-key-not-real",
                project="clus-demo",
                log_stream="agent-watch",
            )
            result = resolve_galileo_project(cfg)
        finally:
            server.shutdown()
            server.server_close()

        self.assertTrue(result["ok"])
        self.assertEqual(result["project"]["id"], "project-123")
        self.assertTrue(result["log_stream_matched"])
        self.assertEqual(seen["api_key"], "test-key-not-real")
        self.assertNotIn("test-key-not-real", json.dumps(result))

    def test_galileo_live_project_id_check_matches_log_stream(self):
        seen: dict[str, object] = {"paths": []}

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                seen["paths"].append(self.path)
                seen["api_key"] = self.headers.get("Galileo-API-Key")
                if self.path.endswith("/log_streams"):
                    response = [{"id": "stream-123", "name": "agent-watch"}]
                else:
                    response = {
                        "id": "project-123",
                        "name": "clus-demo",
                        "num_logstreams": 1,
                    }
                raw = json.dumps(response).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *_args):
                return

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            cfg = galileo_config_from_env(
                api_base=f"http://{server.server_address[0]}:{server.server_address[1]}",
                api_key="test-key-not-real",
                project_id="project-123",
                log_stream_id="stream-123",
            )
            result = resolve_galileo_project(cfg)
        finally:
            server.shutdown()
            server.server_close()

        self.assertTrue(result["ok"])
        self.assertEqual(result["matched_by"], "project_id")
        self.assertTrue(result["log_stream_matched"])
        self.assertEqual(seen["paths"], ["/v2/projects/project-123", "/v2/projects/project-123/log_streams"])
        self.assertEqual(seen["api_key"], "test-key-not-real")

    def test_fixtures_do_not_embed_real_galileo_api_key(self):
        forbidden_fragment = "0v" + "Kj" + "vj" + "Kf" + "Gm"
        for text in [json.dumps(self.galileo), json.dumps(self.rows)]:
            self.assertNotIn(forbidden_fragment, text)


if __name__ == "__main__":
    unittest.main()
