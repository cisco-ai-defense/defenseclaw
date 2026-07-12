#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the ``defenseclaw setup local-observability`` helpers.

Pinned regressions:

* ``_ports_contains`` must understand both single-port mappings
  (``127.0.0.1:3100->3100/tcp``) and the *ranged* mappings the
  otel-collector emits (``127.0.0.1:4317-4318->4317-4318/tcp``).
  An older single-port substring match silently said "no" for half
  of our own services, which made the preflight falsely report
  ports as held by a non-stack process and refuse to re-up an
  already-healthy stack.

* ``_find_orphan_containers`` must return only containers that
  exist *and* lack the expected compose project label. A
  pre-existing ``defenseclaw-grafana`` created via raw ``docker
  run`` (or by a foreign compose project) is what triggers
  ``Conflict. The container name '/defenseclaw-grafana' is already
  in use``; missing containers must NOT be reported as orphans.
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands.cmd_setup_local_observability import (
    _COMPOSE_PROJECT,
    _STACK_CONTAINERS,
    _apply_local_otlp_config,
    _find_orphan_containers,
    _ports_contains,
)
from defenseclaw.commands.redaction_status import redaction_status_hint

ROOT = Path(__file__).resolve().parents[2]
LOCAL_BRIDGE = ROOT / "bundles/local_observability_stack/bin/openclaw-observability-bridge"


class TestBridgeReadinessContract(unittest.TestCase):
    def test_up_waits_for_every_query_and_ingest_service(self):
        text = LOCAL_BRIDGE.read_text(encoding="utf-8")
        for marker in (
            'collector_ok="false"',
            'http://127.0.0.1:13133/',
            'http://127.0.0.1:3000/api/health',
            'http://127.0.0.1:9090/-/ready',
            'http://127.0.0.1:3200/ready',
            'http://127.0.0.1:3100/ready',
        ):
            self.assertIn(marker, text)


class TestV8LocalDestinationWriter(unittest.TestCase):
    def test_local_stack_uses_one_unified_v8_destination(self):
        app = SimpleNamespace(cfg=SimpleNamespace(data_dir="/tmp/defenseclaw-v8"))
        with (
            patch(
                "defenseclaw.commands.cmd_setup_observability._require_v8_operator_status",
                return_value=object(),
            ),
            patch(
                "defenseclaw.commands.cmd_setup_observability._add_v8_destination",
                return_value=(SimpleNamespace(changed=True), []),
            ) as add,
            patch(
                "defenseclaw.commands.cmd_setup_local_observability._reload_cfg_from_data_dir",
            ) as reload_cfg,
            patch("defenseclaw.observability.v8_writer.mutate_v8_config"),
        ):
            result = _apply_local_otlp_config(
                app,
                endpoint="127.0.0.1:4317",
                protocol="grpc",
                signals=("traces", "metrics", "logs"),
                service_name="defenseclaw",
            )

        self.assertIsNone(result)
        args, kwargs = add.call_args
        self.assertEqual(args[0], "/tmp/defenseclaw-v8")
        self.assertEqual(args[1].id, "local-otlp")
        self.assertEqual(args[2]["endpoint"], "127.0.0.1:4317")
        self.assertEqual(kwargs["name"], "local-observability")
        self.assertEqual(kwargs["signals"], ("traces", "metrics", "logs"))
        self.assertIsNone(kwargs["target"])
        reload_cfg.assert_called_once_with(app)

    def test_v8_redaction_summary_uses_route_policy(self):
        cfg = SimpleNamespace(_source_config_version=8)
        status, label, command = redaction_status_hint(cfg)
        self.assertEqual(status, "PER DESTINATION (defaults are unredacted)")
        self.assertIn("route redaction", label)
        self.assertIn("config show --effective", command)

# Real ``docker ps --format {{.Ports}}`` capture from a healthy stack.
# Mixes single-port mappings (Grafana / Loki / Prometheus / Tempo
# main port) with ranged mappings (otel-collector publishes
# ``4317-4318`` as a range) plus a tempo-secondary
# row that uses a comma-separated mapping list.
_HEALTHY_PORTS_BLOB = (
    "127.0.0.1:3000->3000/tcp\n"
    "127.0.0.1:4317-4318->4317-4318/tcp, "
    "127.0.0.1:8888->8888/tcp, "
    "127.0.0.1:13133->13133/tcp, "
    "55678-55679/tcp\n"
    "127.0.0.1:3100->3100/tcp\n"
    "127.0.0.1:9090->9090/tcp\n"
    "127.0.0.1:3200->3200/tcp, 127.0.0.1:9095->9095/tcp"
)


class TestPortsContains(unittest.TestCase):
    def test_single_ports_match(self):
        for port in (3000, 3100, 3200, 9090, 9095, 13133):
            self.assertTrue(
                _ports_contains(_HEALTHY_PORTS_BLOB, port),
                msg=f"single-port {port} should be detected",
            )

    def test_ranged_ports_match(self):
        # 4317 and 4318 come from "127.0.0.1:4317-4318->4317-4318/tcp".
        # Both boundary numbers of the OTLP receiver range must match.
        for port in (4317, 4318):
            self.assertTrue(
                _ports_contains(_HEALTHY_PORTS_BLOB, port),
                msg=f"ranged-port {port} should be detected",
            )

    def test_collector_self_metrics_port_matches(self):
        self.assertTrue(_ports_contains(_HEALTHY_PORTS_BLOB, 8888))
        self.assertFalse(_ports_contains(_HEALTHY_PORTS_BLOB, 8889))

    def test_unrelated_port_does_not_match(self):
        for port in (22, 80, 443, 9999, 65535):
            self.assertFalse(
                _ports_contains(_HEALTHY_PORTS_BLOB, port),
                msg=f"unrelated port {port} must not match",
            )

    def test_empty_blob_returns_false(self):
        self.assertFalse(_ports_contains("", 3000))
        self.assertFalse(_ports_contains("\n\n", 3000))

    def test_malformed_entry_is_ignored(self):
        # Garbage entries must not crash; only the well-formed
        # mapping should be detected.
        blob = "not-a-mapping\n127.0.0.1:3000->3000/tcp\nnan-nan/tcp"
        self.assertTrue(_ports_contains(blob, 3000))
        self.assertFalse(_ports_contains(blob, 9999))

    def test_unbound_container_port_is_ignored(self):
        # ``55678-55679/tcp`` (no host-side ``->`` arrow) is an
        # internal-only port. Operators don't see those held on the
        # host so we must NOT report them as owned.
        self.assertFalse(_ports_contains("55678-55679/tcp", 55678))


class TestFindOrphanContainers(unittest.TestCase):
    """``_find_orphan_containers`` shells out to ``docker inspect``;
    we patch ``subprocess.run`` to make this deterministic.
    """

    @staticmethod
    def _make_run(returns: dict[str, tuple[int, str]]):
        """Return a ``subprocess.run`` stub.

        ``returns`` maps container name → (returncode, stdout).
        Default is "container does not exist" (exit 1, empty stdout).
        """

        def _stub(cmd, *args, **kwargs):
            assert cmd[0] == "docker" and cmd[1] == "inspect"
            container = cmd[-1]
            rc, out = returns.get(container, (1, ""))
            return subprocess.CompletedProcess(cmd, rc, stdout=out, stderr="")

        return _stub

    def test_no_existing_containers_returns_empty_list(self):
        stub = self._make_run({})
        with patch(
            "defenseclaw.commands.cmd_setup_local_observability.subprocess.run",
            side_effect=stub,
        ):
            self.assertEqual(_find_orphan_containers(), [])

    def test_compose_owned_containers_are_not_orphans(self):
        stub = self._make_run({
            name: (0, _COMPOSE_PROJECT) for name in _STACK_CONTAINERS
        })
        with patch(
            "defenseclaw.commands.cmd_setup_local_observability.subprocess.run",
            side_effect=stub,
        ):
            self.assertEqual(_find_orphan_containers(), [])

    def test_unlabelled_container_is_orphan(self):
        # `defenseclaw-grafana` exists but has no compose project label
        # — this is the exact failure mode the user hit after a stray
        # `docker run --name=defenseclaw-grafana ...`.
        stub = self._make_run({"defenseclaw-grafana": (0, "")})
        with patch(
            "defenseclaw.commands.cmd_setup_local_observability.subprocess.run",
            side_effect=stub,
        ):
            self.assertEqual(_find_orphan_containers(), ["defenseclaw-grafana"])

    def test_foreign_compose_project_is_orphan(self):
        # A container labelled with a different compose project must
        # also be reported, because `docker compose up` would still
        # refuse to overwrite it.
        stub = self._make_run({"defenseclaw-grafana": (0, "some-other-project")})
        with patch(
            "defenseclaw.commands.cmd_setup_local_observability.subprocess.run",
            side_effect=stub,
        ):
            self.assertEqual(_find_orphan_containers(), ["defenseclaw-grafana"])

    def test_docker_unreachable_returns_empty_list(self):
        def stub(*args, **kwargs):
            raise FileNotFoundError("docker missing")

        with patch(
            "defenseclaw.commands.cmd_setup_local_observability.subprocess.run",
            side_effect=stub,
        ):
            self.assertEqual(_find_orphan_containers(), [])


if __name__ == "__main__":
    unittest.main()
