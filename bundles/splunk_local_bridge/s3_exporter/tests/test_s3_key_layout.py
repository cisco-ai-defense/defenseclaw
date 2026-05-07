import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import export_splunk_to_s3 as exporter


def _config(tmp_path):
    return exporter.ExportConfig(
        enabled=True,
        once=True,
        bucket="agentwatch-demo",
        prefix="agentwatch/defenseclaw",
        aws_region="us-west-2",
        endpoint_url=None,
        sse=None,
        splunk_base_url="https://splunk:8089",
        splunk_username="admin",
        splunk_password="secret",
        splunk_verify_tls=False,
        interval_seconds=60,
        window_seconds=300,
        lookback_seconds=30,
        checkpoint_file=tmp_path / "checkpoint.json",
        tenant_id="c3-demo-tenant",
        workspace_id="workspace-demo",
        deployment_environment="local",
    )


def test_s3_key_layout_uses_partitions_and_safe_filename(tmp_path):
    key = exporter.s3_data_key(
        _config(tmp_path),
        "2026-05-06T12:00:00Z",
        "2026-05-06T12:05:00Z",
    )

    assert key.startswith(
        "agentwatch/defenseclaw/tenant_id=c3-demo-tenant/workspace_id=workspace-demo/dt=2026-05-06/hour=12/"
    )
    filename = key.rsplit("/", 1)[1]
    assert filename == "defenseclaw-splunk-local-20260506T120000Z-20260506T120500Z.jsonl.gz"
    assert " " not in filename
    assert ":" not in filename


def test_manifest_key_without_prefix_has_no_leading_slash(tmp_path):
    base = _config(tmp_path)
    config = exporter.ExportConfig(**{**base.__dict__, "prefix": ""})

    key = exporter.manifest_key(config, "2026-05-06T12:05:00Z")

    assert key == "_manifests/manifest-20260506T120500Z.json"
