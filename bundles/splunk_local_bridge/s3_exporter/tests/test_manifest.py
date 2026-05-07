import gzip
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import export_splunk_to_s3 as exporter


class FakeS3Client:
    def __init__(self):
        self.objects = []

    def put_object(self, **kwargs):
        self.objects.append(kwargs)


def _set_required_env(monkeypatch, tmp_path):
    monkeypatch.setenv("S3_EXPORT_ENABLED", "true")
    monkeypatch.setenv("S3_BUCKET", "agentwatch-demo")
    monkeypatch.setenv("S3_PREFIX", "agentwatch/defenseclaw")
    monkeypatch.setenv("S3_EXPORT_CHECKPOINT_FILE", str(tmp_path / "checkpoint.json"))
    monkeypatch.setenv("TENANT_ID", "c3-demo-tenant")
    monkeypatch.setenv("WORKSPACE_ID", "workspace-demo")
    monkeypatch.setenv("S3_SSE", "")


def test_write_batch_uploads_data_and_manifest(monkeypatch, tmp_path):
    _set_required_env(monkeypatch, tmp_path)
    client = FakeS3Client()
    monkeypatch.setattr(exporter, "_s3_client", lambda config: client)
    rows = [
        {
            "schema_version": exporter.SCHEMA_VERSION,
            "export_event_id": "abc",
            "tenant_id": "c3-demo-tenant",
            "workspace_id": "workspace-demo",
            "raw": "{}",
        }
    ]

    manifest = exporter.write_batch(rows, "2026-05-06T12:00:00Z", "2026-05-06T12:05:00Z")

    assert manifest is not None
    assert manifest["record_count"] == 1
    assert manifest["tenant_id"] == "c3-demo-tenant"
    assert manifest["workspace_id"] == "workspace-demo"
    assert manifest["object_key"].endswith("defenseclaw-splunk-local-20260506T120000Z-20260506T120500Z.jsonl.gz")
    assert len(client.objects) == 2
    data_object, manifest_object = client.objects
    assert data_object["Key"] == manifest["object_key"]
    assert manifest_object["Key"] == "agentwatch/defenseclaw/_manifests/manifest-20260506T120500Z.json"
    assert gzip.decompress(data_object["Body"]).decode("utf-8").count("\n") == 1
    assert json.loads(manifest_object["Body"])["sha256"] == manifest["sha256"]
