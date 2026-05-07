import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import export_splunk_to_s3 as exporter


class FakeResponse:
    def __init__(self, rows):
        self.rows = rows

    def raise_for_status(self):
        return None

    def iter_lines(self, decode_unicode=True):
        for row in self.rows:
            yield json.dumps({"preview": False, "result": row})


class FakeS3Client:
    def __init__(self, fail=False):
        self.fail = fail
        self.objects = []

    def put_object(self, **kwargs):
        if self.fail:
            raise RuntimeError("upload failed")
        self.objects.append(kwargs)


def _set_env(monkeypatch, tmp_path):
    monkeypatch.setenv("S3_EXPORT_ENABLED", "true")
    monkeypatch.setenv("S3_EXPORT_ONCE", "true")
    monkeypatch.setenv("S3_BUCKET", "agentwatch-demo")
    monkeypatch.setenv("S3_PREFIX", "agentwatch/defenseclaw")
    monkeypatch.setenv("SPLUNK_BASE_URL", "https://splunk:8089")
    monkeypatch.setenv("SPLUNK_VERIFY_TLS", "false")
    monkeypatch.setenv("S3_EXPORT_CHECKPOINT_FILE", str(tmp_path / "checkpoint.json"))
    monkeypatch.setenv("S3_SSE", "")


def _splunk_row():
    return {
        "_time": "1770000000.123",
        "_indextime": "1770000001",
        "index": "defenseclaw_local",
        "source": "defenseclaw",
        "sourcetype": "defenseclaw:json",
        "_raw": '{"message":"ok"}',
    }


def test_splunk_export_reads_line_delimited_results(monkeypatch):
    captured = {}

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured["data"] = kwargs["data"]
        return FakeResponse([_splunk_row()])

    monkeypatch.setattr(exporter.requests, "post", fake_post)

    rows = list(
        exporter.splunk_export(
            "https://splunk:8089",
            "admin",
            "secret",
            False,
            "2024-05-06T00:00:00Z",
            "2024-05-06T00:05:00Z",
        )
    )

    assert rows == [_splunk_row()]
    assert captured["url"] == "https://splunk:8089/services/search/jobs/export"
    assert captured["data"]["output_mode"] == "json"
    assert "index=defenseclaw_local" in captured["data"]["search"]
    assert 'earliest="1714953600"' in captured["data"]["search"]
    assert 'latest="1714953900"' in captured["data"]["search"]


def test_load_config_uses_local_splunk_defaults(monkeypatch, tmp_path):
    _set_env(monkeypatch, tmp_path)

    config = exporter.load_config()

    assert config.splunk_username == "admin"
    assert config.splunk_password == "DefenseClawLocalMode1!"


def test_run_once_uploads_and_advances_checkpoint(monkeypatch, tmp_path):
    _set_env(monkeypatch, tmp_path)
    client = FakeS3Client()
    monkeypatch.setattr(exporter, "_s3_client", lambda config: client)
    monkeypatch.setattr(exporter, "splunk_export", lambda *args, **kwargs: [_splunk_row()])

    status = exporter.run_once()

    assert status["record_count"] == 1
    assert len(client.objects) == 2
    assert exporter.load_checkpoint(tmp_path / "checkpoint.json") == status["latest"]


def test_run_once_advances_checkpoint_with_no_rows(monkeypatch, tmp_path):
    _set_env(monkeypatch, tmp_path)
    client = FakeS3Client()
    monkeypatch.setattr(exporter, "_s3_client", lambda config: client)
    monkeypatch.setattr(exporter, "splunk_export", lambda *args, **kwargs: [])

    status = exporter.run_once()

    assert status["record_count"] == 0
    assert client.objects == []
    assert exporter.load_checkpoint(tmp_path / "checkpoint.json") == status["latest"]


def test_run_once_does_not_advance_checkpoint_when_upload_fails(monkeypatch, tmp_path):
    _set_env(monkeypatch, tmp_path)
    monkeypatch.setattr(exporter, "_s3_client", lambda config: FakeS3Client(fail=True))
    monkeypatch.setattr(exporter, "splunk_export", lambda *args, **kwargs: [_splunk_row()])

    try:
        exporter.run_once()
    except RuntimeError as exc:
        assert str(exc) == "upload failed"
    else:
        raise AssertionError("expected upload failure")

    assert exporter.load_checkpoint(tmp_path / "checkpoint.json") is None
