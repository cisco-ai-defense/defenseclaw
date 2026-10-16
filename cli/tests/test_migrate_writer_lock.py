"""GAP-1455: the 0.x import rewrites the config document under the config
writer's lock whatever its file name.

``DEFENSECLAW_CONFIG`` may name a config that is not called ``config.yaml``.
The migration took ``config.yaml.lock`` only for a file with that name, so a
step rewrote such a config next to a running writer (``config set``, the
gateway) and recorded no generation.
"""

from __future__ import annotations

import hashlib
import threading

from defenseclaw import config_writer
from defenseclaw.migrations import MigrationContext, _migrate_0_4_0_token_env_in_config

LEGACY = "gateway:\n  token_env: OPENCLAW_GATEWAY_TOKEN\n"
MIGRATED = "gateway:\n  token_env: DEFENSECLAW_GATEWAY_TOKEN\n"


def test_an_alternate_config_name_takes_the_migration_writer_lock(tmp_path, monkeypatch):
    data_dir = tmp_path / "home"
    data_dir.mkdir()
    config = tmp_path / "etc" / "defenseclaw.yaml"
    config.parent.mkdir()
    config.write_text(LEGACY, encoding="utf-8")
    monkeypatch.setenv("DEFENSECLAW_CONFIG", str(config))
    ctx = MigrationContext(openclaw_home="", data_dir=str(data_dir))
    assert ctx.active_config_path() == str(config)

    failures: list[BaseException] = []

    def migrate() -> None:
        try:
            _migrate_0_4_0_token_env_in_config(ctx)
        except BaseException as exc:  # surfaced in the main thread
            failures.append(exc)

    worker = threading.Thread(target=migrate, daemon=True)
    with config_writer.hold_lock(str(config)):
        worker.start()
        worker.join(timeout=1.0)
        # The step must wait for the writer that holds the lock.
        assert worker.is_alive(), "the migration step finished while another writer held the lock"
        assert config.read_text(encoding="utf-8") == LEGACY
    worker.join(timeout=30)
    assert not worker.is_alive()
    assert not failures, failures
    assert config.read_text(encoding="utf-8") == MIGRATED
    state = config_writer.read_generation_state(str(config))
    assert state.actor == config_writer.ACTOR_MIGRATION
    assert state.config_sha256 == hashlib.sha256(MIGRATED.encode("utf-8")).hexdigest()
