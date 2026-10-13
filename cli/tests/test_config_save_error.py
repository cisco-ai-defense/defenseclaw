from __future__ import annotations

from unittest.mock import patch

import pytest
from defenseclaw.config import ConfigSaveError, default_config


def test_config_save_names_file_and_cause_when_atomic_write_is_refused(tmp_path):
    cfg = default_config()
    cfg.data_dir = str(tmp_path)
    with patch("defenseclaw.config_writer.write_with", side_effect=PermissionError(1, "Operation not permitted")):
        with pytest.raises(ConfigSaveError) as failure:
            cfg.save()
    assert failure.value.path == str(tmp_path / "config.yaml")
    assert "Operation not permitted" in str(failure.value)
