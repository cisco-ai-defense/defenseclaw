"""Shared exception types for dctest."""

from __future__ import annotations


class DctestError(Exception):
    """Base class for dctest errors."""


class RunNotFoundError(DctestError):
    """Raised when a referenced run id does not exist on disk."""


class CellNotFoundError(DctestError):
    """Raised when a referenced cell id does not exist within a run."""


class CaseNotFoundError(DctestError):
    """Raised when a referenced case id does not exist."""


class MatrixSelectionError(DctestError):
    """Raised when a matrix filter or selection file is malformed."""


class StageRunnerError(DctestError):
    """Raised when subprocess invocation of the agent backend fails."""


class StageSkipped(DctestError):
    """Raised by a stage that determines it has nothing to do.

    The CLI treats this as a soft pass and continues.
    """


class DoctorError(DctestError):
    """Raised when prerequisite checks fail."""


class SnapshotError(DctestError):
    """Raised when host-state snapshot or restore fails."""


class ProviderError(DctestError):
    """Raised when a provider switch fails (auth, endpoint, model)."""


class ConnectorError(DctestError):
    """Raised when a connector install/teardown fails."""


class ExecutorTimeout(DctestError):
    """Raised when a command under test exceeds its timeout."""
