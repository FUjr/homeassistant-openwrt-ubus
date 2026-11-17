"""Runtime data of a config entry (stored in ``entry.runtime_data``)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .shared_data_manager import SharedUbusDataManager


@dataclass
class OpenwrtRuntimeData:
    """Everything that belongs to ONE router; nothing here is shared between entries."""

    data_manager: SharedUbusDataManager
    # Optional router features, detected once at setup
    modem_ctrl_available: bool = False
    mwan3_available: bool = False
    nlbwmon_available: bool = False
    # Coordinators created by the platforms, shut down on unload
    coordinators: list[Any] = field(default_factory=list)
