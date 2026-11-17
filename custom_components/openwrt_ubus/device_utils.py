"""Device registry helpers (HA 2026.8+: devices belong to one config entry)."""

from __future__ import annotations

from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.device_registry import DeviceInfo

from .const import DOMAIN


def get_device_id(hass: HomeAssistant, entry_id: str, identifier: str) -> str | None:
    """Return the device id of one of our devices, or None if it does not exist (yet)."""
    device = dr.async_get(hass).async_get_device_by_identifier((DOMAIN, identifier), entry_id)
    return device.id if device else None


def link_via(info: DeviceInfo, hass: HomeAssistant, entry_id: str, identifier: str) -> DeviceInfo:
    """Set via_device_id on a DeviceInfo, best effort.

    The key is only added when the parent already exists, because passing None
    would clear an existing link.
    """
    if (parent_id := get_device_id(hass, entry_id, identifier)) is not None:
        info["via_device_id"] = parent_id
    return info
