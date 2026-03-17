"""Support for OpenWrt system reboot via ubus."""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.button import ButtonDeviceClass, ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from ..const import DOMAIN

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the system reboot button entity from a config entry."""
    data_manager_key = f"data_manager_{entry.entry_id}"
    data_manager = hass.data[DOMAIN][data_manager_key]

    async_add_entities([OpenwrtRebootButton(data_manager, entry)], True)
    _LOGGER.debug("Created reboot button entity for %s", entry.data[CONF_HOST])


class OpenwrtRebootButton(ButtonEntity):
    """Representation of an OpenWrt system reboot button."""

    _attr_device_class = ButtonDeviceClass.RESTART
    _attr_icon = "mdi:restart"
    _attr_entity_registry_enabled_default = True

    def __init__(self, data_manager, entry: ConfigEntry) -> None:
        """Initialize the button."""
        self._data_manager = data_manager
        self._host = entry.data[CONF_HOST]
        self._attr_unique_id = f"{self._host}_system_reboot"
        self._attr_name = "Reboot"

    @property
    def device_info(self) -> DeviceInfo:
        """Return device info."""
        return DeviceInfo(
            identifiers={(DOMAIN, self._host)},
            name=f"OpenWrt Router ({self._host})",
            manufacturer="OpenWrt",
            model="Router",
        )

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return the state attributes."""
        return {
            "host": self._host,
            "action": "reboot",
        }

    async def async_press(self) -> None:
        """Trigger a system reboot."""
        try:
            ubus = await self._data_manager.get_ubus_connection_async()
            await ubus.system_reboot()
            _LOGGER.info("Reboot command sent to %s", self._host)
        except Exception as exc:
            _LOGGER.error("Failed to reboot %s: %s", self._host, exc)
            raise
