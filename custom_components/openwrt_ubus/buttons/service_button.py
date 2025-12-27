"""Support for OpenWrt service restart via ubus."""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from ..const import (
    CONF_SELECTED_SERVICES,
    CONF_ENABLE_SERVICE_CONTROLS,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up service restart button entities from a config entry."""

    # Check if service controls are enabled
    if not entry.data.get(CONF_ENABLE_SERVICE_CONTROLS, False):
        _LOGGER.debug("Service controls disabled, skipping service restart button setup")
        return

    # Get selected services
    selected_services = entry.data.get(CONF_SELECTED_SERVICES, [])
    if not selected_services:
        _LOGGER.debug("No services selected, skipping service restart button setup")
        return

    # Get shared data manager
    data_manager_key = f"data_manager_{entry.entry_id}"
    data_manager = hass.data[DOMAIN][data_manager_key]

    # Create button entities for each selected service
    entities = []
    for service_name in selected_services:
        entities.append(OpenwrtServiceRestartButton(data_manager, service_name, entry))
        _LOGGER.debug("Created restart button entity for service: %s", service_name)

    if entities:
        async_add_entities(entities, True)
        _LOGGER.info("Created %d service restart button entities", len(entities))


class OpenwrtServiceRestartButton(ButtonEntity):
    """Representation of an OpenWrt service restart button."""

    def __init__(self, data_manager, service_name: str, entry: ConfigEntry) -> None:
        """Initialize the button."""
        self.data_manager = data_manager
        self.service_name = service_name
        self.entry = entry
        self._host = entry.data[CONF_HOST]
        self._attr_unique_id = f"{self._host}_restart_{service_name}"
        self._attr_name = f"Restart {service_name}"
        self._attr_entity_registry_enabled_default = True
        self._attr_icon = "mdi:restart"

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
            "service_name": self.service_name,
            "host": self._host,
            "action": "restart",
        }

    async def async_press(self) -> None:
        """Handle the button press."""
        try:
            ubus = await self.data_manager.get_ubus_connection_async()

            # Restart the service
            await ubus.service_action(self.service_name, "restart")

            _LOGGER.info("Restarted service: %s", self.service_name)

            # Invalidate service status cache to force refresh
            self.data_manager.invalidate_cache("service_status")

        except Exception as exc:
            _LOGGER.error("Failed to restart service %s: %s", self.service_name, exc)
            raise
