"""Support for OpenWrt service control via ubus."""

from __future__ import annotations

from datetime import timedelta
import logging
from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity,
    DataUpdateCoordinator,
    UpdateFailed,
)

from .const import (
    CONF_SELECTED_SERVICES,
    CONF_ENABLE_SERVICE_CONTROLS,
    DOMAIN,
    API_SUBSYS_RC,
    API_METHOD_LIST,
    API_METHOD_INIT,
)
from .shared_data_manager import SharedDataUpdateCoordinator

_LOGGER = logging.getLogger(__name__)

SCAN_INTERVAL = timedelta(seconds=60)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up switch entities from a config entry."""
    
    # Check if service controls are enabled
    if not entry.data.get(CONF_ENABLE_SERVICE_CONTROLS, False):
        _LOGGER.debug("Service controls disabled, skipping switch setup")
        return
    
    # Get selected services
    selected_services = entry.data.get(CONF_SELECTED_SERVICES, [])
    if not selected_services:
        _LOGGER.debug("No services selected, skipping switch setup")
        return
    
    # Get shared data manager
    data_manager_key = f"data_manager_{entry.entry_id}"
    data_manager = hass.data[DOMAIN][data_manager_key]
    
    # Create coordinator using shared data manager for service status
    coordinator = SharedDataUpdateCoordinator(
        hass,
        data_manager,
        ["service_status"],  # Data types this coordinator needs
        f"{DOMAIN}_services_{entry.data[CONF_HOST]}",
        SCAN_INTERVAL,
    )
    
    # Fetch initial data
    try:
        await coordinator.async_config_entry_first_refresh()
    except Exception as exc:
        _LOGGER.warning("Initial service data fetch failed, will retry automatically: %s", exc)
    
    # Create switch entities for each selected service
    entities = []
    for service_name in selected_services:
        entities.append(OpenwrtServiceSwitch(coordinator, service_name, entry))
        _LOGGER.debug("Created switch entity for service: %s", service_name)
    
    if entities:
        async_add_entities(entities, True)
        _LOGGER.info("Created %d service switch entities", len(entities))


class OpenwrtServiceSwitch(CoordinatorEntity, SwitchEntity):
    """Representation of an OpenWrt service switch."""

    def __init__(self, coordinator: SharedDataUpdateCoordinator, service_name: str, entry: ConfigEntry) -> None:
        """Initialize the switch."""
        super().__init__(coordinator)
        self.service_name = service_name
        self.entry = entry
        self._host = entry.data[CONF_HOST]
        self._attr_unique_id = f"{self._host}_service_{service_name}"
        self._attr_name = f"{service_name}"
        self._attr_entity_registry_enabled_default = True

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
    def is_on(self) -> bool:
        """Return true if the service is running."""
        if not self.coordinator.data or "service_status" not in self.coordinator.data:
            _LOGGER.debug("Service %s: No coordinator data or service_status missing. Data keys: %s", 
                         self.service_name, list(self.coordinator.data.keys()) if self.coordinator.data else "None")
            return False
        
        service_data = self.coordinator.data["service_status"].get(self.service_name, {})
        _LOGGER.debug("Service %s: Retrieved service data: %s", self.service_name, service_data)
        
        # OpenWrt RC returns: {"running": bool, "enabled": bool, "start_priority": int}
        if isinstance(service_data, dict):
            # Primary check: "running" field indicates actual service status
            running_status = service_data.get("running", False)
            _LOGGER.debug("Service %s: Running status=%s", self.service_name, running_status)
            return bool(running_status)
        
        # Default to False if no clear status is found
        _LOGGER.debug("Service %s: No valid service data, defaulting to False", self.service_name)
        return False

    @property
    def available(self) -> bool:
        """Return True if coordinator is available."""
        return self.coordinator.last_update_success

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return the state attributes."""
        attributes = {
            "service_name": self.service_name,
            "host": self._host,
        }
        
        if (self.coordinator.data and 
            "service_status" in self.coordinator.data and 
            self.service_name in self.coordinator.data["service_status"]):
            service_data = self.coordinator.data["service_status"][self.service_name]
            
            # Add service status details
            if isinstance(service_data, dict):
                attributes.update({
                    "enabled": service_data.get("enabled", False),
                    "running": service_data.get("running", False),
                    "start_priority": service_data.get("start_priority"),
                })
        
        return attributes

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn the service on."""
        try:
            ubus = await self.coordinator.data_manager.get_ubus_connection_async()
            
            # Start the service
            await ubus.service_action(self.service_name, "start")
            
            _LOGGER.info("Started service: %s", self.service_name)
            
            # Invalidate service status cache and trigger coordinator update
            self.coordinator.data_manager.invalidate_cache("service_status")
            await self.coordinator.async_request_refresh()
            
        except Exception as exc:
            _LOGGER.error("Failed to start service %s: %s", self.service_name, exc)
            raise

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn the service off."""
        try:
            ubus = await self.coordinator.data_manager.get_ubus_connection_async()
            
            # Stop the service
            await ubus.service_action(self.service_name, "stop")
            
            _LOGGER.info("Stopped service: %s", self.service_name)
            
            # Invalidate service status cache and trigger coordinator update
            self.coordinator.data_manager.invalidate_cache("service_status")
            await self.coordinator.async_request_refresh()
            
        except Exception as exc:
            _LOGGER.error("Failed to stop service %s: %s", self.service_name, exc)
            raise
