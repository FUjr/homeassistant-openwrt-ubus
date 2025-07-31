"""Support for OpenWrt device tracking via ubus."""

from __future__ import annotations

from datetime import timedelta
import logging

import voluptuous as vol

from homeassistant.components.device_tracker import (
    PLATFORM_SCHEMA as DEVICE_TRACKER_PLATFORM_SCHEMA,
    ScannerEntity,
    SourceType,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant
from homeassistant.helpers import config_validation as cv, entity_registry as er
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity,
)

from .const import (
    CONF_DHCP_SOFTWARE,
    CONF_WIRELESS_SOFTWARE,
    DEFAULT_DHCP_SOFTWARE,
    DEFAULT_WIRELESS_SOFTWARE,
    DHCP_SOFTWARES,
    DOMAIN,
    WIRELESS_SOFTWARES,
)
from .shared_data_manager import SharedDataUpdateCoordinator

_LOGGER = logging.getLogger(__name__)

SCAN_INTERVAL = timedelta(seconds=30)

PLATFORM_SCHEMA = DEVICE_TRACKER_PLATFORM_SCHEMA.extend(
    {
        vol.Required(CONF_HOST): cv.string,
        vol.Required(CONF_PASSWORD): cv.string,
        vol.Required(CONF_USERNAME): cv.string,
        vol.Optional(CONF_WIRELESS_SOFTWARE, default=DEFAULT_WIRELESS_SOFTWARE): vol.In(
            WIRELESS_SOFTWARES
        ),
        vol.Optional(CONF_DHCP_SOFTWARE, default=DEFAULT_DHCP_SOFTWARE): vol.In(
            DHCP_SOFTWARES
        ),
    }
)
async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up device tracker from a config entry."""
    
    # Get shared data manager
    data_manager_key = f"data_manager_{entry.entry_id}"
    data_manager = hass.data[DOMAIN][data_manager_key]
    
    # Create coordinator using shared data manager
    coordinator = SharedDataUpdateCoordinator(
        hass,
        data_manager,
        ["device_statistics"],  # Data types this coordinator needs
        f"{DOMAIN}_tracker_{entry.data[CONF_HOST]}",
        SCAN_INTERVAL,
    )
    
    # Store tracking attributes
    coordinator.known_devices = set()
    coordinator.async_add_entities = async_add_entities
    coordinator.mac2name = {}  # For storing DHCP mappings
    
    # Initialize known_devices from existing entity registry entries
    await _restore_known_devices_from_registry(hass, entry, coordinator)
    _LOGGER.debug("Restored %d known devices from registry", len(coordinator.known_devices))

    # Add update listener for dynamic device creation
    async def _handle_coordinator_update_async():
        """Handle coordinator updates and create new entities for new devices."""
        if not coordinator.data or "device_statistics" not in coordinator.data:
            return
            
        device_stats = coordinator.data["device_statistics"]
        # Extract MAC addresses from device statistics
        current_devices = set(device_stats.keys())
        new_devices = current_devices - coordinator.known_devices
        
        if new_devices:
            _LOGGER.info("Found %d new devices for tracking: %s", len(new_devices), new_devices)
            new_entities = await _create_entities_for_devices(hass, entry, coordinator, new_devices)
            if new_entities:
                async_add_entities(new_entities, True)
                _LOGGER.info("Created %d device tracker entities", len(new_entities))

    def _handle_coordinator_update():
        """Sync wrapper for coordinator update handler."""
        hass.async_create_task(_handle_coordinator_update_async())

    # Fetch initial data
    try:
        await coordinator.async_config_entry_first_refresh()
    except Exception as exc:
        _LOGGER.warning("Initial data fetch failed, will retry automatically: %s", exc)

    # Create device tracker entities for each detected device
    if coordinator.data and coordinator.data.get("device_statistics"):
        device_stats = coordinator.data["device_statistics"]
        device_macs = set(device_stats.keys())
        _LOGGER.info("Initial scan found %d devices", len(device_macs))
        _LOGGER.debug("Initial devices detected: %s", device_macs)
        
        new_entities = await _create_entities_for_devices(hass, entry, coordinator, device_macs)
        if new_entities:
            async_add_entities(new_entities, True)
            _LOGGER.info("Created %d initial device tracker entities", len(new_entities))
        else:
            _LOGGER.info("No new entities to create (all devices already exist)")
    else:
        _LOGGER.info("No devices found in initial scan, entities will be created dynamically as devices are discovered")

    # Register the update listener
    coordinator.async_add_listener(_handle_coordinator_update)


async def _restore_known_devices_from_registry(hass: HomeAssistant, entry: ConfigEntry, coordinator: SharedDataUpdateCoordinator) -> None:
    """Restore known devices from existing entity registry entries."""
    entity_registry = er.async_get(hass)
    existing_entities = er.async_entries_for_config_entry(entity_registry, entry.entry_id)
    for entity_entry in existing_entities:
        if entity_entry.domain == "device_tracker" and entity_entry.platform == DOMAIN:
            # Extract MAC address from unique_id (format: "{host}_{mac_address}")
            if entity_entry.unique_id and "_" in entity_entry.unique_id:
                mac_address = entity_entry.unique_id.split("_", 1)[1].upper()  # Normalize to uppercase
                coordinator.known_devices.add(mac_address)
                _LOGGER.debug("Restored known device from registry: %s", mac_address)


async def _create_entities_for_devices(hass: HomeAssistant, entry: ConfigEntry, coordinator: SharedDataUpdateCoordinator, mac_addresses: set[str]) -> list:
    """Create device tracker entities for the given MAC addresses."""
    entity_registry = er.async_get(hass)
    new_entities = []
    
    for mac_address in mac_addresses:
        # Normalize MAC address format to ensure consistency
        mac_address = mac_address.upper()
        
        # Skip if already in known devices
        if mac_address in coordinator.known_devices:
            _LOGGER.debug("Device %s already in known devices, skipping", mac_address)
            continue
            
        # Check if entity already exists in registry
        unique_id = f"{entry.data[CONF_HOST]}_{mac_address}"
        existing_entity_id = entity_registry.async_get_entity_id(
            "device_tracker", DOMAIN, unique_id
        )
        
        if existing_entity_id:
            _LOGGER.debug(
                "Device tracker entity %s already exists with entity_id %s, adding to known devices",
                unique_id, existing_entity_id
            )
            # Add to known devices to prevent repeated checks
            coordinator.known_devices.add(mac_address)
            continue
        
        # Create device tracker entity for the new device
        try:
            entity = OpenwrtDeviceTracker(coordinator, mac_address)
            # Ensure the entity is enabled by default
            entity._attr_entity_registry_enabled_default = True
            new_entities.append(entity)
            coordinator.known_devices.add(mac_address)
            _LOGGER.debug("Created device tracker entity for %s with unique_id %s", mac_address, unique_id)
        except Exception as exc:
            _LOGGER.error("Failed to create entity for device %s: %s", mac_address, exc)
            continue
    
    return new_entities


class OpenwrtDeviceTracker(CoordinatorEntity, ScannerEntity):
    """Representation of a device tracker entity."""

    def __init__(self, coordinator: SharedDataUpdateCoordinator, mac_address: str) -> None:
        """Initialize the device tracker."""
        super().__init__(coordinator)
        self.mac_address = mac_address
        self._host = coordinator.data_manager.entry.data[CONF_HOST]
        self._attr_unique_id = f"{self._host}_{mac_address}"
        self._attr_name = None  # Will be set dynamically
        self._attr_entity_registry_enabled_default = True  # Enable by default

    @property
    def device_info(self) -> DeviceInfo:
        """Return device info with updated device name."""
        device_name = self._get_device_name()
        device_info_dict = {
            "identifiers": {(DOMAIN, self.mac_address)},
            "name": device_name,
            "model": "Network Device",
            "connections": {("mac", self.mac_address)},
        }
        
        # Only set via_device if we have a valid AP device (not "Unknown AP")
        if self.ap_device != "Unknown AP":
            device_info_dict["via_device"] = (DOMAIN, self.via_device)
        
        return DeviceInfo(**device_info_dict)

    @property
    def ap_device(self) -> str:
        """Return the access point device this device is connected to."""
        # Get device statistics from shared coordinator
        device_stats = self.coordinator.data.get("device_statistics", {})
        device_data = device_stats.get(self.mac_address) or device_stats.get(self.mac_address.upper())
        if device_data:
            return device_data.get("ap_device", "Unknown AP")
        return "Unknown AP"

    @property
    def via_device(self) -> str:
        """Return the via device info for this device."""
        if self.ap_device != "Unknown AP":
            return f"{self._host}_ap_{self.ap_device}"
        return self._host

    @property
    def ap_device(self) -> str:
        """Return the access point device this device is connected to."""
        # Get device statistics from shared coordinator
        device_stats = self.coordinator.data.get("device_statistics", {})
        device_data = device_stats.get(self.mac_address) or device_stats.get(self.mac_address.upper())
        if device_data:
            return device_data.get("ap_device", "Unknown AP")
        return "Unknown AP"

    @property
    def via_device(self) -> str:
        """Return the via device info for this device."""
        if self.ap_device != "Unknown AP":
            return f"{self._host}_ap_{self.ap_device}"
        return self._host

    def _get_device_name(self) -> str:
        """Get the device name from coordinator data or fallback to MAC."""
        connected_router = self._host or "Unknown Router"
        
        # Get device statistics from shared coordinator
        device_stats = self.coordinator.data.get("device_statistics", {})
        device_data = device_stats.get(self.mac_address) or device_stats.get(self.mac_address.upper())
        
        if device_data:
            base_name = f"{connected_router}({self.ap_device})" if self.ap_device != "Unknown AP" else connected_router
            hostname = device_data.get("hostname")
            if hostname and hostname != self.mac_address and hostname != self.mac_address.upper() and hostname != "*":
                return f"{base_name} {hostname}"
            else:
                return f"{base_name} {self.mac_address.replace(':', '')}"
        
        # Fallback to MAC address if no device data found
        return f"{connected_router} {self.mac_address.replace(':', '')}"

    @property
    def name(self) -> str:
        """Return the name of the device."""
        return self._get_device_name()

    @property
    def source_type(self) -> SourceType:
        """Return the source type of the device."""
        return SourceType.ROUTER

    @property
    def is_connected(self) -> bool:
        """Return true if the device is connected to the network."""
        # Get device statistics from shared coordinator
        device_stats = self.coordinator.data.get("device_statistics", {})
        device_data = device_stats.get(self.mac_address) or device_stats.get(self.mac_address.upper())
        
        if device_data:
            connected = device_data.get("connected", False)
            _LOGGER.debug("Device %s connection status: %s", self.mac_address, connected)
            return connected
        
        _LOGGER.debug("Device %s not found in device statistics, assuming disconnected", self.mac_address)
        return False

    @property
    def available(self) -> bool:
        """Return True if coordinator is available."""
        return self.coordinator.last_update_success

    @property
    def extra_state_attributes(self) -> dict[str, str]:
        """Return the device state attributes."""
        attributes = {
            "host": self._host,
            "mac": self.mac_address,
        }

        # Get device statistics from shared coordinator
        device_stats = self.coordinator.data.get("device_statistics", {})
        device_data = device_stats.get(self.mac_address) or device_stats.get(self.mac_address.upper())
        
        if device_data:
            attributes.update({
                "name": self._get_device_name(),
                "ap_device": device_data.get("ap_device", "Unknown AP"),
                "hostname": device_data.get("hostname", self.mac_address),
                "connection_type": "wireless",
                "router": self._host,
                "ip_address": device_data.get("ip_address", "Unknown IP"),
            })
        else:
            attributes.update({
                "last_seen": "disconnected",
                "connection_type": "wireless",
            })

        return attributes
