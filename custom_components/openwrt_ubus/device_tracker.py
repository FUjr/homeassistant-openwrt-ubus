"""Support for OpenWrt device tracking via ubus."""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

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


async def _restore_known_devices_from_registry(hass: HomeAssistant, entry: ConfigEntry,
                                               coordinator: SharedDataUpdateCoordinator) -> None:
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


async def _create_entities_for_devices(hass: HomeAssistant, entry: ConfigEntry,
                                       coordinator: SharedDataUpdateCoordinator, mac_addresses: set[str]) -> list:
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
        self._attr_mac_address = mac_address
        self._attr_source_type = SourceType.ROUTER
        self._host = coordinator.data_manager.entry.data[CONF_HOST]
        self._attr_unique_id = f"{self._host}_{mac_address}"
        self._attr_name = None  # Will be set dynamically
        self._attr_entity_registry_enabled_default = True  # Enable by default

    @property
    def name(self) -> str:
        """Return the name of the entity."""
        hostname = self.hostname

        if hostname and hostname != self._attr_mac_address and hostname != self._attr_mac_address.upper() and hostname != "*":
            return hostname

        return self._attr_mac_address.replace(':', '')

    @property
    def is_connected(self) -> bool:
        """Return true if the device is connected to the network."""
        if device_data := self._device_data():
            connected = device_data.get("connected", False)
            _LOGGER.debug("Device %s connection status: %s", self._attr_mac_address, connected)
            return connected

        _LOGGER.debug("Device %s not found in device statistics, assuming disconnected", self._attr_mac_address)
        return False

    @property
    def extra_state_attributes(self) -> dict[str, str]:
        """Return the device state attributes."""
        attributes = {
            "connection_type": "wireless",
        }

        if self.is_connected:
            ap_device = "Unknown AP"
            if device_data := self._device_data():
                ap_device = device_data.get("ap_device", "Unknown AP")
            attributes.update({
                "ap_device": ap_device,
                "router": self._host,
            })
        else:
            attributes.update({
                "last_seen": "disconnected",
            })

        return attributes

    def _device_data(self) -> dict[str, Any] | None:
        device_stats = self.coordinator.data.get("device_statistics", {})
        return device_stats.get(self._attr_mac_address) or device_stats.get(self._attr_mac_address.upper())

    @property
    def hostname(self) -> str | None:
        """Return the hostname of the device."""
        if device_data := self._device_data():
            return device_data.get("hostname")
        return None

    @property
    def ip_address(self) -> str | None:
        """Return the IP address of the device."""
        if device_data := self._device_data():
            return device_data.get("ip_address")
        return None
