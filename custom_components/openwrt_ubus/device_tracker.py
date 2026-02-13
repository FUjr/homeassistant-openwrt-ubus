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
from homeassistant.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
    CONF_IP_ADDRESS,
)
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
    CONF_TRACKING_METHOD,
    CONF_ENABLE_WIRED_TRACKER,
    DEFAULT_DHCP_SOFTWARE,
    DEFAULT_WIRELESS_SOFTWARE,
    DEFAULT_TRACKING_METHOD,
    DEFAULT_ENABLE_WIRED_TRACKER,
    DHCP_SOFTWARES,
    DOMAIN,
    WIRELESS_SOFTWARES,
)
from .shared_data_manager import SharedDataUpdateCoordinator

_LOGGER = logging.getLogger(__name__)

SCAN_INTERVAL = timedelta(seconds=30)


def _generate_unique_id(host: str, mac_address: str, tracking_method: str) -> str:
    """Generate unique_id based on tracking method.

    Args:
        host: Router hostname
        mac_address: Device MAC address (normalized uppercase)
        tracking_method: "uniqueid" or "combined"

    Returns:
        Unique ID string
    """
    if tracking_method == "uniqueid":
        return mac_address
    else:  # "combined" (default)
        return f"{host}_{mac_address}"


async def _migrate_device_tracker_unique_ids(
    hass: HomeAssistant,
    entry: ConfigEntry,
    old_tracking_method: str,
    new_tracking_method: str,
) -> None:
    """Migrate device tracker unique_ids when tracking method changes.

    Args:
        hass: Home Assistant instance
        entry: Config entry
        old_tracking_method: Previous tracking method
        new_tracking_method: New tracking method
    """
    if old_tracking_method == new_tracking_method:
        return

    entity_registry = er.async_get(hass)
    host = entry.data[CONF_HOST]

    _LOGGER.info(
        "Migrating device tracker unique_ids from '%s' to '%s'",
        old_tracking_method,
        new_tracking_method,
    )

    # Get all device tracker entities for this config entry
    existing_entities = er.async_entries_for_config_entry(entity_registry, entry.entry_id)
    migrated_count = 0

    for entity_entry in existing_entities:
        if entity_entry.domain != "device_tracker" or entity_entry.platform != DOMAIN:
            continue

        old_unique_id = entity_entry.unique_id

        # Extract MAC address from old unique_id
        if old_tracking_method == "combined":
            # Format: "{host}_{mac_address}"
            # Use rsplit to handle hostnames with underscores correctly
            if "_" in old_unique_id:
                mac_address = old_unique_id.rsplit("_", 1)[-1].upper()
            else:
                _LOGGER.warning("Cannot parse MAC from unique_id: %s", old_unique_id)
                continue
        else:  # old was "uniqueid"
            # Format: "{mac_address}"
            mac_address = old_unique_id.upper()

        # Generate new unique_id
        new_unique_id = _generate_unique_id(host, mac_address, new_tracking_method)

        if old_unique_id == new_unique_id:
            continue

        # Check if new unique_id already exists
        existing_entity_id = entity_registry.async_get_entity_id("device_tracker", DOMAIN, new_unique_id)

        if existing_entity_id and existing_entity_id != entity_entry.entity_id:
            _LOGGER.warning(
                "Cannot migrate %s to %s: new unique_id already exists for entity %s",
                old_unique_id,
                new_unique_id,
                existing_entity_id,
            )
            continue

        # Perform migration
        try:
            entity_registry.async_update_entity(entity_entry.entity_id, new_unique_id=new_unique_id)
            migrated_count += 1
            _LOGGER.debug(
                "Migrated entity %s: %s → %s",
                entity_entry.entity_id,
                old_unique_id,
                new_unique_id,
            )
        except Exception as exc:
            _LOGGER.error(
                "Failed to migrate entity %s from %s to %s: %s",
                entity_entry.entity_id,
                old_unique_id,
                new_unique_id,
                exc,
            )

    _LOGGER.info("Migration completed: %d entities migrated", migrated_count)


PLATFORM_SCHEMA = DEVICE_TRACKER_PLATFORM_SCHEMA.extend(
    {
        vol.Required(CONF_HOST): cv.string,
        vol.Optional(CONF_IP_ADDRESS): cv.string,
        vol.Optional(CONF_VERIFY_SSL, default=False): cv.boolean,
        vol.Required(CONF_PASSWORD): cv.string,
        vol.Required(CONF_USERNAME): cv.string,
        vol.Optional(CONF_WIRELESS_SOFTWARE, default=DEFAULT_WIRELESS_SOFTWARE): vol.In(WIRELESS_SOFTWARES),
        vol.Optional(CONF_DHCP_SOFTWARE, default=DEFAULT_DHCP_SOFTWARE): vol.In(DHCP_SOFTWARES),
    }
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up device tracker from a config entry."""

    # Get tracking method configuration
    tracking_method = entry.data.get(CONF_TRACKING_METHOD, DEFAULT_TRACKING_METHOD)

    # Check if tracking method changed and perform migration if needed
    # Store the current tracking method in hass.data for comparison on reload
    tracking_state_key = f"tracking_method_{entry.entry_id}"
    old_tracking_method = hass.data[DOMAIN].get(tracking_state_key)

    if old_tracking_method is not None and old_tracking_method != tracking_method:
        _LOGGER.info(
            "Tracking method changed from '%s' to '%s', starting migration",
            old_tracking_method,
            tracking_method,
        )
        await _migrate_device_tracker_unique_ids(hass, entry, old_tracking_method, tracking_method)

    # Store current tracking method for future comparisons
    hass.data[DOMAIN][tracking_state_key] = tracking_method

    # Get shared data manager
    data_manager_key = f"data_manager_{entry.entry_id}"
    data_manager = hass.data[DOMAIN][data_manager_key]

    # Check if wired tracker is enabled
    enable_wired_tracker = entry.options.get(
        CONF_ENABLE_WIRED_TRACKER,
        entry.data.get(CONF_ENABLE_WIRED_TRACKER, DEFAULT_ENABLE_WIRED_TRACKER),
    )

    # Determine which data types the coordinator needs
    data_types = ["device_statistics"]  # WiFi devices
    if enable_wired_tracker:
        data_types.append("wired_devices")  # Add wired devices if enabled

    # Create coordinator using shared data manager
    coordinator = SharedDataUpdateCoordinator(
        hass,
        data_manager,
        data_types,  # Data types this coordinator needs
        f"{DOMAIN}_tracker_{entry.data[CONF_HOST]}",
        SCAN_INTERVAL,
    )

    # Store tracking attributes
    coordinator.known_devices = set()
    coordinator.async_add_entities = async_add_entities
    coordinator.mac2name = {}  # For storing DHCP mappings
    coordinator.tracking_method = tracking_method  # Store tracking method

    # Store coordinator in hass.data for cross-router device tracking (only for uniqueid method)
    if tracking_method == "uniqueid":
        tracker_coordinators_key = "tracker_coordinators"
        if tracker_coordinators_key not in hass.data[DOMAIN]:
            hass.data[DOMAIN][tracker_coordinators_key] = {}
        hass.data[DOMAIN][tracker_coordinators_key][entry.entry_id] = coordinator
        _LOGGER.debug(
            "Stored tracker coordinator for %s (tracking_method=uniqueid)",
            entry.data[CONF_HOST],
        )

    # Initialize known_devices from existing entity registry entries
    await _restore_known_devices_from_registry(hass, entry, coordinator, tracking_method)
    _LOGGER.debug("Restored %d known devices from registry", len(coordinator.known_devices))

    # Add update listener for dynamic device creation
    async def _handle_coordinator_update_async():
        """Handle coordinator updates and create new entities for new devices."""
        if not coordinator.data:
            return

        # Merge device_statistics and wired_devices
        all_devices = {}
        
        # Add WiFi devices
        if "device_statistics" in coordinator.data:
            device_stats = coordinator.data["device_statistics"]
            all_devices.update(device_stats)
        
        # Add wired devices
        if enable_wired_tracker and "wired_devices" in coordinator.data:
            wired_devices = coordinator.data["wired_devices"]
            # Merge wired devices, but WiFi devices take priority
            for mac, device_info in wired_devices.items():
                if mac not in all_devices:
                    all_devices[mac] = device_info

        # Extract MAC addresses from all devices
        current_devices = set(all_devices.keys())
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
    if coordinator.data:
        # Merge device_statistics and wired_devices
        all_devices = {}
        
        # Add WiFi devices
        if "device_statistics" in coordinator.data:
            device_stats = coordinator.data["device_statistics"]
            all_devices.update(device_stats)
        
        # Add wired devices
        if enable_wired_tracker and "wired_devices" in coordinator.data:
            wired_devices = coordinator.data["wired_devices"]
            # Merge wired devices, but WiFi devices take priority
            for mac, device_info in wired_devices.items():
                if mac not in all_devices:
                    all_devices[mac] = device_info

        device_macs = set(all_devices.keys())
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


async def _restore_known_devices_from_registry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    coordinator: SharedDataUpdateCoordinator,
    tracking_method: str,
) -> None:
    """Restore known devices from existing entity registry entries."""
    entity_registry = er.async_get(hass)
    host = entry.data[CONF_HOST]
    existing_entities = er.async_entries_for_config_entry(entity_registry, entry.entry_id)

    for entity_entry in existing_entities:
        # Skip deleted entities (entity_id is None for deleted entities)
        # They should be recreated if device reconnects
        if entity_entry.entity_id is None:
            _LOGGER.debug("Skipping deleted entity with unique_id: %s", entity_entry.unique_id)
            continue

        if entity_entry.domain == "device_tracker" and entity_entry.platform == DOMAIN:
            # Extract MAC address from unique_id based on tracking method
            if entity_entry.unique_id:
                if tracking_method == "uniqueid":
                    # Format: "{mac_address}"
                    mac_address = entity_entry.unique_id.upper()
                else:  # "combined"
                    # Format: "{host}_{mac_address}"
                    # Use rsplit to handle hostnames with underscores correctly
                    if "_" in entity_entry.unique_id:
                        mac_address = entity_entry.unique_id.rsplit("_", 1)[-1].upper()
                    else:
                        _LOGGER.warning(
                            "Cannot parse MAC from unique_id: %s (expected format: {host}_{mac})",
                            entity_entry.unique_id,
                        )
                        continue

                # Don't add to known_devices during restore - let the entity creation flow handle it
                # This ensures entity objects are created for registry entities
                # coordinator.known_devices.add(mac_address)
                _LOGGER.debug(
                    "Found device in registry: %s (will create entity object during scan)",
                    mac_address,
                )


async def _create_entities_for_devices(
    hass: HomeAssistant,
    entry: ConfigEntry,
    coordinator: SharedDataUpdateCoordinator,
    mac_addresses: set[str],
) -> list:
    """Create device tracker entities for the given MAC addresses."""
    entity_registry = er.async_get(hass)
    new_entities = []
    tracking_method = coordinator.tracking_method
    host = entry.data[CONF_HOST]

    for mac_address in mac_addresses:
        # Normalize MAC address format to ensure consistency
        mac_address = mac_address.upper()

        # Skip if already in known devices
        if mac_address in coordinator.known_devices:
            _LOGGER.debug("Device %s already in known devices, skipping", mac_address)
            continue

        # Generate unique_id based on tracking method
        unique_id = _generate_unique_id(host, mac_address, tracking_method)

        # For uniqueid tracking, entity might be registered to ANY config entry
        # So we need to search more broadly
        existing_entity_id = None
        if tracking_method == "uniqueid":
            # Search for entity with this unique_id across all config entries
            for entity_entry in entity_registry.entities.values():
                if (
                    entity_entry.domain == "device_tracker"
                    and entity_entry.platform == DOMAIN
                    and entity_entry.unique_id == unique_id
                    and entity_entry.entity_id is not None
                ):  # Not deleted
                    existing_entity_id = entity_entry.entity_id
                    _LOGGER.debug(
                        "Found existing entity %s with unique_id %s (config_entry: %s)",
                        existing_entity_id,
                        unique_id,
                        entity_entry.config_entry_id,
                    )
                    break
        else:
            # For combined tracking, use normal lookup (should only exist in current config entry)
            existing_entity_id = entity_registry.async_get_entity_id("device_tracker", DOMAIN, unique_id)

        # Always create entity object - HA will handle duplicates via unique_id
        # This is critical: existing entities in registry need active Python objects too!
        if existing_entity_id:
            _LOGGER.debug(
                "Device tracker entity %s already exists in registry, creating entity object for updates",
                existing_entity_id,
            )

        # Create device tracker entity (new or existing)
        try:
            entity = OpenwrtDeviceTracker(coordinator, mac_address)
            # Ensure the entity is enabled by default
            entity._attr_entity_registry_enabled_default = True
            new_entities.append(entity)
            coordinator.known_devices.add(mac_address)
            if existing_entity_id:
                _LOGGER.debug(
                    "Created entity object for existing device tracker %s",
                    existing_entity_id,
                )
            else:
                _LOGGER.debug(
                    "Created new device tracker entity for %s with unique_id %s",
                    mac_address,
                    unique_id,
                )
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
        self._tracking_method = coordinator.tracking_method

        # Generate unique_id based on tracking method
        self._attr_unique_id = _generate_unique_id(self._host, mac_address, self._tracking_method)
        self._attr_name = None  # Will be set dynamically
        self._attr_entity_registry_enabled_default = True  # Enable by default

    def _get_device_data_from_any_coordinator(self) -> tuple[dict | None, str | None]:
        """Get device data from any coordinator (for uniqueid tracking method).

        Returns:
            Tuple of (device_data, coordinator_host) or (None, None) if not found
        """
        # First try the local coordinator (most likely case)
        device_stats = self.coordinator.data.get("device_statistics", {})
        device_data = device_stats.get(self.mac_address) or device_stats.get(self.mac_address.upper())

        if device_data and device_data.get("connected"):
            return device_data, self._host

        # If not found locally and tracking method is uniqueid, search in all coordinators
        if self._tracking_method == "uniqueid":
            tracker_coordinators_key = "tracker_coordinators"
            all_coordinators = self.hass.data.get(DOMAIN, {}).get(tracker_coordinators_key, {})

            for entry_id, other_coordinator in all_coordinators.items():
                # Skip the coordinator we already checked
                if other_coordinator == self.coordinator:
                    continue

                # Check if coordinator has data
                if not other_coordinator.data:
                    continue

                # Look for device in this coordinator's data
                other_stats = other_coordinator.data.get("device_statistics", {})
                device_data = other_stats.get(self.mac_address) or other_stats.get(self.mac_address.upper())

                if device_data and device_data.get("connected"):
                    # Found on another router
                    other_host = other_coordinator.data_manager.entry.data[CONF_HOST]
                    _LOGGER.debug(
                        "Device %s found on router %s (not on %s)",
                        self.mac_address,
                        other_host,
                        self._host,
                    )
                    return device_data, other_host

        # Not found anywhere
        return None, None

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

        # For uniqueid tracking, don't set via_device since device can roam between routers
        # For combined tracking, set via_device to local AP
        if self._tracking_method == "combined" and self.ap_device != "Unknown AP":
            device_info_dict["via_device"] = (DOMAIN, self.via_device)

        return DeviceInfo(**device_info_dict)

    @property
    def ap_device(self) -> str:
        """Return the access point device this device is connected to."""
        # For uniqueid tracking, search across all routers
        if self._tracking_method == "uniqueid":
            device_data, _ = self._get_device_data_from_any_coordinator()
            if device_data:
                return device_data.get("ap_device", "Unknown AP")
            return "Unknown AP"

        # For combined tracking, only check local coordinator
        device_stats = self.coordinator.data.get("device_statistics", {})
        device_data = device_stats.get(self.mac_address) or device_stats.get(self.mac_address.upper())
        if device_data:
            return device_data.get("ap_device", "Unknown AP")
        return "Unknown AP"

    @property
    def via_device(self) -> str:
        """Return the via device info for this device."""
        # For uniqueid tracking, use the host where device was found
        if self._tracking_method == "uniqueid":
            _, found_host = self._get_device_data_from_any_coordinator()
            if found_host and self.ap_device != "Unknown AP":
                return f"{found_host}_ap_{self.ap_device}"
            return found_host if found_host else self._host

        # For combined tracking, always use local host
        if self.ap_device != "Unknown AP":
            return f"{self._host}_ap_{self.ap_device}"
        return self._host

    def _get_device_name(self) -> str:
        """Get the device name from coordinator data or fallback to MAC."""
        # Get device data based on tracking method
        if self._tracking_method == "uniqueid":
            device_data, _ = self._get_device_data_from_any_coordinator()
        else:
            device_stats = self.coordinator.data.get("device_statistics", {})
            device_data = device_stats.get(self.mac_address) or device_stats.get(self.mac_address.upper())

        # If tracking method is "uniqueid", use simple naming without AP/SSID info
        if self._tracking_method == "uniqueid":
            if device_data:
                hostname = device_data.get("hostname")

                # Show hostname if available and meaningful
                if (
                    hostname
                    and hostname != self.mac_address
                    and hostname != self.mac_address.upper()
                    and hostname != "*"
                ):
                    # If hostname looks like a domain name, use only the first part
                    if "." in hostname:
                        return hostname.split(".")[0]
                    else:
                        return hostname
                else:
                    # Try to show IP address if hostname not available
                    ip_address = device_data.get("ip_address", "")
                    if ip_address and ip_address != "Unknown IP":
                        return ip_address.replace(".", "_")
                    else:
                        # Fallback to MAC address without colons
                        return self.mac_address.replace(":", "")

            # Fallback to MAC address if no device data found
            return self.mac_address.replace(":", "")

        # For "combined" tracking method, use the detailed naming with AP/SSID
        connected_router = self._host or "Unknown Router"

        if device_data:
            # Use SSID instead of physical interface name
            ssid = device_data.get("ap_ssid", "Unknown SSID")
            base_name = f"{connected_router}({ssid})" if ssid != "Unknown SSID" else connected_router

            hostname = device_data.get("hostname")

            # Show hostname if available and meaningful
            if hostname and hostname != self.mac_address and hostname != self.mac_address.upper() and hostname != "*":
                # If hostname looks like a domain name, use it directly
                if "." in hostname:
                    return f"{base_name} {hostname.split('.')[0]}"
                else:
                    return f"{base_name} {hostname}"
            else:
                # Try to show IP address if hostname not available
                ip_address = device_data.get("ip_address", "")
                if ip_address and ip_address != "Unknown IP":
                    return f"{base_name} {ip_address}"
                else:
                    # Fallback to MAC address
                    return f"{base_name} {self.mac_address.replace(':', '')}"

        # Fallback to MAC address if no device data found
        return f"{connected_router} {self.mac_address.replace(':', '')}"

    @property
    def name(self) -> str:
        """Return the name of the entity."""
        hostname = self.hostname

        if (
            hostname
            and hostname != self._attr_mac_address
            and hostname != self._attr_mac_address.upper()
            and hostname != "*"
        ):
            return hostname

        return self._attr_mac_address.replace(":", "")

    @property
    def is_connected(self) -> bool:
        """Return true if the device is connected to the network."""
        # For uniqueid tracking, search across all routers
        if self._tracking_method == "uniqueid":
            device_data, found_host = self._get_device_data_from_any_coordinator()

            if device_data:
                connected = device_data.get("connected", False)
                if found_host and found_host != self._host:
                    _LOGGER.debug(
                        "Device %s connection status: %s (on router %s, not %s)",
                        self.mac_address,
                        connected,
                        found_host,
                        self._host,
                    )
                else:
                    _LOGGER.debug("Device %s connection status: %s", self.mac_address, connected)
                return connected

            _LOGGER.debug(
                "Device %s not found in any device statistics, assuming disconnected",
                self.mac_address,
            )
            return False

        # For combined tracking, use simplified logic from main
        if device_data := self._device_data():
            connected = device_data.get("connected", False)
            _LOGGER.debug("Device %s connection status: %s", self._attr_mac_address, connected)
            return connected

        _LOGGER.debug(
            "Device %s not found in device statistics, assuming disconnected",
            self._attr_mac_address,
        )
        return False

    @property
    def extra_state_attributes(self) -> dict[str, str]:
        """Return the device state attributes."""
        # Get device data based on tracking method
        if self._tracking_method == "uniqueid":
            device_data, found_host = self._get_device_data_from_any_coordinator()
            # Use found_host for router attribute to show where device is actually connected
            current_router = found_host if found_host else self._host
        else:
            device_stats = self.coordinator.data.get("device_statistics", {})
            device_data = device_stats.get(self.mac_address) or device_stats.get(self.mac_address.upper())
            current_router = self._host

        attributes = {
            "host": self._host,  # Keep original host for reference
            "mac": self.mac_address,
        }

        if device_data:
            # Determine connection type
            connection_type = "wireless"
            if "ap_device" not in device_data:
                # If no ap_device, it's likely a wired device
                connection_type = "wired"
            
            attributes.update(
                {
                    "name": self._get_device_name(),
                    "hostname": device_data.get("hostname", self.mac_address),
                    "connection_type": connection_type,
                    "router": current_router,  # Show router where device is currently connected
                    "ip_address": device_data.get("ip_address", "Unknown IP"),
                }
            )
            
            # Add wireless-specific attributes
            if connection_type == "wireless":
                attributes["ap_device"] = device_data.get("ap_device", "Unknown AP")
                # Add SSID if available
                if "ap_ssid" in device_data:
                    attributes["ssid"] = device_data.get("ap_ssid", "Unknown SSID")
            else:
                # Add wired-specific attributes
                if "interface" in device_data:
                    attributes["interface"] = device_data.get("interface")
                # Add IPv4/IPv6 addresses for wired devices
                if "ipv4" in device_data and device_data.get("ipv4"):
                    attributes["ipv4"] = device_data.get("ipv4")
                if "ipv6" in device_data and device_data.get("ipv6"):
                    attributes["ipv6"] = device_data.get("ipv6")
                if "state" in device_data:
                    attributes["neighbor_state"] = device_data.get("state")
        else:
            attributes.update(
                {
                    "last_seen": "disconnected",
                }
            )

        return attributes

    def _device_data(self) -> dict[str, Any] | None:
        """Get device data from either device_statistics (WiFi) or wired_devices."""
        # Try WiFi devices first
        device_stats = self.coordinator.data.get("device_statistics", {})
        device_data = device_stats.get(self._attr_mac_address) or device_stats.get(self._attr_mac_address.upper())
        if device_data:
            return device_data
        
        # Try wired devices
        wired_devices = self.coordinator.data.get("wired_devices", {})
        wired_data = wired_devices.get(self._attr_mac_address) or wired_devices.get(self._attr_mac_address.upper())
        return wired_data

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
