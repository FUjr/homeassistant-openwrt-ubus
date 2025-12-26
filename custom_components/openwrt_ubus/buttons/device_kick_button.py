"""Device kick button for OpenWrt Ubus integration."""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.button import ButtonEntity, ButtonDeviceClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.helpers import entity_registry as er
from homeassistant.exceptions import HomeAssistantError

from ..const import DOMAIN, CONF_TRACKING_METHOD, DEFAULT_TRACKING_METHOD
from ..shared_data_manager import SharedDataUpdateCoordinator

_LOGGER = logging.getLogger(__name__)


async def _migrate_kick_button_unique_ids(
    hass: HomeAssistant,
    entry: ConfigEntry,
    tracking_method: str,
) -> None:
    """Migrate kick button unique_ids to remove host prefix for uniqueid tracking.

    For uniqueid tracking method, buttons should have unique_ids without host prefix
    to allow devices to roam between APs without creating duplicate buttons.
    """
    if tracking_method != "uniqueid":
        return  # Migration only needed for uniqueid tracking

    entity_registry = er.async_get(hass)
    host = entry.data["host"]

    _LOGGER.info("Migrating kick button unique_ids for %s (tracking_method=uniqueid)", host)

    # Get all button entities for this config entry
    existing_entities = er.async_entries_for_config_entry(entity_registry, entry.entry_id)
    migrated_count = 0

    for entity_entry in existing_entities:
        if entity_entry.domain != "button" or entity_entry.platform != DOMAIN:
            continue

        old_unique_id = entity_entry.unique_id

        # Check if this is a kick button with host prefix
        # Format: "openwrt_ubus_{host}_{mac}_kick"
        if not old_unique_id or not old_unique_id.endswith("_kick"):
            continue

        # Extract MAC from old unique_id
        # Remove "openwrt_ubus_" prefix and "_kick" suffix
        if not old_unique_id.startswith(f"{DOMAIN}_"):
            continue

        without_prefix = old_unique_id[len(f"{DOMAIN}_") :]
        if not without_prefix.endswith("_kick"):
            continue

        without_suffix = without_prefix[:-5]  # Remove "_kick"

        # Check if it contains host prefix
        # Format should be: {host}_{mac_with_underscores}
        # Try to extract MAC (last part after removing potential host)
        parts = without_suffix.split("_")
        if len(parts) < 6:  # MAC has at least 6 parts when using underscores
            continue

        # Assume last 6 parts are MAC address
        mac_parts = parts[-6:]
        mac_address = "_".join(mac_parts)

        # New format: "openwrt_ubus_{mac}_kick"
        new_unique_id = f"{DOMAIN}_{mac_address}_kick"

        if old_unique_id == new_unique_id:
            continue

        # Check if new unique_id already exists (could be from another AP entry)
        existing_entity_id = entity_registry.async_get_entity_id("button", DOMAIN, new_unique_id)

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
                "Migrated button entity %s: %s → %s",
                entity_entry.entity_id,
                old_unique_id,
                new_unique_id,
            )
        except Exception as exc:
            _LOGGER.error(
                "Failed to migrate button entity %s from %s to %s: %s",
                entity_entry.entity_id,
                old_unique_id,
                new_unique_id,
                exc,
            )

    _LOGGER.info("Kick button migration completed: %d entities migrated", migrated_count)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up device kick buttons for OpenWrt."""
    _LOGGER.info("Setting up OpenWrt device kick buttons")
    tracking_method = entry.data.get(CONF_TRACKING_METHOD, DEFAULT_TRACKING_METHOD)

    # Migrate button unique_ids if needed
    await _migrate_kick_button_unique_ids(hass, entry, tracking_method)

    # Get entity registry for checking existing entities
    from homeassistant.helpers import entity_registry as er

    entity_registry = er.async_get(hass)

    # Get shared data manager
    data_manager_key = f"data_manager_{entry.entry_id}"
    data_manager = hass.data[DOMAIN][data_manager_key]

    # Create coordinator for device kick buttons - we need device_statistics, ap_info, and hostapd_available
    from datetime import timedelta

    coordinator = SharedDataUpdateCoordinator(
        hass,
        data_manager,
        [
            "device_statistics",
            "ap_info",
            "hostapd_available",
        ],  # Data types this coordinator needs
        f"{DOMAIN}_device_kick_{entry.data['host']}",
        timedelta(seconds=30),  # Update every 30 seconds
    )

    # Store coordinator in hass data for later reference
    hass.data.setdefault(DOMAIN, {})
    coordinators_key = f"device_kick_coordinators"
    if coordinators_key not in hass.data[DOMAIN]:
        hass.data[DOMAIN][coordinators_key] = {}
    hass.data[DOMAIN][coordinators_key][entry.entry_id] = coordinator

    # Also store in tracker_coordinators for cross-router lookups (uniqueid tracking method)
    if tracking_method == "uniqueid":
        tracker_coordinators_key = "tracker_coordinators"
        if tracker_coordinators_key not in hass.data[DOMAIN]:
            hass.data[DOMAIN][tracker_coordinators_key] = {}
        # Use same entry_id key for consistency
        if entry.entry_id not in hass.data[DOMAIN][tracker_coordinators_key]:
            hass.data[DOMAIN][tracker_coordinators_key][entry.entry_id] = coordinator
        _LOGGER.debug(
            "Stored button coordinator for %s in tracker_coordinators (tracking_method=uniqueid)",
            entry.data["host"],
        )

    # Track created buttons to avoid duplicates and allow re-enabling
    created_buttons = set()
    button_entities = {}  # Store references to button entities for availability updates

    @callback
    def _async_add_kick_buttons():
        """Add kick buttons for connected devices and update availability."""
        _LOGGER.debug("Checking for devices to create kick buttons and update availability")

        # Get current data
        hostapd_available = coordinator.data.get("hostapd_available", False)
        ap_info_data = coordinator.data.get("ap_info", {})
        device_statistics = coordinator.data.get("device_statistics", {})

        # Get host for unique ID generation
        host = entry.data["host"]

        # Log current state for debugging
        _LOGGER.debug(
            "Hostapd available: %s, AP info available: %s, Device stats count: %d",
            hostapd_available,
            bool(ap_info_data),
            len(device_statistics),
        )

        new_buttons = []
        current_devices = set()

        # Process each connected device (even if hostapd is not available, we still track them)
        for mac, device_info in device_statistics.items():
            if not isinstance(device_info, dict):
                continue

            ap_device = device_info.get("ap_device")
            if not ap_device:
                continue

            # Create unique identifier for this device button
            # For uniqueid tracking: use only MAC to allow device roaming between APs
            # For combined tracking: use host+MAC to keep separate buttons per router
            if tracking_method == "uniqueid":
                button_id = mac.replace(":", "_")
            else:
                button_id = f"{host}_{mac.replace(':', '_')}"
            current_devices.add(button_id)

            # Create button if it doesn't exist (regardless of current availability)
            if button_id not in created_buttons:
                # Create hostapd interface name
                # Don't add "hostapd." prefix if already present (when using hostapd wireless_software)
                if ap_device.startswith("hostapd."):
                    hostapd_interface = ap_device
                else:
                    hostapd_interface = f"hostapd.{ap_device}"

                # Create new kick button
            # Get SSID for user-friendly naming
            ap_ssid = device_info.get("ap_ssid", ap_device)

            # Create or update button entity for tracking
            if button_id not in button_entities:
                # Create button object for tracking (HA will handle duplicates via unique_id)
                # For uniqueid: use only MAC for single entity across all routers
                # For combined: use host+MAC for separate entities per router
                # NOTE: button_id is for internal tracking per-router, entity_unique_id is global
                if tracking_method == "uniqueid":
                    entity_unique_id = mac.replace(":", "_")
                else:
                    entity_unique_id = f"{host}_{mac.replace(':', '_')}"

                kick_button = DeviceKickButton(
                    coordinator=coordinator,
                    device_mac=mac,
                    device_name=device_info.get("hostname", f"Device {mac}"),
                    unique_id=entity_unique_id,
                    host=host,
                    tracking_method=tracking_method,
                )

                # Add to button_entities for tracking and updates
                button_entities[button_id] = kick_button

                # Always add to new_buttons - HA will handle existing entities via unique_id
                new_buttons.append(kick_button)
                _LOGGER.debug(
                    "Created kick button for device %s (%s) on AP %s (%s)",
                    device_info.get("hostname", mac),
                    mac,
                    ap_ssid,
                    ap_device,
                )

            # Mark button as seen in this update cycle
            created_buttons.add(button_id)

        # Add new buttons if any
        if new_buttons:
            async_add_entities(new_buttons)
            _LOGGER.info("Added %d new device kick buttons", len(new_buttons))

        # Update availability for all existing buttons
        for button_id, button_entity in button_entities.items():
            # Only update state if the entity has been fully initialized (hass is set)
            if hasattr(button_entity, "hass") and button_entity.hass is not None:
                try:
                    # Trigger availability update by writing state
                    button_entity.async_write_ha_state()
                except RuntimeError as exc:
                    _LOGGER.debug("Could not update state for button %s: %s", button_id, exc)

        # Clean up tracking for completely disconnected devices
        disconnected_devices = created_buttons - current_devices
        if disconnected_devices:
            _LOGGER.debug(
                "Found %d disconnected devices, removing from tracking",
                len(disconnected_devices),
            )
            for button_id in disconnected_devices:
                created_buttons.discard(button_id)
                button_entities.pop(button_id, None)

    # Initial setup
    await coordinator.async_config_entry_first_refresh()
    _async_add_kick_buttons()

    # Listen for coordinator updates to refresh buttons
    coordinator.async_add_listener(_async_add_kick_buttons)

    # Return None to indicate we don't need tracking in button.py
    return None


class DeviceKickButton(CoordinatorEntity[SharedDataUpdateCoordinator], ButtonEntity):
    """Button to kick a device from AP."""

    _attr_device_class = ButtonDeviceClass.RESTART
    _attr_entity_category = EntityCategory.CONFIG
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: SharedDataUpdateCoordinator,
        device_mac: str,
        device_name: str,
        unique_id: str,
        host: str,
        tracking_method: str = DEFAULT_TRACKING_METHOD,
    ) -> None:
        """Initialize the kick button."""
        super().__init__(coordinator)

        self._device_mac = device_mac
        self._initial_device_name = device_name
        self._host = host
        self._tracking_method = tracking_method
        self._previous_available_state = None  # Track availability changes
        self._previous_ap_info = None  # Track AP changes: (host, ap_device, ssid)

        self._attr_unique_id = f"{DOMAIN}_{unique_id}_kick"

    def _get_device_info(self) -> dict:
        """Get current device info from coordinator data.

        For uniqueid tracking method, searches across all routers to find where device is currently connected.
        """
        # First try local coordinator
        device_statistics = self.coordinator.data.get("device_statistics", {})
        device_data = device_statistics.get(self._device_mac, {})

        if device_data and device_data.get("connected"):
            return device_data

        # If using uniqueid tracking and device not found locally, search other routers
        if self._tracking_method == "uniqueid" and hasattr(self, "hass"):
            # Get all tracker coordinators
            tracker_coordinators_key = "tracker_coordinators"
            all_coordinators = self.hass.data.get(DOMAIN, {}).get(tracker_coordinators_key, {})

            for entry_id, other_coordinator in all_coordinators.items():
                # Skip current coordinator
                if other_coordinator == self.coordinator:
                    continue

                # Check if coordinator has data
                if not other_coordinator.data:
                    continue

                # Look for device in this coordinator's data
                other_stats = other_coordinator.data.get("device_statistics", {})
                device_data = other_stats.get(self._device_mac, {})

                if device_data and device_data.get("connected"):
                    # Found on another router
                    return device_data

        # Return empty dict if not found anywhere
        return {}

    @property
    def suggested_object_id(self) -> str:
        """Return suggested entity_id for the button.

        Automatically adapts based on has_entity_name setting:
        - If has_entity_name=True: Returns only suffix (HA adds device name automatically)
        - If has_entity_name=False: Returns full name including device name
        """
        if self._tracking_method == "uniqueid":
            # Get AP hostname (without domain)
            ap_host = self._host.split(".")[0].replace("-", "_").replace(" ", "_").lower()

            # Check if has_entity_name is enabled
            if getattr(self, "_attr_has_entity_name", False):
                # Home Assistant will add device name automatically, so we only provide the suffix
                return f"kick"
            else:
                # We need to include the device name ourselves
                device_info = self._get_device_info()
                device_name = device_info.get("hostname", self._initial_device_name)

                # Clean device name for entity_id (remove special chars, use lowercase)
                if not device_name or device_name == "Unknown" or device_name == "*" or device_name == self._device_mac:
                    clean_name = self._device_mac.replace(":", "_").lower()
                else:
                    # Remove domain suffix if present and clean
                    clean_name = device_name.split(".")[0].replace("-", "_").replace(" ", "_").lower()

                return f"{clean_name}_kick"
        else:
            # For combined: use default behavior
            return None

    @property
    def name(self) -> str:
        """Return the name of the button using SSID."""
        device_info = self._get_device_info()
        device_name = device_info.get("hostname", self._initial_device_name)
        ap_ssid = device_info.get("ap_ssid", "Unknown Network")

        if not device_name or device_name == "Unknown" or device_name == "*" or device_name == self._device_mac:
            return f"Kick {self._device_mac} from {ap_ssid}"
        else:
            return f"Kick {device_name} from {ap_ssid}"

    @property
    def device_info(self):
        """Return device info - associate with the mobile device, not the AP."""
        from homeassistant.helpers.device_registry import DeviceInfo

        device_info = self._get_device_info()
        ap_device = device_info.get("ap_device", "unknown")

        # Associate button with the mobile device (using MAC as identifier)
        device_info_dict = {
            "identifiers": {(DOMAIN, self._device_mac)},
            "connections": {("mac", self._device_mac)},
        }

        # For uniqueid tracking, don't set via_device since device can roam between APs
        # For combined tracking, set via_device to local AP
        if self._tracking_method == "combined" and ap_device != "unknown":
            device_info_dict["via_device"] = (DOMAIN, f"{self._host}_ap_{ap_device}")

        return DeviceInfo(**device_info_dict)

    @property
    def available(self) -> bool:
        """Return if button is available."""
        if not super().available:
            _LOGGER.debug("Button %s: Coordinator not available", self._attr_unique_id)
            current_state = False
        else:
            # Check if hostapd is available
            hostapd_available = self.coordinator.data.get("hostapd_available", False)
            if not hostapd_available:
                _LOGGER.debug("Button %s: Hostapd not available", self._attr_unique_id)
                current_state = False
            else:
                # Check if device is still connected
                device_info = self._get_device_info()
                is_connected = device_info.get("connected", False)
                current_ap_device = device_info.get("ap_device")
                current_ssid = device_info.get("ap_ssid", "Unknown")

                if not is_connected:
                    _LOGGER.debug(
                        "Button %s: Device %s not connected",
                        self._attr_unique_id,
                        self._device_mac,
                    )
                    current_state = False
                elif not current_ap_device:
                    _LOGGER.debug(
                        "Button %s: Device %s has no AP info",
                        self._attr_unique_id,
                        self._device_mac,
                    )
                    current_state = False
                else:
                    # Track AP changes using router host + interface + SSID
                    current_ap_info = (self._host, current_ap_device, current_ssid)
                    _LOGGER.debug(
                        "Current_ap_info: %s %s %s",
                        self._host,
                        current_ap_device,
                        current_ssid,
                    )

                    if self._previous_ap_info and self._previous_ap_info != current_ap_info:
                        prev_host, prev_device, prev_ssid = self._previous_ap_info
                        _LOGGER.info(
                            "Button %s: Device %s moved from %s/%s (%s) to %s/%s (%s)",
                            self._attr_unique_id,
                            self._device_mac,
                            prev_host,
                            prev_device,
                            prev_ssid,
                            self._host,
                            current_ap_device,
                            current_ssid,
                        )

                    self._previous_ap_info = current_ap_info
                    _LOGGER.debug(
                        "Button %s: Available - device %s connected on %s/%s (%s)",
                        self._attr_unique_id,
                        self._device_mac,
                        self._host,
                        current_ap_device,
                        current_ssid,
                    )
                    current_state = True

        # Log availability state changes
        if self._previous_available_state is not None and self._previous_available_state != current_state:
            if current_state:
                _LOGGER.info(
                    "Button %s: Device %s became available (reconnected or hostapd restored)",
                    self._attr_unique_id,
                    self._device_mac,
                )
            else:
                _LOGGER.info(
                    "Button %s: Device %s became unavailable (disconnected or hostapd down)",
                    self._attr_unique_id,
                    self._device_mac,
                )

        self._previous_available_state = current_state
        return current_state

    @property
    def icon(self) -> str:
        """Return the icon for the button."""
        return "mdi:wifi-cancel"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return extra state attributes."""
        device_info = self._get_device_info()
        ap_device = device_info.get("ap_device", "Unknown AP")
        ap_ssid = device_info.get("ap_ssid", "Unknown Network")
        hostname = device_info.get("hostname", self._initial_device_name)

        return {
            "device_mac": self._device_mac,
            "device_name": hostname,
            "router": self._host,
            "ap_device": ap_device,
            "ap_ssid": ap_ssid,
            "hostapd_interface": f"hostapd.{ap_device}",
        }

    async def async_press(self) -> None:
        """Press the button to kick the device."""
        try:
            # Get current device info
            device_info = self._get_device_info()
            ap_device = device_info.get("ap_device")
            ap_ssid = device_info.get("ap_ssid", ap_device)
            hostname = device_info.get("hostname", self._initial_device_name)

            if not ap_device:
                raise HomeAssistantError(f"Cannot kick device {hostname}: no AP information available")

            hostapd_interface = f"hostapd.{ap_device}"

            _LOGGER.info(
                "Kicking device %s (%s) from %s/%s (%s)",
                hostname,
                self._device_mac,
                self._host,
                ap_device,
                ap_ssid,
            )

            # Get the ubus client
            ubus = await self.coordinator.data_manager.get_ubus_connection_async()

            # Kick the device
            await ubus.kick_device(
                hostapd_interface=hostapd_interface,
                mac_address=self._device_mac,
                ban_time=60000,  # 60 seconds
                reason=5,  # Deauth reason
            )

            _LOGGER.info(
                "Successfully kicked device %s from %s (%s)",
                self._device_mac,
                self._host,
                ap_ssid,
            )

            # Refresh data to update device status
            await self.coordinator.async_request_refresh()

        except Exception as exc:
            device_info = self._get_device_info()
            hostname = device_info.get("hostname", self._initial_device_name)
            _LOGGER.error("Failed to kick device %s: %s", self._device_mac, exc)
            raise HomeAssistantError(f"Failed to kick device {hostname}: {exc}") from exc
