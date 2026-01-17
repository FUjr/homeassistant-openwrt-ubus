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
from homeassistant.exceptions import HomeAssistantError

from ..const import DOMAIN
from ..shared_data_manager import SharedDataUpdateCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up device kick buttons for OpenWrt."""
    _LOGGER.info("Setting up OpenWrt device kick buttons")

    # Get shared data manager
    data_manager_key = f"data_manager_{entry.entry_id}"
    data_manager = hass.data[DOMAIN][data_manager_key]

    # Create coordinator for device kick buttons - we need device_statistics, ap_info, and hostapd_available
    from datetime import timedelta
    coordinator = SharedDataUpdateCoordinator(
        hass,
        data_manager,
        ["device_statistics", "ap_info", "hostapd_available"],  # Data types this coordinator needs
        f"{DOMAIN}_device_kick_{entry.data['host']}",
        timedelta(seconds=30),  # Update every 30 seconds
    )

    # Store coordinator in hass data for later reference
    hass.data.setdefault(DOMAIN, {})
    coordinators_key = "device_kick_coordinators"
    if coordinators_key not in hass.data[DOMAIN]:
        hass.data[DOMAIN][coordinators_key] = {}
    hass.data[DOMAIN][coordinators_key][entry.entry_id] = coordinator

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

        # Log current state for debugging
        _LOGGER.debug("Hostapd available: %s, AP info available: %s, Device stats count: %d",
                      hostapd_available, bool(ap_info_data), len(device_statistics))

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
            button_id = f"{ap_device}_{mac.replace(':', '_')}"
            current_devices.add(button_id)

            # Create button if it doesn't exist (regardless of current availability)
            if button_id not in created_buttons:
                # Create hostapd interface name
                hostapd_interface = f"hostapd.{ap_device}"

                # Create new kick button
                kick_button = DeviceKickButton(
                    coordinator=coordinator,
                    ap_device=ap_device,
                    hostapd_interface=hostapd_interface,
                    device_mac=mac,
                    device_name=device_info.get("hostname", f"Device {mac}"),
                    unique_id=button_id
                )

                new_buttons.append(kick_button)
                created_buttons.add(button_id)
                button_entities[button_id] = kick_button
                _LOGGER.debug("Created kick button for device %s (%s) on AP %s",
                              device_info.get("hostname", mac), mac, ap_device)

        # Add new buttons if any
        if new_buttons:
            async_add_entities(new_buttons)
            _LOGGER.info("Added %d new device kick buttons", len(new_buttons))

        # Update availability for all existing buttons
        for button_id, button_entity in button_entities.items():
            if hasattr(button_entity, 'async_write_ha_state'):
                # Trigger availability update by writing state
                button_entity.async_write_ha_state()

        # Clean up tracking for completely disconnected devices
        disconnected_devices = created_buttons - current_devices
        if disconnected_devices:
            _LOGGER.debug("Found %d disconnected devices, removing from tracking",
                          len(disconnected_devices))
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
        ap_device: str,
        hostapd_interface: str,
        device_mac: str,
        device_name: str,
        unique_id: str,
    ) -> None:
        """Initialize the kick button."""
        super().__init__(coordinator)

        self._ap_device = ap_device
        self._hostapd_interface = hostapd_interface
        self._device_mac = device_mac
        self._device_name = device_name
        self._host = coordinator.data_manager.entry.data["host"]
        self._previous_available_state = None  # Track availability changes

        if device_name == "Unknown" or device_name == "*":
            self._attr_name = f"Kick {self._device_mac}"
        else:
            self._attr_name = f"Kick {device_name}"
        self._attr_unique_id = f"{DOMAIN}_{unique_id}_kick"

        # Device info - associate with the AP device
        from homeassistant.helpers.device_registry import DeviceInfo
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, f"{self._host}_ap_{ap_device}")},
        )

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
                device_statistics = self.coordinator.data.get("device_statistics", {})
                device_info = device_statistics.get(self._device_mac, {})

                is_connected = device_info.get("connected", False)
                correct_ap = device_info.get("ap_device") == self._ap_device

                if not is_connected:
                    _LOGGER.debug("Button %s: Device %s not connected", self._attr_unique_id, self._device_mac)
                    current_state = False
                elif not correct_ap:
                    _LOGGER.debug("Button %s: Device %s on wrong AP (expected: %s, actual: %s)",
                                  self._attr_unique_id, self._device_mac, self._ap_device,
                                  device_info.get("ap_device"))
                    current_state = False
                else:
                    _LOGGER.debug("Button %s: Available - device %s connected on AP %s",
                                  self._attr_unique_id, self._device_mac, self._ap_device)
                    current_state = True

        # Log availability state changes
        if self._previous_available_state is not None and self._previous_available_state != current_state:
            if current_state:
                _LOGGER.info("Button %s: Device %s became available (reconnected or hostapd restored)",
                             self._attr_unique_id, self._device_mac)
            else:
                _LOGGER.info("Button %s: Device %s became unavailable (disconnected or hostapd down)",
                             self._attr_unique_id, self._device_mac)

        self._previous_available_state = current_state
        return current_state

    @property
    def icon(self) -> str:
        """Return the icon for the button."""
        return "mdi:wifi-cancel"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return extra state attributes."""
        return {
            "device_mac": self._device_mac,
            "device_name": self._device_name,
            "ap_device": self._ap_device,
            "hostapd_interface": self._hostapd_interface,
        }

    async def async_press(self) -> None:
        """Press the button to kick the device."""
        try:
            _LOGGER.info("Kicking device %s (%s) from AP %s",
                         self._device_name, self._device_mac, self._ap_device)

            # Get the ubus client
            ubus = await self.coordinator.data_manager.get_ubus_connection_async()

            # Kick the device
            await ubus.kick_device(
                hostapd_interface=self._hostapd_interface,
                mac_address=self._device_mac,
                ban_time=60000,  # 60 seconds
                reason=5  # Deauth reason
            )

            _LOGGER.info("Successfully kicked device %s from AP %s",
                         self._device_mac, self._ap_device)

            # Refresh data to update device status
            await self.coordinator.async_request_refresh()

        except Exception as exc:
            _LOGGER.error("Failed to kick device %s: %s", self._device_mac, exc)
            raise HomeAssistantError(f"Failed to kick device {self._device_name}: {exc}") from exc
