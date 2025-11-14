"""The ubus component for OpenWrt."""

from __future__ import annotations

import logging

import voluptuous as vol
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers import config_validation as cv, device_registry as dr
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.typing import ConfigType

from .const import (
    CONF_DHCP_SOFTWARE,
    CONF_WIRELESS_SOFTWARE,
    CONF_ENABLE_QMODEM_SENSORS,
    CONF_ENABLE_STA_SENSORS,
    CONF_ENABLE_SYSTEM_SENSORS,
    CONF_ENABLE_AP_SENSORS,
    CONF_ENABLE_SERVICE_CONTROLS,
    CONF_SELECTED_SERVICES,
    DEFAULT_DHCP_SOFTWARE,
    DEFAULT_WIRELESS_SOFTWARE,
    DEFAULT_ENABLE_QMODEM_SENSORS,
    DEFAULT_ENABLE_STA_SENSORS,
    DEFAULT_ENABLE_SYSTEM_SENSORS,
    DEFAULT_ENABLE_AP_SENSORS,
    DEFAULT_ENABLE_SERVICE_CONTROLS,
    DEFAULT_SELECTED_SERVICES,
    DHCP_SOFTWARES,
    DOMAIN,
    PLATFORMS,
    WIRELESS_SOFTWARES,
)
from .extended_ubus import ExtendedUbus
from .shared_data_manager import SharedUbusDataManager

_LOGGER = logging.getLogger(__name__)

CONFIG_SCHEMA = vol.Schema(
    {
        DOMAIN: vol.Schema(
            {
                vol.Required(CONF_HOST): cv.string,
                vol.Required(CONF_USERNAME): cv.string,
                vol.Required(CONF_PASSWORD): cv.string,
                vol.Optional(CONF_WIRELESS_SOFTWARE, default=DEFAULT_WIRELESS_SOFTWARE): vol.In(
                    WIRELESS_SOFTWARES
                ),
                vol.Optional(CONF_DHCP_SOFTWARE, default=DEFAULT_DHCP_SOFTWARE): vol.In(
                    DHCP_SOFTWARES
                ),
            }
        )
    },
    extra=vol.ALLOW_EXTRA,
)


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Set up the openwrt ubus component."""
    if DOMAIN not in config:
        return True

    hass.data.setdefault(DOMAIN, {})

    # Store the configuration for the device tracker
    hass.data[DOMAIN]["config"] = config[DOMAIN]

    # clear session_id for reload
    for key in list(hass.data[DOMAIN].keys()):
        if key.startswith("data_manager_"):
            shared_ubus_data_manager: SharedUbusDataManager = hass.data[DOMAIN][key]
            shared_ubus_data_manager.logout()

    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up openwrt ubus from a config entry."""
    hass.data.setdefault(DOMAIN, {})

    # Test connection before setting up platforms
    try:
        url = f"http://{entry.data[CONF_HOST]}/ubus"
        session = async_get_clientsession(hass)
        ubus = ExtendedUbus(url, entry.data[CONF_USERNAME], entry.data[CONF_PASSWORD], session=session)

        # Test connection
        session_id = await ubus.connect()
        if session_id is None:
            raise ConfigEntryNotReady(f"Failed to connect to OpenWrt device at {entry.data[CONF_HOST]}")

        # Check for modem_ctrl availability and store the result
        modem_ctrl_available = False
        try:
            modem_ctrl_list = await ubus.list_modem_ctrl()
            modem_ctrl_available = modem_ctrl_list is not None and bool(modem_ctrl_list)
            _LOGGER.debug("Modem_ctrl availability check: %s", modem_ctrl_available)
        except Exception as exc:
            _LOGGER.debug("Modem_ctrl not available: %s", exc)
            modem_ctrl_available = False

        # Store modem_ctrl availability in hass data
        hass.data[DOMAIN]["modem_ctrl_available"] = modem_ctrl_available

        # Close the test connection
        await ubus.close()

        # Create shared data manager
        data_manager = SharedUbusDataManager(hass, entry)
        hass.data[DOMAIN][f"data_manager_{entry.entry_id}"] = data_manager
                # Register UCI services once per integration domain
        if not hass.data[DOMAIN].get("uci_services_registered"):
            hass.data[DOMAIN]["uci_services_registered"] = True

            async def async_handle_uci_get(call):
                """Handle openwrt_ubus.uci_get service."""
                config = call.data["config"]
                section = call.data.get("section")
                option = call.data.get("option")

                # Pick the first available data manager (single-router setup)
                shared_manager = None
                for key, value in hass.data[DOMAIN].items():
                    if key.startswith("data_manager_"):
                        shared_manager = value
                        break

                if shared_manager is None:
                    _LOGGER.error("No SharedUbusDataManager available for uci_get")
                    return

                # Get an ExtendedUbus client and call UCI
                client = await shared_manager._get_ubus_client()  # type: ignore[attr-defined]
                result = await client.uci_get_option(config, section, option)
                _LOGGER.debug("UCI get %s/%s/%s -> %s", config, section, option, result)

            async def async_handle_uci_set_commit(call):
                """Handle openwrt_ubus.uci_set_commit service."""
                config = call.data["config"]
                section = call.data["section"]
                option = call.data["option"]
                value = str(call.data["value"])

                shared_manager = None
                for key, value_dm in hass.data[DOMAIN].items():
                    if key.startswith("data_manager_"):
                        shared_manager = value_dm
                        break

                if shared_manager is None:
                    _LOGGER.error("No SharedUbusDataManager available for uci_set_commit")
                    return

                client = await shared_manager._get_ubus_client()  # type: ignore[attr-defined]
                await client.uci_set_option(config, section, option, value)
                await client.uci_commit_config(config)
                _LOGGER.debug("UCI set+commit %s/%s %s=%r", config, section, option, value)

            hass.services.async_register(
                DOMAIN,
                "uci_get",
                async_handle_uci_get,
            )

            hass.services.async_register(
                DOMAIN,
                "uci_set_commit",
                async_handle_uci_set_commit,
            )


    except Exception as exc:
        raise ConfigEntryNotReady(f"Failed to connect to OpenWrt device at {entry.data[CONF_HOST]}: {exc}") from exc

    # Store the config entry data as a mutable dict
    hass.data[DOMAIN][f"entry_data_{entry.entry_id}"] = dict(entry.data)

    # Set up platforms
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # Clean up devices for disabled sensors after setting up platforms
    # This ensures devices exist before we try to clean them up
    await _cleanup_disabled_sensor_devices(hass, entry)

    return True


async def _cleanup_disabled_sensor_devices(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Clean up devices for disabled sensor types."""
    device_registry = dr.async_get(hass)
    host = entry.data[CONF_HOST]

    _LOGGER.debug("Starting device cleanup for host: %s", host)

    # Check if system sensors are disabled
    system_enabled = entry.options.get(
        CONF_ENABLE_SYSTEM_SENSORS,
        entry.data.get(CONF_ENABLE_SYSTEM_SENSORS, DEFAULT_ENABLE_SYSTEM_SENSORS)
    )

    # Check if QModem sensors are disabled
    qmodem_enabled = entry.options.get(
        CONF_ENABLE_QMODEM_SENSORS,
        entry.data.get(CONF_ENABLE_QMODEM_SENSORS, DEFAULT_ENABLE_QMODEM_SENSORS)
    )

    # Check if STA sensors are disabled
    sta_enabled = entry.options.get(
        CONF_ENABLE_STA_SENSORS,
        entry.data.get(CONF_ENABLE_STA_SENSORS, DEFAULT_ENABLE_STA_SENSORS)
    )

    # Check if AP sensors are disabled
    ap_enabled = entry.options.get(
        CONF_ENABLE_AP_SENSORS,
        entry.data.get(CONF_ENABLE_AP_SENSORS, DEFAULT_ENABLE_AP_SENSORS)
    )

    _LOGGER.debug("Sensor states - System: %s, QModem: %s, STA: %s, AP: %s",
                  system_enabled, qmodem_enabled, sta_enabled, ap_enabled)

    # List all current devices for debugging
    all_devices = [device for device in device_registry.devices.values()
                   if any(identifier[0] == DOMAIN for identifier in device.identifiers)]
    _LOGGER.debug("Current devices in registry: %s",
                  [list(device.identifiers) for device in all_devices])

    # If system sensors are disabled, remove the main router device
    # (this will also remove any via_device dependencies like QModem and STA devices)
    if not system_enabled:
        main_device = device_registry.async_get_device(identifiers={(DOMAIN, host)})
        if main_device:
            _LOGGER.info("Removing main router device %s (system sensors disabled)", host)
            device_registry.async_remove_device(main_device.id)
        else:
            _LOGGER.debug("Main router device not found for removal: %s", host)
    else:
        # If system sensors are enabled but QModem sensors are disabled,
        # only remove the QModem device
        if not qmodem_enabled:
            qmodem_identifier = (DOMAIN, f"{host}_qmodem")
            qmodem_device = device_registry.async_get_device(identifiers={qmodem_identifier})
            if qmodem_device:
                _LOGGER.info("Removing QModem device %s (QModem sensors disabled)", f"{host}_qmodem")
                device_registry.async_remove_device(qmodem_device.id)
            else:
                _LOGGER.debug("QModem device not found for removal: %s", f"{host}_qmodem")
                # Check if device exists with different identifier pattern
                for device in device_registry.devices.values():
                    for identifier in device.identifiers:
                        if identifier[0] == DOMAIN and "_qmodem" in str(identifier[1]):
                            _LOGGER.debug("Found QModem-like device: %s", identifier)

        # If STA sensors are disabled, remove all STA devices (devices with via_device pointing to main router)
        if not sta_enabled:
            removed_count = 0
            # Find all devices that have via_device pointing to the main router
            for device in list(device_registry.devices.values()):  # Use list() to avoid modification during iteration
                if device.via_device_id:
                    via_device = device_registry.devices.get(device.via_device_id)
                    if via_device and (DOMAIN, host) in via_device.identifiers:
                        # This device is connected via the main router, check if it's a STA device
                        for identifier in device.identifiers:
                            if (identifier[0] == DOMAIN and identifier[1] != host and
                                    identifier[1] != f"{host}_qmodem" and
                                    not identifier[1].startswith(f"{host}_ap_") and
                                    not identifier[1].endswith("_br-lan") and
                                    not identifier[1].endswith("_lan") and
                                    not identifier[1].endswith("_wan") and
                                    not identifier[1].endswith("_eth0")):
                                # This is a STA device (not the main router, QModem, AP device, or network interface)
                                _LOGGER.info("Removing STA device %s (STA sensors disabled)", identifier[1])
                                device_registry.async_remove_device(device.id)
                                removed_count += 1
                                break
            _LOGGER.debug("Removed %d STA devices", removed_count)

        # If AP sensors are disabled, remove all AP devices
        if not ap_enabled:
            removed_count = 0
            # Find all AP devices (devices with identifiers starting with host_ap_)
            for device in list(device_registry.devices.values()):  # Use list() to avoid modification during iteration
                for identifier in device.identifiers:
                    if (identifier[0] == DOMAIN and
                            identifier[1].startswith(f"{host}_ap_")):
                        # This is an AP device
                        _LOGGER.info("Removing AP device %s (AP sensors disabled)", identifier[1])
                        device_registry.async_remove_device(device.id)
                        removed_count += 1
                        break
            _LOGGER.debug("Removed %d AP devices", removed_count)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)

    if unload_ok:
        # Clean up shared data manager
        data_manager_key = f"data_manager_{entry.entry_id}"
        if DOMAIN in hass.data and data_manager_key in hass.data[DOMAIN]:
            data_manager = hass.data[DOMAIN][data_manager_key]
            try:
                await data_manager.close()
            except Exception as exc:
                _LOGGER.debug("Error closing data manager: %s", exc)
            hass.data[DOMAIN].pop(data_manager_key, None)

        # Clean up coordinators
        if DOMAIN in hass.data and "coordinators" in hass.data[DOMAIN]:
            coordinators = hass.data[DOMAIN]["coordinators"]
            for coordinator in coordinators:
                if hasattr(coordinator, 'async_shutdown'):
                    try:
                        await coordinator.async_shutdown()
                    except Exception as exc:
                        _LOGGER.debug("Error shutting down coordinator: %s", exc)
            # Clear the coordinators list
            hass.data[DOMAIN]["coordinators"] = []

        # Clean up entry-specific data
        hass.data[DOMAIN].pop(f"entry_data_{entry.entry_id}", None)

        # Clean up device kick coordinators
        if "device_kick_coordinators" in hass.data[DOMAIN]:
            hass.data[DOMAIN]["device_kick_coordinators"].pop(entry.entry_id, None)

        # Clean up modem_ctrl availability data if no more entries
        if len([e for e in hass.config_entries.async_entries(DOMAIN) if e.entry_id != entry.entry_id]) == 0:
            hass.data[DOMAIN].pop("modem_ctrl_available", None)

    return unload_ok


async def async_remove_config_entry_device(
        _: HomeAssistant, entry: ConfigEntry, device_entry: dr.DeviceEntry
) -> bool:
    """Handle device removal."""
    host = entry.data[CONF_HOST]
    for identifier in device_entry.identifiers:
        unique_id = str(identifier[1])
        if str(identifier[0]) == DOMAIN and not (
                unique_id == host or "_ap_" in unique_id or unique_id.endswith("_qmodem")
        ):
            return True
    return False
