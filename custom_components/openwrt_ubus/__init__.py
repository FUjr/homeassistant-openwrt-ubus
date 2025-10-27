"""The ubus component for OpenWrt."""

from __future__ import annotations

import asyncio
import logging

import voluptuous as vol

from homeassistant.components.device_tracker import DOMAIN as DEVICE_TRACKER_DOMAIN
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
    CONF_USE_HTTPS,
    CONF_VERIFY_SSL,
    CONF_CERT_PATH,
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
from .ubus_client import create_enhanced_extended_ubus_client
from .security_utils import CredentialManager, safe_log_data

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

    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up openwrt ubus from a config entry."""
    hass.data.setdefault(DOMAIN, {})

    # Test connection before setting up platforms
    try:
        # Build URL with proper protocol
        protocol = "https" if entry.data.get(CONF_USE_HTTPS, False) else "http"
        url = f"{protocol}://{entry.data[CONF_HOST]}/ubus"

        # Configure SSL verification
        verify_ssl = entry.data.get(CONF_VERIFY_SSL, False)  # 默认不验证SSL
        cert_path = entry.data.get(CONF_CERT_PATH)

        # If using HTTPS with unverified SSL, warn user
        if protocol == "https" and not verify_ssl:
            _LOGGER.warning("HTTPS enabled with SSL verification disabled - this is insecure but necessary for unsigned certificates")

        # Create credential manager for secure handling
        credentials = CredentialManager(
            entry.data[CONF_HOST],
            entry.data[CONF_USERNAME],
            entry.data[CONF_PASSWORD]
        )

        safe_log_data(credentials.get_connection_info(), "debug", "Testing connection")

        session = async_get_clientsession(hass)
        ubus = create_enhanced_extended_ubus_client(
            url,
            entry.data[CONF_USERNAME],
            entry.data[CONF_PASSWORD],
            session=session,
            verify_ssl=verify_ssl,
            cert_file=cert_path
        )

        # Test connection
        _LOGGER.debug("Testing connection to %s://%s with user %s", protocol, entry.data[CONF_HOST], entry.data[CONF_USERNAME])
        session_id = await ubus.connect()
        if session_id is None:
            _LOGGER.error("Setup failed: session_id is None for %s://%s", protocol, entry.data[CONF_HOST])
            raise ConfigEntryNotReady(f"Failed to connect to OpenWrt device at {entry.data[CONF_HOST]} - session_id is None")

        _LOGGER.info("Successfully connected to OpenWrt device at %s://%s during setup", protocol, entry.data[CONF_HOST])

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

    except ConnectionRefusedError as exc:
        _LOGGER.error("Setup failed: Connection refused for OpenWrt device at %s", entry.data[CONF_HOST])
        raise ConfigEntryNotReady(f"Connection refused - check if OpenWrt device is running and accessible at {entry.data[CONF_HOST]}") from exc
    except asyncio.TimeoutError as exc:
        _LOGGER.error("Setup failed: Connection timeout for OpenWrt device at %s", entry.data[CONF_HOST])
        raise ConfigEntryNotReady(f"Connection timeout - check network connectivity to {entry.data[CONF_HOST]}") from exc
    except PermissionError as exc:
        _LOGGER.error("Setup failed: Authentication failed for user %s on %s", entry.data[CONF_USERNAME], entry.data[CONF_HOST])
        raise ConfigEntryNotReady(f"Authentication failed - check username and password for {entry.data[CONF_HOST]}") from exc
    except Exception as exc:
        _LOGGER.exception("Setup failed: Unexpected error connecting to OpenWrt device at %s: %s", entry.data[CONF_HOST], str(exc))
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
