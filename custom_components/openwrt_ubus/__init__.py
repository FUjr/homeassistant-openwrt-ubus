"""The ubus component for OpenWrt."""

from __future__ import annotations

import logging

import voluptuous as vol
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_USERNAME,
    CONF_IP_ADDRESS,
    CONF_VERIFY_SSL,
)
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers import config_validation as cv, device_registry as dr
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.typing import ConfigType

from .Ubus.const import API_DEF_TIMEOUT
from .const import (
    CONF_DHCP_SOFTWARE,
    CONF_WIRELESS_SOFTWARE,
    CONF_ENABLE_QMODEM_SENSORS,
    CONF_ENABLE_STA_SENSORS,
    CONF_ENABLE_SYSTEM_SENSORS,
    CONF_ENABLE_AP_SENSORS,
    CONF_ENABLE_ETH_SENSORS,
    CONF_ENABLE_MWAN3_SENSORS,
    CONF_ENABLE_SERVICE_CONTROLS,
    CONF_SELECTED_SERVICES,
    DEFAULT_DHCP_SOFTWARE,
    DEFAULT_WIRELESS_SOFTWARE,
    DEFAULT_ENABLE_QMODEM_SENSORS,
    DEFAULT_ENABLE_STA_SENSORS,
    DEFAULT_ENABLE_SYSTEM_SENSORS,
    DEFAULT_ENABLE_AP_SENSORS,
    DEFAULT_ENABLE_ETH_SENSORS,
    DEFAULT_ENABLE_MWAN3_SENSORS,
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
                vol.Optional(CONF_IP_ADDRESS): cv.string,
                vol.Optional(CONF_VERIFY_SSL, default=False): cv.boolean,
                vol.Required(CONF_USERNAME): cv.string,
                vol.Required(CONF_PASSWORD): cv.string,
                vol.Optional(CONF_WIRELESS_SOFTWARE, default=DEFAULT_WIRELESS_SOFTWARE): vol.In(WIRELESS_SOFTWARES),
                vol.Optional(CONF_DHCP_SOFTWARE, default=DEFAULT_DHCP_SOFTWARE): vol.In(DHCP_SOFTWARES),
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
    hostname = entry.data[CONF_HOST]
    try:
        ip = entry.data.get(CONF_IP_ADDRESS, None)
        url = f"http://{ip if ip else hostname}/ubus"
        session = async_get_clientsession(hass)
        ubus = ExtendedUbus(
            url,
            hostname,
            entry.data[CONF_USERNAME],
            entry.data[CONF_PASSWORD],
            session=session,
            timeout=API_DEF_TIMEOUT,
            verify=entry.data.get(CONF_VERIFY_SSL, False),
        )

        # Test connection
        session_id = await ubus.connect()
        if session_id is None:
            raise ConfigEntryNotReady(f"Failed to connect to OpenWrt device at {hostname}")

        # Check for modem_ctrl availability and store the result
        try:
            modem_ctrl_list = await ubus.list_modem_ctrl()
            modem_ctrl_available = modem_ctrl_list is not None and bool(modem_ctrl_list)
            _LOGGER.debug("Modem_ctrl availability check: %s", modem_ctrl_available)
        except Exception as exc:
            _LOGGER.debug("Modem_ctrl not available: %s", exc)
            modem_ctrl_available = False

        # Store modem_ctrl availability in hass data
        hass.data[DOMAIN]["modem_ctrl_available"] = modem_ctrl_available

        # Check for mwan3 availability and store the result
        mwan3_available = False
        try:
            mwan3_list = await ubus.list_mwan3()
            mwan3_available = mwan3_list is not None and bool(mwan3_list)
            _LOGGER.debug("MWAN3 availability check: %s", mwan3_available)
        except Exception as exc:
            _LOGGER.debug("MWAN3 not available: %s", exc)
            mwan3_available = False

        # Store mwan3 availability in hass data
        hass.data[DOMAIN]["mwan3_available"] = mwan3_available

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
                target_entity_id = call.data.get("target_entity_id")

                # Find a SharedUbusDataManager (single-router assumption)
                shared_manager = None
                for key, value in hass.data[DOMAIN].items():
                    if key.startswith("data_manager_"):
                        shared_manager = value
                        break

                if shared_manager is None:
                    _LOGGER.error("No SharedUbusDataManager available for uci_get")
                    return

                # Use the data manager to obtain a connected ExtendedUbus client
                client = await shared_manager._get_ubus_client()  # type: ignore[attr-defined]

                # Call UCI get
                result = await client.uci_get_option(config, section, option)
                _LOGGER.debug("UCI get %s/%s/%s -> %s", config, section, option, result)

                # Try to extract the value from ubus result structure:
                # {"result": [0, {"values": {"enabled": "1", ...}}]}
                value = None
                try:
                    res_list = result.get("result", [])
                    if len(res_list) >= 2:
                        values_dict = res_list[1].get("values", {})
                        if option is not None:
                            value = values_dict.get(option)
                        elif values_dict:
                            # if no option specified, grab first value
                            value = next(iter(values_dict.values()))
                except Exception as exc:
                    _LOGGER.warning("Failed to parse UCI get result: %s", exc)

                if target_entity_id and value is not None:
                    _LOGGER.debug(
                        "Setting state of %s to %r from UCI %s/%s/%s",
                        target_entity_id,
                        value,
                        config,
                        section,
                        option,
                    )
                    # This creates or updates the entity state in HA
                    hass.states.async_set(target_entity_id, value)
                elif target_entity_id:
                    _LOGGER.warning(
                        "UCI get for %s/%s/%s returned no value; not updating %s",
                        config,
                        section,
                        option,
                        target_entity_id,
                    )

            async def async_handle_uci_network_interface(call):
                """Handle openwrt_ubus.uci_call service."""
                # config = call.data["config"]
                section = call.data["section"]
                option = call.data["option"]

                # Find a SharedUbusDataManager (single-router assumption)
                shared_manager = None
                for key, value in hass.data[DOMAIN].items():
                    if key.startswith("data_manager_"):
                        shared_manager = value
                        break

                if shared_manager is None:
                    _LOGGER.error("No SharedUbusDataManager available for uci_get")
                    return

                # Use the data manager to obtain a connected ExtendedUbus client
                client = await shared_manager._get_ubus_client()  # type: ignore[attr-defined]

                # Call UCI uci_network_interface
                result = await client.uci_network_interface(section, option)
                _LOGGER.debug("UBUS call %s %s", section, option)

            async def async_handle_uci_set_commit(call):
                """Handle openwrt_ubus.uci_set_commit service."""
                config = call.data["config"]
                section = call.data["section"]
                option = call.data["option"]
                value = call.data["value"]
                services_to_restart = call.data.get("service")

                shared_manager = None
                for key, value_dm in hass.data[DOMAIN].items():
                    if key.startswith("data_manager_"):
                        shared_manager = value_dm
                        break

                if shared_manager is None:
                    _LOGGER.error("No SharedUbusDataManager available for uci_set_commit")
                    return

                client = await shared_manager._get_ubus_client()  # type: ignore[attr-defined]

                # Set and commit the UCI value
                await client.uci_set_option(config, section, option, value)
                await client.uci_commit_config(config)
                _LOGGER.debug("UCI set+commit %s/%s %s=%r", config, section, option, value)

                # Restart services if specified
                if services_to_restart:
                    # Handle both string and list inputs
                    service_list = (
                        services_to_restart if isinstance(services_to_restart, list) else [services_to_restart]
                    )
                    for service_name in service_list:
                        try:
                            result = await client.service_action(service_name, "restart")
                            _LOGGER.info(
                                "Restarted service %s after UCI change: %s",
                                service_name,
                                result,
                            )
                        except Exception as exc:
                            _LOGGER.warning("Failed to restart service %s: %s", service_name, exc)

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

            hass.services.async_register(
                DOMAIN,
                "uci_network_interface",
                async_handle_uci_network_interface,
            )

    except Exception as exc:
        raise ConfigEntryNotReady(f"Failed to connect to OpenWrt device at {hostname}: {exc}") from exc

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
        entry.data.get(CONF_ENABLE_SYSTEM_SENSORS, DEFAULT_ENABLE_SYSTEM_SENSORS),
    )

    # Check if QModem sensors are disabled
    qmodem_enabled = entry.options.get(
        CONF_ENABLE_QMODEM_SENSORS,
        entry.data.get(CONF_ENABLE_QMODEM_SENSORS, DEFAULT_ENABLE_QMODEM_SENSORS),
    )

    # Check if STA sensors are disabled
    sta_enabled = entry.options.get(
        CONF_ENABLE_STA_SENSORS,
        entry.data.get(CONF_ENABLE_STA_SENSORS, DEFAULT_ENABLE_STA_SENSORS),
    )

    # Check if AP sensors are disabled
    ap_enabled = entry.options.get(
        CONF_ENABLE_AP_SENSORS,
        entry.data.get(CONF_ENABLE_AP_SENSORS, DEFAULT_ENABLE_AP_SENSORS),
    )

    # Check if eth sensors are disabled
    eth_enabled = entry.options.get(
        CONF_ENABLE_ETH_SENSORS,
        entry.data.get(CONF_ENABLE_ETH_SENSORS, DEFAULT_ENABLE_ETH_SENSORS),
    )

    # Check if MWAN3 sensors are disabled
    mwan3_enabled = entry.options.get(
        CONF_ENABLE_MWAN3_SENSORS,
        entry.data.get(CONF_ENABLE_MWAN3_SENSORS, DEFAULT_ENABLE_MWAN3_SENSORS),
    )

    _LOGGER.debug(
        "Sensor states - System: %s, QModem: %s, STA: %s, AP: %s, ETH: %s, MWAN3: %s",
        system_enabled,
        qmodem_enabled,
        sta_enabled,
        ap_enabled,
        eth_enabled,
        mwan3_enabled,
    )

    # List all current devices for debugging
    all_devices = [
        device
        for device in device_registry.devices.values()
        if any(identifier[0] == DOMAIN for identifier in device.identifiers)
    ]
    _LOGGER.debug(
        "Current devices in registry: %s",
        [list(device.identifiers) for device in all_devices],
    )

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
                _LOGGER.info(
                    "Removing QModem device %s (QModem sensors disabled)",
                    f"{host}_qmodem",
                )
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
                            if (
                                identifier[0] == DOMAIN
                                and identifier[1] != host
                                and identifier[1] != f"{host}_qmodem"
                                and identifier[1] != f"{host}_eth"
                                and identifier[1] != f"{host}_mwan3"
                                and identifier[1] != f"{host}_ap"
                            ):
                                # This is a STA device (not the main router, QModem, AP device, network interface or MWAN device)
                                _LOGGER.info(
                                    "Removing STA device %s (STA sensors disabled)",
                                    identifier[1],
                                )
                                device_registry.async_remove_device(device.id)
                                removed_count += 1
                                break
            _LOGGER.debug("Removed %d STA devices", removed_count)

        sensors = [
            ("AP", ap_enabled, f"{host}_ap"),
            ("ETH", eth_enabled, f"{host}_eth"),
            ("MWAN3", mwan3_enabled, f"{host}_mwan3"),
        ]
        for name, enabled, main_id in sensors:
            if enabled:
                continue
            main_device = device_registry.async_get_device(identifiers={(DOMAIN, f"{host}_eth")})
            if not main_device:
                continue
            removed_count = 0
            for device in list(device_registry.devices.values()):  # Use list() to avoid modification during iteration
                if device.via_device_id == main_device.id:
                    device_registry.async_remove_device(device.id)
                    removed_count += 1

            _LOGGER.info("Removing %s devices", name)
            device_registry.async_remove_device(main_device.id)
            _LOGGER.debug("Removed %d %s devices", removed_count, name)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)

    if unload_ok:
        # Clean up shared data manager
        data_manager_key = f"data_manager_{entry.entry_id}"
        if DOMAIN in hass.data and data_manager_key in hass.data[DOMAIN]:
            data_manager: SharedUbusDataManager = hass.data[DOMAIN][data_manager_key]
            try:
                await data_manager.logout()
                await data_manager.close()
            except Exception as exc:
                _LOGGER.debug("Error closing data manager: %s", exc)
            hass.data[DOMAIN].pop(data_manager_key, None)

        # Clean up coordinators
        if DOMAIN in hass.data and "coordinators" in hass.data[DOMAIN]:
            coordinators = hass.data[DOMAIN]["coordinators"]
            for coordinator in coordinators:
                if hasattr(coordinator, "async_shutdown"):
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

        hass.data[DOMAIN].pop("mwan3_available", None)

    return unload_ok


async def async_remove_config_entry_device(_: HomeAssistant, entry: ConfigEntry, device_entry: dr.DeviceEntry) -> bool:
    """Handle device removal."""
    host = entry.data[CONF_HOST]
    for identifier in device_entry.identifiers:
        unique_id = str(identifier[1])
        if str(identifier[0]) == DOMAIN and not (
            unique_id == host or "_ap_" in unique_id or unique_id.endswith("_qmodem")
        ):
            return True
    return False
