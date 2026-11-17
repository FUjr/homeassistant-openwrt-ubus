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
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers import config_validation as cv, device_registry as dr
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.service import async_register_admin_service
from homeassistant.helpers.typing import ConfigType

from .Ubus.interface import AuthenticationError
from .Ubus.const import API_DEF_TIMEOUT
from .const import (
    CONF_DHCP_SOFTWARE,
    CONF_WIRELESS_SOFTWARE,
    CONF_USE_HTTPS,
    CONF_PORT,
    CONF_ENDPOINT,
    CONF_ENABLE_QMODEM_SENSORS,
    CONF_ENABLE_STA_SENSORS,
    CONF_ENABLE_SYSTEM_SENSORS,
    CONF_ENABLE_AP_SENSORS,
    CONF_ENABLE_ETH_SENSORS,
    CONF_ENABLE_MWAN3_SENSORS,
    CONF_ENABLE_NLBWMON_SENSORS,
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
    DEFAULT_USE_HTTPS,
    DEFAULT_ENDPOINT,
    DHCP_SOFTWARES,
    DOMAIN,
    PLATFORMS,
    WIRELESS_SOFTWARES,
    build_ubus_url,
)
from .extended_ubus import ExtendedUbus
from .runtime import OpenwrtRuntimeData
from .services import async_setup_services
from .shared_data_manager import SharedUbusDataManager

_LOGGER = logging.getLogger(__name__)

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Set up the integration (services are registered once, not per config entry)."""
    await async_setup_services(hass)
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up openwrt ubus from a config entry."""
    hass.data.setdefault(DOMAIN, {})

    # Backward compatibility: preserve pre-toggle behavior for legacy entries.
    # New entries get an explicit value from config flow (default off).
    if CONF_ENABLE_NLBWMON_SENSORS not in entry.data:
        new_data = dict(entry.data)
        new_data[CONF_ENABLE_NLBWMON_SENSORS] = True
        hass.config_entries.async_update_entry(entry, data=new_data)
        entry = hass.config_entries.async_get_entry(entry.entry_id)
        if entry is None:
            raise ConfigEntryNotReady("Failed to reload config entry data for nlbwmon migration")

    # Test connection before setting up platforms
    hostname = entry.data[CONF_HOST]
    try:
        ip = entry.data.get(CONF_IP_ADDRESS, None)
        use_https = entry.data.get(CONF_USE_HTTPS, DEFAULT_USE_HTTPS)
        port = entry.data.get(CONF_PORT)
        endpoint = entry.data.get(CONF_ENDPOINT, DEFAULT_ENDPOINT)
        url = build_ubus_url(hostname, use_https, ip, port, endpoint)
        session = async_get_clientsession(hass, verify_ssl=entry.data.get(CONF_VERIFY_SSL, False))
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
        try:
            session_id = await ubus.connect()
        except AuthenticationError as exc:
            raise ConfigEntryAuthFailed(f"Invalid credentials for OpenWrt device at {hostname}") from exc
        if session_id is None:
            raise ConfigEntryNotReady(f"Failed to connect to OpenWrt device at {hostname}")

        import asyncio

        async def _check_availability(check_name: str, create_coro) -> bool:
            """Run an availability check with retries for resilience during startup bursts."""
            for attempt in range(1, 4):
                try:
                    result = await create_coro()
                    # list_mwan3 etc can return empty lists/dicts if not supported gracefully
                    if result:
                        _LOGGER.debug("%s availability check: True", check_name)
                        return True
                    _LOGGER.debug("%s availability check returned False/None/Empty", check_name)
                    return False
                except Exception as exc:
                    err_str = str(exc)
                    # Don't retry permission errors
                    if "Access denied" in err_str or type(exc).__name__ in ("PermissionError",):
                        _LOGGER.debug("%s check failed (Permission Denied): %s", check_name, exc)
                        return False
                    
                    _LOGGER.debug("%s check failed (attempt %d/3): %s", check_name, attempt, exc)
                    if attempt < 3:
                        await asyncio.sleep(2)
            
            return False

        # Check for modem_ctrl availability and store the result
        modem_ctrl_available = await _check_availability(
            "Modem_ctrl", lambda: ubus.list_modem_ctrl()
        )

        # Check for mwan3 availability and store the result
        mwan3_available = await _check_availability(
            "MWAN3", lambda: ubus.list_mwan3()
        )

        # Check for nlbwmon availability/permission and store the result
        nlbwmon_available = await _check_availability(
            "nlbwmon", lambda: ubus.file_exec("/usr/sbin/nlbw", ["-h"])
        )

        # Close the test connection — logout first to destroy the rpcd session,
        # otherwise the session lingers until rpcd's own 300 s GC runs.
        await ubus.logout()
        await ubus.close()

        # Create shared data manager; everything per-router lives in entry.runtime_data
        data_manager = SharedUbusDataManager(hass, entry)
        entry.runtime_data = OpenwrtRuntimeData(
            data_manager=data_manager,
            modem_ctrl_available=modem_ctrl_available,
            mwan3_available=mwan3_available,
            nlbwmon_available=nlbwmon_available,
        )

    except ConfigEntryAuthFailed:
        raise
    except Exception as exc:
        raise ConfigEntryNotReady(f"Failed to connect to OpenWrt device at {hostname}: {exc}") from exc

    # Register the main router device first: child devices link to it via via_device_id,
    # which needs a real device id.
    dr.async_get(hass).async_get_or_create(
        config_entry_id=entry.entry_id,
        identifiers={(DOMAIN, hostname)},
        name=hostname,
        manufacturer="OpenWrt",
    )

    # Set up platforms
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # Clean up devices for disabled sensors after setting up platforms
    # This ensures devices exist before we try to clean them up
    await _cleanup_disabled_sensor_devices(hass, entry)

    return True


def _entry_flag(entry: ConfigEntry, key: str, default: bool) -> bool:
    """Read a sensor toggle (priority: options > data > default)."""
    return entry.options.get(key, entry.data.get(key, default))


async def _cleanup_disabled_sensor_devices(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Remove devices that belong to disabled sensor groups.

    Only devices of this config entry are looked at (the device registry no longer
    allows lookups by identifier across config entries).
    """
    device_registry = dr.async_get(hass)
    host = entry.data[CONF_HOST]

    system_enabled = _entry_flag(entry, CONF_ENABLE_SYSTEM_SENSORS, DEFAULT_ENABLE_SYSTEM_SENSORS)
    qmodem_enabled = _entry_flag(entry, CONF_ENABLE_QMODEM_SENSORS, DEFAULT_ENABLE_QMODEM_SENSORS)
    sta_enabled = _entry_flag(entry, CONF_ENABLE_STA_SENSORS, DEFAULT_ENABLE_STA_SENSORS)
    ap_enabled = _entry_flag(entry, CONF_ENABLE_AP_SENSORS, DEFAULT_ENABLE_AP_SENSORS)
    eth_enabled = _entry_flag(entry, CONF_ENABLE_ETH_SENSORS, DEFAULT_ENABLE_ETH_SENSORS)
    mwan3_enabled = _entry_flag(entry, CONF_ENABLE_MWAN3_SENSORS, DEFAULT_ENABLE_MWAN3_SENSORS)

    _LOGGER.debug(
        "Sensor states - System: %s, QModem: %s, STA: %s, AP: %s, ETH: %s, MWAN3: %s",
        system_enabled,
        qmodem_enabled,
        sta_enabled,
        ap_enabled,
        eth_enabled,
        mwan3_enabled,
    )

    def _find(identifier: str) -> dr.DeviceEntry | None:
        return device_registry.async_get_device_by_identifier((DOMAIN, identifier), entry.entry_id)

    # If system sensors are disabled, remove the main router device
    # (HA also detaches everything that was linked through it)
    if not system_enabled:
        if main_device := _find(host):
            _LOGGER.info("Removing main router device %s (system sensors disabled)", host)
            device_registry.async_remove_device(main_device.id)
        return

    if not qmodem_enabled and (qmodem_device := _find(f"{host}_qmodem")):
        _LOGGER.info("Removing QModem device %s_qmodem (QModem sensors disabled)", host)
        device_registry.async_remove_device(qmodem_device.id)

    group_ids = {host, f"{host}_qmodem", f"{host}_eth", f"{host}_mwan3", f"{host}_ap"}
    main_device = _find(host)

    # If STA sensors are disabled, remove client devices attached to the router or its AP devices
    if not sta_enabled and main_device is not None:
        removed_count = 0
        for device in dr.async_entries_for_config_entry(device_registry, entry.entry_id):
            if device.via_device_id is None:
                continue
            parent = device_registry.async_get(device.via_device_id)
            if parent is None:
                continue
            parent_ids = {i[1] for i in parent.identifiers if i[0] == DOMAIN}
            # Client devices hang below the router or an "<host>_ap_<iface>" AP device
            if not (host in parent_ids or any(i.startswith(f"{host}_ap_") for i in parent_ids)):
                continue
            own_ids = {i[1] for i in device.identifiers if i[0] == DOMAIN}
            if own_ids & group_ids or any(i.startswith(f"{host}_ap_") for i in own_ids):
                continue  # group hubs / AP devices are not clients
            _LOGGER.info("Removing STA device %s (STA sensors disabled)", own_ids)
            device_registry.async_remove_device(device.id)
            removed_count += 1
        _LOGGER.debug("Removed %d STA devices", removed_count)

    for name, enabled, group_id in (
        ("AP", ap_enabled, f"{host}_ap"),
        ("ETH", eth_enabled, f"{host}_eth"),
        ("MWAN3", mwan3_enabled, f"{host}_mwan3"),
    ):
        if enabled:
            continue
        group_device = _find(group_id)
        if group_device is None:
            continue
        removed_count = 0
        for device in dr.async_entries_for_config_entry(device_registry, entry.entry_id):
            if device.via_device_id == group_device.id:
                device_registry.async_remove_device(device.id)
                removed_count += 1
        _LOGGER.info("Removing %s devices", name)
        device_registry.async_remove_device(group_device.id)
        _LOGGER.debug("Removed %d %s child devices", removed_count, name)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)

    if unload_ok:
        runtime: OpenwrtRuntimeData = entry.runtime_data
        for coordinator in runtime.coordinators:
            try:
                await coordinator.async_shutdown()
            except Exception as exc:  # noqa: BLE001
                _LOGGER.debug("Error shutting down coordinator: %s", exc)
        try:
            await runtime.data_manager.logout()
            await runtime.data_manager.close()
        except Exception as exc:  # noqa: BLE001
            _LOGGER.debug("Error closing data manager: %s", exc)

        # Cross-router lookup tables (uniqueid tracking) must not keep this entry's coordinators
        domain_data = hass.data.get(DOMAIN, {})
        for registry in ("tracker_coordinators", "sta_sensor_coordinators", "device_kick_coordinators"):
            domain_data.get(registry, {}).pop(entry.entry_id, None)

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


async def async_remove_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Forget the tracking-method memory of a removed entry."""
    hass.data.get(DOMAIN, {}).pop(f"tracking_method_{entry.entry_id}", None)
