"""Support for OpenWrt router sensors."""

from __future__ import annotations

import asyncio
import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import (
    DOMAIN,
    CONF_ENABLE_QMODEM_SENSORS,
    CONF_ENABLE_STA_SENSORS,
    CONF_ENABLE_SYSTEM_SENSORS,
    CONF_ENABLE_AP_SENSORS,
    CONF_ENABLE_ETH_SENSORS,
    CONF_ENABLE_NLBWMON_SENSORS,
    DEFAULT_ENABLE_QMODEM_SENSORS,
    DEFAULT_ENABLE_STA_SENSORS,
    DEFAULT_ENABLE_SYSTEM_SENSORS,
    DEFAULT_ENABLE_AP_SENSORS,
    DEFAULT_ENABLE_ETH_SENSORS,
    DEFAULT_ENABLE_MWAN3_SENSORS,
    DEFAULT_ENABLE_NLBWMON_SENSORS,
)
from .sensors import (
    system_sensor,
    qmodem_sensor,
    sta_sensor,
    ap_sensor,
    eth_sensor,
    mwan3_sensor,
    nlbwmon_sensor,
)

_LOGGER = logging.getLogger(__name__)

# Sensor modules configuration
SENSOR_MODULES = [
    {
        "module": system_sensor,
        "config_key": CONF_ENABLE_SYSTEM_SENSORS,
        "default": DEFAULT_ENABLE_SYSTEM_SENSORS,
        "name": "system_sensor",
    },
    {
        "module": qmodem_sensor,
        "config_key": CONF_ENABLE_QMODEM_SENSORS,
        "default": DEFAULT_ENABLE_QMODEM_SENSORS,
        "name": "qmodem_sensor",
    },
    {
        "module": sta_sensor,
        "config_key": CONF_ENABLE_STA_SENSORS,
        "default": DEFAULT_ENABLE_STA_SENSORS,
        "name": "sta_sensor",
    },
    {
        "module": ap_sensor,
        "config_key": CONF_ENABLE_AP_SENSORS,
        "default": DEFAULT_ENABLE_AP_SENSORS,
        "name": "ap_sensor",
    },
    {
        "module": mwan3_sensor,
        "config_key": "enable_mwan3_sensors",
        "default": DEFAULT_ENABLE_MWAN3_SENSORS,
        "name": "mwan3_sensor",
    },
    {
        "module": eth_sensor,
        "config_key": CONF_ENABLE_ETH_SENSORS,
        "default": DEFAULT_ENABLE_ETH_SENSORS,
        "name": "eth_sensor",
    },
    {
        "module": nlbwmon_sensor,
        "config_key": CONF_ENABLE_NLBWMON_SENSORS,
        "default": DEFAULT_ENABLE_NLBWMON_SENSORS,
        "name": "nlbwmon_sensor",
    },
]


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up OpenWrt sensors from a config entry."""
    _LOGGER.info("Setting up OpenWrt sensors")

    # Modules are independent: each does its own first refresh against the router,
    # so run them concurrently instead of one after another (sequential setup took
    # >10 s and triggered "Setup of sensor platform is taking over 10 seconds").
    async def _setup_module(sensor_config: dict):
        module = sensor_config["module"]
        module_name = sensor_config["name"]

        # Priority: options > data > default
        enabled = entry.options.get(
            sensor_config["config_key"], entry.data.get(sensor_config["config_key"], sensor_config["default"])
        )
        if not enabled:
            _LOGGER.debug("Sensor module %s is disabled in configuration", module_name)
            return None
        if not hasattr(module, "async_setup_entry"):
            _LOGGER.warning("Sensor module %s has no async_setup_entry function", module_name)
            return None

        try:
            _LOGGER.debug("Loading sensor module: %s", module_name)
            coordinator = await module.async_setup_entry(hass, entry, async_add_entities)
        except Exception as exc:  # noqa: BLE001 - one broken module must not break the others
            _LOGGER.error("Error setting up sensor module %s: %s", module_name, exc)
            return None

        if coordinator is None:
            _LOGGER.debug("Sensor module %s returned no coordinator", module_name)
        return coordinator

    results = await asyncio.gather(*(_setup_module(cfg) for cfg in SENSOR_MODULES))
    coordinators = [c for c in results if c]
    _LOGGER.debug("Completed loading of %d sensor modules", len(coordinators))

    # Remember coordinators so they are shut down on unload
    entry.runtime_data.coordinators.extend(coordinators)
