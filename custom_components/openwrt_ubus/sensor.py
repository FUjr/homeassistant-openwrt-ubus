"""Support for OpenWrt router sensors."""

from __future__ import annotations

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
    DEFAULT_ENABLE_QMODEM_SENSORS,
    DEFAULT_ENABLE_STA_SENSORS,
    DEFAULT_ENABLE_SYSTEM_SENSORS,
    DEFAULT_ENABLE_AP_SENSORS,
    DEFAULT_ENABLE_ETH_SENSORS,
)
from .sensors import system_sensor, qmodem_sensor, sta_sensor, ap_sensor, eth_sensor

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
        "module": eth_sensor,
        "config_key": CONF_ENABLE_ETH_SENSORS,
        "default": DEFAULT_ENABLE_ETH_SENSORS,
        "name": "eth_sensor",
    },
]


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up OpenWrt sensors from a config entry."""
    _LOGGER.info("Setting up OpenWrt sensors")

    coordinators = []

    # Setup each sensor module based on configuration
    for sensor_config in SENSOR_MODULES:
        module = sensor_config["module"]
        config_key = sensor_config["config_key"]
        default_enabled = sensor_config["default"]
        module_name = sensor_config["name"]

        # Check if this sensor type is enabled
        # Priority: options > data > default
        enabled = entry.options.get(config_key, entry.data.get(config_key, default_enabled))

        if not enabled:
            _LOGGER.info("Sensor module %s is disabled in configuration", module_name)
            continue

        try:
            # Check if module has async_setup_entry function
            if hasattr(module, "async_setup_entry"):
                _LOGGER.debug("Loading sensor module: %s", module_name)

                try:
                    # Call the module's setup function
                    coordinator = await module.async_setup_entry(hass, entry, async_add_entities)
                except Exception as exc:
                    # If the error is from the eth_sensor module, log with eth_sensor logger
                    if module_name == "eth_sensor":
                        eth_logger = logging.getLogger("custom_components.openwrt_ubus.sensors.eth_sensor")
                        eth_logger.error("Error accessing coordinator for eth_sensor: %s", exc)
                        eth_logger.error("eth_sensor module entry data: %s", entry.data)
                        eth_logger.error("eth_sensor module entry options: %s", entry.options)
                    else:
                        _LOGGER.error("Error setting up sensor module %s: %s", module_name, exc)
                    coordinator = None

                if coordinator:
                    coordinators.append(coordinator)
                    _LOGGER.info("Successfully loaded sensor module: %s", module_name)
                else:
                    _LOGGER.debug("Sensor module %s returned no coordinator", module_name)
            else:
                _LOGGER.warning("Sensor module %s has no async_setup_entry function", module_name)

        except Exception as exc:
            _LOGGER.error("Error setting up sensor module %s: %s", module_name, exc)

    _LOGGER.info("Completed loading of %d sensor modules", len(coordinators))

    # Store coordinators in hass data for cleanup
    if DOMAIN not in hass.data:
        hass.data[DOMAIN] = {}
    if "coordinators" not in hass.data[DOMAIN]:
        hass.data[DOMAIN]["coordinators"] = []
    hass.data[DOMAIN]["coordinators"].extend(coordinators)
