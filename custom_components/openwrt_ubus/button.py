"""Support for OpenWrt buttons via ubus."""

from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import (
    DOMAIN,
    CONF_ENABLE_SERVICE_CONTROLS,
    CONF_ENABLE_DEVICE_KICK_BUTTONS,
    DEFAULT_ENABLE_SERVICE_CONTROLS,
    DEFAULT_ENABLE_DEVICE_KICK_BUTTONS,
)
from .buttons import service_button, device_kick_button

_LOGGER = logging.getLogger(__name__)

# Button modules configuration
BUTTON_MODULES = [
    {
        "module": service_button,
        "config_key": CONF_ENABLE_SERVICE_CONTROLS,
        "default": DEFAULT_ENABLE_SERVICE_CONTROLS,
        "name": "service_button"
    },
    {
        "module": device_kick_button,
        "config_key": CONF_ENABLE_DEVICE_KICK_BUTTONS,
        "default": DEFAULT_ENABLE_DEVICE_KICK_BUTTONS,
        "name": "device_kick_button"
    },
]


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up OpenWrt buttons from a config entry."""
    _LOGGER.info("Setting up OpenWrt buttons")

    coordinators = []

    # Setup each button module based on configuration
    for button_config in BUTTON_MODULES:
        module = button_config["module"]
        config_key = button_config["config_key"]
        default_enabled = button_config["default"]
        module_name = button_config["name"]

        # Check if this button type is enabled
        # Priority: options > data > default
        enabled = entry.options.get(
            config_key,
            entry.data.get(config_key, default_enabled)
        )

        if not enabled:
            _LOGGER.info("Button module %s is disabled in configuration", module_name)
            continue

        try:
            # Check if module has async_setup_entry function
            if hasattr(module, 'async_setup_entry'):
                _LOGGER.debug("Loading button module: %s", module_name)

                # For device_kick_button, we need to pass the add_entities callback
                if module_name == "device_kick_button":
                    await module.async_setup_entry(hass, entry, async_add_entities)
                else:
                    # Call the module's setup function
                    coordinator = await module.async_setup_entry(hass, entry, async_add_entities)

                    if coordinator:
                        coordinators.append(coordinator)
                        _LOGGER.info("Successfully loaded button module: %s", module_name)
                    else:
                        _LOGGER.debug("Button module %s returned no coordinator", module_name)
            else:
                _LOGGER.warning("Button module %s has no async_setup_entry function", module_name)

        except Exception as exc:
            _LOGGER.error("Error setting up button module %s: %s", module_name, exc)

    _LOGGER.info("Completed loading of %d button modules", len(coordinators))

    # Store coordinators in hass data for cleanup
    hass.data.setdefault(DOMAIN, {})
    if "button_coordinators" not in hass.data[DOMAIN]:
        hass.data[DOMAIN]["button_coordinators"] = []
    hass.data[DOMAIN]["button_coordinators"].extend(coordinators)
