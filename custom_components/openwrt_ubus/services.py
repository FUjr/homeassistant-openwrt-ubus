"""Services of the OpenWrt ubus integration."""

from __future__ import annotations

import logging

from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.exceptions import ServiceValidationError
from homeassistant.helpers.service import async_register_admin_service

from .const import DOMAIN
from .extended_ubus import ExtendedUbus

_LOGGER = logging.getLogger(__name__)

ATTR_CONFIG_ENTRY_ID = "config_entry_id"


async def _async_get_client(hass: HomeAssistant, call: ServiceCall) -> ExtendedUbus:
    """Return the ubus client of the router the call is meant for.

    With one router configured it is used automatically; with several, the call must
    carry ``config_entry_id``.
    """
    entries = hass.config_entries.async_loaded_entries(DOMAIN)
    if (entry_id := call.data.get(ATTR_CONFIG_ENTRY_ID)) is not None:
        entries = [entry for entry in entries if entry.entry_id == entry_id]
        if not entries:
            raise ServiceValidationError(f"No loaded OpenWrt ubus entry with id {entry_id}")
    elif not entries:
        raise ServiceValidationError("No OpenWrt ubus router is set up")
    elif len(entries) > 1:
        raise ServiceValidationError(f"Several routers are configured; pass {ATTR_CONFIG_ENTRY_ID} to select one")
    return await entries[0].runtime_data.data_manager.async_get_client()


async def _async_uci_get(call: ServiceCall) -> None:
    """Read a UCI value and optionally store it as the state of an entity."""
    hass = call.hass
    config = call.data["config"]
    section = call.data.get("section")
    option = call.data.get("option")
    target_entity_id = call.data.get("target_entity_id")

    client = await _async_get_client(hass, call)
    result = await client.uci_get_option(config, section, option)
    _LOGGER.debug("UCI get %s/%s/%s -> %s", config, section, option, result)

    # ubus returns {"value": "..."} for section+option and {"values": {...}} otherwise
    value = None
    if isinstance(result, dict):
        if "value" in result:
            value = result["value"]
        else:
            values = result.get("values", {})
            if option is not None:
                value = values.get(option)
            elif values:
                value = next(iter(values.values()))

    if target_entity_id and value is not None:
        hass.states.async_set(target_entity_id, value)
    elif target_entity_id:
        _LOGGER.warning("UCI get for %s/%s/%s returned no value; not updating %s", config, section, option, target_entity_id)


async def _async_uci_network_interface(call: ServiceCall) -> None:
    """Call an ubus object method (e.g. network.interface.wwan up)."""
    client = await _async_get_client(call.hass, call)
    await client.uci_network_interface(call.data["section"], call.data["option"])
    _LOGGER.debug("UBUS call %s %s", call.data["section"], call.data["option"])


async def _async_uci_set_commit(call: ServiceCall) -> None:
    """Set a UCI option, commit it and optionally restart services."""
    config = call.data["config"]
    section = call.data["section"]
    option = call.data["option"]
    value = call.data["value"]
    services_to_restart = call.data.get("service")

    client = await _async_get_client(call.hass, call)
    await client.uci_set_option(config, section, option, value)
    await client.uci_commit_config(config)
    _LOGGER.debug("UCI set+commit %s/%s %s=%r", config, section, option, value)

    if services_to_restart:
        service_list = services_to_restart if isinstance(services_to_restart, list) else [services_to_restart]
        for service_name in service_list:
            try:
                result = await client.service_action(service_name, "restart")
                _LOGGER.info("Restarted service %s after UCI change: %s", service_name, result)
            except Exception as exc:  # noqa: BLE001 - one failing restart must not stop the others
                _LOGGER.warning("Failed to restart service %s: %s", service_name, exc)


async def async_setup_services(hass: HomeAssistant) -> None:
    """Register the services (admin only: they change router configuration)."""
    async_register_admin_service(hass, DOMAIN, "uci_get", _async_uci_get)
    async_register_admin_service(hass, DOMAIN, "uci_set_commit", _async_uci_set_commit)
    async_register_admin_service(hass, DOMAIN, "uci_network_interface", _async_uci_network_interface)
