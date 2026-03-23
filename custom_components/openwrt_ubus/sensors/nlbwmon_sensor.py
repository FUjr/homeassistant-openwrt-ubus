"""Support for OpenWrt nlbwmon top host sensors."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from homeassistant.components.sensor import SensorEntity, SensorEntityDescription
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from ..const import DOMAIN, CONF_PORT, CONF_USE_HTTPS, DEFAULT_USE_HTTPS, build_configuration_url
from ..shared_data_manager import SharedDataUpdateCoordinator

SCAN_INTERVAL = timedelta(seconds=60)


def _format_bytes(num_bytes: int) -> str:
    """Format bytes using binary units."""
    value = float(num_bytes)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if value < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.2f} {unit}"
        value /= 1024
    return f"{num_bytes} B"


SENSOR_DESCRIPTION = SensorEntityDescription(
    key="top_bandwidth_hosts",
    name="Top Bandwidth Hosts",
    icon="mdi:network-outline",
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> SharedDataUpdateCoordinator:
    """Set up OpenWrt nlbwmon sensors from a config entry."""
    data_manager_key = f"data_manager_{entry.entry_id}"
    data_manager = hass.data[DOMAIN][data_manager_key]

    coordinator = SharedDataUpdateCoordinator(
        hass,
        data_manager,
        ["nlbwmon_top_hosts"],
        f"{DOMAIN}_nlbwmon_{entry.data[CONF_HOST]}",
        SCAN_INTERVAL,
    )

    await coordinator.async_config_entry_first_refresh()
    async_add_entities([NLBWTopHostsSensor(coordinator, SENSOR_DESCRIPTION)], True)
    return coordinator


class NLBWTopHostsSensor(CoordinatorEntity, SensorEntity):
    """Representation of an nlbwmon top hosts sensor."""

    def __init__(
        self,
        coordinator: SharedDataUpdateCoordinator,
        description: SensorEntityDescription,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator)
        self.entity_description = description
        self._host = coordinator.data_manager.entry.data[CONF_HOST]
        self._attr_unique_id = f"{self._host}_{description.key}"
        self._attr_has_entity_name = True

    @property
    def device_info(self) -> DeviceInfo:
        """Return device info for the router."""
        return DeviceInfo(
            identifiers={(DOMAIN, self._host)},
            name=f"OpenWrt Router ({self._host})",
            manufacturer="OpenWrt",
            model="Router",
            configuration_url=build_configuration_url(
                self._host,
                self.coordinator.data_manager.entry.data.get(CONF_USE_HTTPS, DEFAULT_USE_HTTPS),
                self.coordinator.data_manager.entry.data.get(CONF_PORT),
            ),
        )

    @property
    def native_value(self) -> int:
        """Return the number of tracked hosts."""
        data = self.coordinator.data.get("nlbwmon_top_hosts", {}) if self.coordinator.data else {}
        return int(data.get("host_count", 0))

    @property
    def available(self) -> bool:
        """Return True if entity is available."""
        return self.coordinator.last_update_success

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return top-host data as state attributes."""
        data = self.coordinator.data.get("nlbwmon_top_hosts", {}) if self.coordinator.data else {}
        top_hosts = []

        for index, host in enumerate(data.get("top_hosts", []), start=1):
            top_hosts.append(
                {
                    "rank": index,
                    "hostname": host.get("hostname"),
                    "ip": host.get("ip"),
                    "mac": host.get("mac"),
                    "connections": host.get("connections", 0),
                    "rx_bytes": host.get("rx_bytes", 0),
                    "tx_bytes": host.get("tx_bytes", 0),
                    "total_bytes": host.get("total_bytes", 0),
                    "download": _format_bytes(int(host.get("rx_bytes", 0))),
                    "upload": _format_bytes(int(host.get("tx_bytes", 0))),
                    "total": _format_bytes(int(host.get("total_bytes", 0))),
                }
            )

        return {
            "router_host": self._host,
            "host_count": data.get("host_count", 0),
            "total_download": _format_bytes(int(data.get("total_rx_bytes", 0))),
            "total_upload": _format_bytes(int(data.get("total_tx_bytes", 0))),
            "top_hosts": top_hosts,
        }