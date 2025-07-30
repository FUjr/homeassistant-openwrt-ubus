"""Support for OpenWrt router QModem information sensors."""

from __future__ import annotations

from datetime import timedelta
import logging
import re
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_USERNAME,
    PERCENTAGE,
    UnitOfInformation,
    UnitOfTime,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity,
    DataUpdateCoordinator,
    UpdateFailed,
)

from ..const import (
    DOMAIN,
    CONF_SYSTEM_SENSOR_TIMEOUT,
    DEFAULT_SYSTEM_SENSOR_TIMEOUT,
)
from ..shared_data_manager import SharedDataUpdateCoordinator

_LOGGER = logging.getLogger(__name__)

SCAN_INTERVAL = timedelta(minutes=2)  # QModem info changes more frequently

SENSOR_DESCRIPTIONS = [
    SensorEntityDescription(
        key="uptime",
        name="Uptime",
        device_class=SensorDeviceClass.DURATION,
        state_class=SensorStateClass.TOTAL_INCREASING,
        native_unit_of_measurement=UnitOfTime.SECONDS,
        suggested_unit_of_measurement=UnitOfTime.HOURS,
        entity_category=None,  # Main sensor, not diagnostic
        icon="mdi:clock-outline",
    ),
    SensorEntityDescription(
        key="load_1",
        name="Load Average (1m)",
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement="%",
        icon="mdi:speedometer",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="load_5",
        name="Load Average (5m)",
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement="%",
        icon="mdi:speedometer",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="load_15",
        name="Load Average (15m)",
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement="%",
        icon="mdi:speedometer",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="memory_total",
        name="Total Memory",
        device_class=SensorDeviceClass.DATA_SIZE,
        native_unit_of_measurement=UnitOfInformation.MEGABYTES,
        icon="mdi:memory",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="memory_free",
        name="Free Memory",
        device_class=SensorDeviceClass.DATA_SIZE,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfInformation.MEGABYTES,
        icon="mdi:memory",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="memory_buffered",
        name="Buffered Memory",
        device_class=SensorDeviceClass.DATA_SIZE,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfInformation.MEGABYTES,
        icon="mdi:memory",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="memory_shared",
        name="Shared Memory",
        device_class=SensorDeviceClass.DATA_SIZE,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfInformation.MEGABYTES,
        icon="mdi:memory",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="memory_usage_percent",
        name="Memory Usage",
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=PERCENTAGE,
        icon="mdi:memory",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="swap_total",
        name="Total Swap",
        device_class=SensorDeviceClass.DATA_SIZE,
        native_unit_of_measurement=UnitOfInformation.MEGABYTES,
        icon="mdi:harddisk",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="swap_free",
        name="Free Swap",
        device_class=SensorDeviceClass.DATA_SIZE,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfInformation.MEGABYTES,
        icon="mdi:harddisk",
        entity_category=None,
    ),
    # Board/Hardware information sensors
    SensorEntityDescription(
        key="board_kernel",
        name="Kernel Version",
        icon="mdi:chip",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="board_hostname",
        name="Hostname",
        icon="mdi:router-network",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="board_model",
        name="Board Model",
        icon="mdi:developer-board",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="board_system",
        name="System",
        icon="mdi:chip",
        entity_category=None,
    ),
]


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> SharedDataUpdateCoordinator:
    """Set up OpenWrt system sensors from a config entry."""
    
    # Get shared data manager
    data_manager_key = f"data_manager_{entry.entry_id}"
    data_manager = hass.data[DOMAIN][data_manager_key]
    
    # Get timeout from configuration (priority: options > data > default)
    timeout = entry.options.get(
        CONF_SYSTEM_SENSOR_TIMEOUT,
        entry.data.get(CONF_SYSTEM_SENSOR_TIMEOUT, DEFAULT_SYSTEM_SENSOR_TIMEOUT)
    )
    scan_interval = timedelta(seconds=timeout)
    
    # Create coordinator using shared data manager
    coordinator = SharedDataUpdateCoordinator(
        hass,
        data_manager,
        ["system_info", "system_board"],  # Data types this coordinator needs
        f"{DOMAIN}_system_{entry.data[CONF_HOST]}",
        scan_interval,
    )

    # Fetch initial data
    await coordinator.async_config_entry_first_refresh()

    entities = [
        SystemInfoSensor(coordinator, description)
        for description in SENSOR_DESCRIPTIONS
    ]

    async_add_entities(entities, True)

    return coordinator

class SystemInfoCoordinator(DataUpdateCoordinator):
    """Class to manage fetching system information from the router."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        """Initialize."""
        self.entry = entry
        self.host = entry.data[CONF_HOST]
        self.username = entry.data[CONF_USERNAME]
        self.password = entry.data[CONF_PASSWORD]

        # Get Home Assistant's HTTP client session
        session = async_get_clientsession(hass)

        self.url = f"http://{self.host}/ubus"

class SystemInfoSensor(CoordinatorEntity, SensorEntity):
    """Representation of a system information sensor."""

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
        # Try to get board info from coordinator data
        board_model = self.coordinator.data.get("system_board", {}).get("model", "Router") if self.coordinator.data else "Router"
        board_hostname = self.coordinator.data.get("system_board", {}).get("hostname") if self.coordinator.data else None
        board_system = self.coordinator.data.get("system_board", {}).get("system") if self.coordinator.data else None

        # Use hostname for name if available, otherwise use host
        device_name = board_hostname or f"OpenWrt Router ({self._host})"

        return DeviceInfo(
            identifiers={(DOMAIN, self._host)},
            name=device_name,
            manufacturer="OpenWrt",
            model=board_model,
            configuration_url=f"http://{self._host}",
            sw_version=board_system,  # Use system info as software version
        )

    @property
    def native_value(self) -> Any:
        """Return the value reported by the sensor."""
        if not self.coordinator.data:
            return None

        return self._get_sensor_value()

    def _get_sensor_value(self) -> Any:
        """Get the sensor value from coordinator data."""
        key = self.entity_description.key
        
        # Handle system info data
        system_info = self.coordinator.data.get("system_info", {})
        board_info = self.coordinator.data.get("system_board", {})
        
        # Map sensor keys to their data sources
        if key == "uptime":
            return system_info.get("uptime")
        elif key in ["load_1", "load_5", "load_15"]:
            load = system_info.get("load", [])
            if isinstance(load, list) and len(load) >= 3:
                load_map = {"load_1": 0, "load_5": 1, "load_15": 2}
                return load[load_map[key]] / 1000 if key in load_map else None
        elif key.startswith("memory_"):
            memory = system_info.get("memory", {})
            if key == "memory_total":
                return round(memory.get("total", 0) / (1024 * 1024), 1) if memory.get("total") else None
            elif key == "memory_free":
                return round(memory.get("free", 0) / (1024 * 1024), 1) if memory.get("free") else None
            elif key == "memory_buffered":
                return round(memory.get("buffered", 0) / (1024 * 1024), 1) if memory.get("buffered") else None
            elif key == "memory_shared":
                return round(memory.get("shared", 0) / (1024 * 1024), 1) if memory.get("shared") else None
            elif key == "memory_usage_percent":
                total = memory.get("total", 0)
                free = memory.get("free", 0)
                if total > 0:
                    used = total - free
                    return round((used / total) * 100, 1)
        elif key.startswith("swap_"):
            swap = system_info.get("swap", {})
            if key == "swap_total":
                return round(swap.get("total", 0) / (1024 * 1024), 1) if swap.get("total") else None
            elif key == "swap_free":
                return round(swap.get("free", 0) / (1024 * 1024), 1) if swap.get("free") else None
        elif key.startswith("board_"):
            board_key = key.replace("board_", "")
            return board_info.get(board_key)
        
        return None

    @property
    def available(self) -> bool:
        """Return True if coordinator is available."""
        return self.coordinator.last_update_success

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        """Return additional state attributes."""
        attributes = {
            "router_host": self._host,
            "last_update": self.coordinator.last_update_success,
        }

        # Add raw system info for debugging if available
        if self.coordinator.data:
            attributes["raw_data"] = str(self.coordinator.data)

        return attributes
