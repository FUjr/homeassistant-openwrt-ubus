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
    UnitOfTemperature,
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
        key="conntrack_count",
        name="Connection Count",
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=None,
        icon="mdi:connection",
        entity_category=None,
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
        key="cpu_usage",
        name="CPU Usage",
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement="%",
        icon="mdi:cpu-64-bit",
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
        key="dhcp_clients_count",
        name="DHCP Clients Count",
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=None,
        icon="mdi:account-multiple",
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
    SensorEntityDescription(
        key="root_filesystem_free",
        name="Root Filesystem Free",
        device_class=SensorDeviceClass.DATA_SIZE,
        native_unit_of_measurement=UnitOfInformation.MEGABYTES,
        icon="mdi:harddisk",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="root_filesystem_total",
        name="Root Filesystem Total",
        device_class=SensorDeviceClass.DATA_SIZE,
        native_unit_of_measurement=UnitOfInformation.MEGABYTES,
        icon="mdi:harddisk",
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
        ["system_info", "system_stat", "system_board", "conntrack_count", "system_temperatures", "dhcp_clients_count"],  # Data types this coordinator needs
        f"{DOMAIN}_system_{entry.data[CONF_HOST]}",
        scan_interval,
    )

    # Fetch initial data
    await coordinator.async_config_entry_first_refresh()

    entities = [
        SystemInfoSensor(coordinator, description)
        for description in SENSOR_DESCRIPTIONS
    ]

    # Add temperature sensors dynamically based on available sensors
    if coordinator.data and "system_temperatures" in coordinator.data:
        temperatures = coordinator.data["system_temperatures"]
        for sensor_name, temp_value in temperatures.items():
            temp_description = SensorEntityDescription(
                key=f"temperature_{sensor_name}",
                name=f"Temperature {sensor_name}",
                device_class=SensorDeviceClass.TEMPERATURE,
                state_class=SensorStateClass.MEASUREMENT,
                native_unit_of_measurement=UnitOfTemperature.CELSIUS,
                icon="mdi:thermometer",
                entity_category=None,
            )
            entities.append(SystemInfoSensor(coordinator, temp_description))

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
        self.cpu_idle = None
        self.cpu_total = None

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
        elif key == "cpu_usage":
            system_stat = self.coordinator.data.get("system_stat", {}).get("data", "")
            cpu_data = next((line for line in system_stat.splitlines() if line.startswith("cpu ")), "").split()[1:]
            cpu_data = [int(value) for value in cpu_data]
            if len(cpu_data) < 10:
                return None
            cpu_idle = cpu_data[3] + cpu_data[4]
            cpu_total = sum(cpu_data)
            if self.cpu_idle is None or self.cpu_total is None:
                cpu_usage = None
            else:
                cpu_idle_delta = cpu_idle - self.cpu_idle
                cpu_total_delta = cpu_total - self.cpu_total
                cpu_usage = round((1. - cpu_idle_delta/cpu_total_delta) * 100) if cpu_total_delta > 0 else None
            self.cpu_total = cpu_total
            self.cpu_idle = cpu_idle
            return cpu_usage
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
                return round(swap.get("total", 0) / (1024 * 1024), 1) if "total" in swap else None
            elif key == "swap_free":
                return round(swap.get("free", 0) / (1024 * 1024), 1) if "free" in swap else None
        elif key.startswith("board_"):
            board_key = key.replace("board_", "")
            return board_info.get(board_key)
        elif key == "conntrack_count":
            return self.coordinator.data.get("conntrack_count")
        elif key.startswith("temperature_"):
            # Extract sensor name from key (after "temperature_")
            sensor_name = key[12:]  # Remove "temperature_" prefix
            temperatures = self.coordinator.data.get("system_temperatures", {})
            return temperatures.get(sensor_name)
        elif key == "dhcp_clients_count":
            return self.coordinator.data.get("dhcp_clients_count")
        elif key == "root_filesystem_total":
            root = self.coordinator.data.get("system_info", {}).get("root", {})
            total = root.get("total")
            return round(total / 1024, 2) if total is not None else None
        elif key == "root_filesystem_free":
            root = self.coordinator.data.get("system_info", {}).get("root", {})
            free = root.get("free")
            return round(free / 1024, 2) if free is not None else None

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
