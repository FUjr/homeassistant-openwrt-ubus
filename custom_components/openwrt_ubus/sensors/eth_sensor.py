"""Support for OpenWrt router network interface sensors."""

from __future__ import annotations

from datetime import timedelta
import logging
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
    UnitOfDataRate,
    UnitOfInformation,
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

SCAN_INTERVAL = timedelta(minutes=1)  # Network stats change frequently

SENSOR_DESCRIPTIONS = [
    SensorEntityDescription(
        key="status",
        name="Status",
        icon="mdi:network",
    ),
    SensorEntityDescription(
        key="speed",
        name="Speed",
        icon="mdi:speedometer",
    ),
    SensorEntityDescription(
        key="carrier",
        name="Carrier",
        icon="mdi:cable-data",
    ),
    SensorEntityDescription(
        key="mtu",
        name="MTU",
        icon="mdi:network",
    ),
    SensorEntityDescription(
        key="rx_bytes",
        name="RX Bytes",
        device_class=SensorDeviceClass.DATA_SIZE,
        native_unit_of_measurement=UnitOfInformation.BYTES,
        state_class=SensorStateClass.TOTAL_INCREASING,
        icon="mdi:download",
    ),
    SensorEntityDescription(
        key="tx_bytes",
        name="TX Bytes",
        device_class=SensorDeviceClass.DATA_SIZE,
        native_unit_of_measurement=UnitOfInformation.BYTES,
        state_class=SensorStateClass.TOTAL_INCREASING,
        icon="mdi:upload",
    ),
    SensorEntityDescription(
        key="rx_packets",
        name="RX Packets",
        state_class=SensorStateClass.TOTAL_INCREASING,
        icon="mdi:download",
    ),
    SensorEntityDescription(
        key="tx_packets",
        name="TX Packets",
        state_class=SensorStateClass.TOTAL_INCREASING,
        icon="mdi:upload",
    ),
    SensorEntityDescription(
        key="rx_errors",
        name="RX Errors",
        state_class=SensorStateClass.TOTAL_INCREASING,
        icon="mdi:alert-circle",
    ),
    SensorEntityDescription(
        key="tx_errors",
        name="TX Errors",
        state_class=SensorStateClass.TOTAL_INCREASING,
        icon="mdi:alert-circle",
    ),
    SensorEntityDescription(
        key="rx_dropped",
        name="RX Dropped",
        state_class=SensorStateClass.TOTAL_INCREASING,
        icon="mdi:alert-circle",
    ),
    SensorEntityDescription(
        key="tx_dropped",
        name="TX Dropped",
        state_class=SensorStateClass.TOTAL_INCREASING,
        icon="mdi:alert-circle",
    ),
]


# Network interface sensors will use the shared data manager
# No need for a separate coordinator


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the OpenWrt network interface sensors."""
    try:
        # Get the shared data coordinator
        coordinator: SharedDataUpdateCoordinator = hass.data[DOMAIN][config_entry.entry_id]["coordinator"]
    except Exception as exc:
        _LOGGER.error("Error accessing coordinator for eth_sensor: %s", exc)
        return

    try:
        # Request network devices data
        coordinator.data_manager.request_data_types(["network_devices"])
    except Exception as exc:
        _LOGGER.error("Error requesting network_devices data in eth_sensor: %s", exc)
        return

    entities = []

    try:
        # Get the network devices from coordinator data
        if coordinator.data and "network_devices" in coordinator.data:
            network_devices = coordinator.data["network_devices"]
            for device_name, device_data in network_devices.items():
                # Skip loopback and virtual interfaces for cleaner display
                if device_name in ["lo"] or device_data.get("external", False):
                    continue

                # Create sensors for each network interface
                for description in SENSOR_DESCRIPTIONS:
                    try:
                        entities.append(
                            NetworkInterfaceSensor(
                                coordinator,
                                description,
                                device_name,
                                device_data,
                            )
                        )
                    except Exception as exc:
                        _LOGGER.error(
                            "Error creating NetworkInterfaceSensor for %s (%s): %s",
                            device_name, description.key, exc
                        )
    except Exception as exc:
        _LOGGER.error("Error loading network devices for eth_sensor: %s", exc)
        return

    try:
        async_add_entities(entities)
    except Exception as exc:
        _LOGGER.error("Error adding entities in eth_sensor: %s", exc)

    # Return the coordinator for the main sensor setup
    return coordinator


class NetworkInterfaceSensor(CoordinatorEntity, SensorEntity):
    """Representation of a OpenWrt network interface sensor."""

    def __init__(
        self,
        coordinator: SharedDataUpdateCoordinator,
        description: SensorEntityDescription,
        device_name: str,
        device_data: dict[str, Any],
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator)
        self.entity_description = description
        self.device_name = device_name
        self.device_data = device_data

        # Defensive: try to get host, fallback to "unknown"
        try:
            host = coordinator.data_manager.entry.data[CONF_HOST]
        except Exception as exc:
            _LOGGER.error("Error getting CONF_HOST for device %s: %s", device_name, exc)
            host = "unknown"

        # Set unique ID
        self._attr_unique_id = f"{host}_{device_name}_{description.key}"

        # Set device info
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, f"{host}_{device_name}")},
            name=f"Network Interface {device_name}",
            manufacturer="OpenWrt",
            model="Router",
            sw_version="OpenWrt",
        )

    @property
    def name(self) -> str:
        """Return the name of the sensor."""
        return f"{self.device_name} {self.entity_description.name}"

    @property
    def native_value(self) -> Any:
        """Return the state of the sensor."""
        try:
            if not self.coordinator.data or "network_devices" not in self.coordinator.data:
                return None

            network_devices = self.coordinator.data["network_devices"]
            device_data = network_devices.get(self.device_name, {})

            if self.entity_description.key == "status":
                return "up" if device_data.get("up", False) else "down"
            elif self.entity_description.key == "speed":
                return device_data.get("speed", "unknown")
            elif self.entity_description.key == "carrier":
                return "connected" if device_data.get("carrier", False) else "disconnected"
            elif self.entity_description.key == "mtu":
                return device_data.get("mtu", 0)
            elif self.entity_description.key in [
                "rx_bytes", "tx_bytes", "rx_packets", "tx_packets",
                "rx_errors", "tx_errors", "rx_dropped", "tx_dropped"
            ]:
                stats = device_data.get("statistics", {})
                return stats.get(self.entity_description.key, 0)

            return None
        except Exception as exc:
            _LOGGER.error(
                "Error getting native_value for %s (%s): %s",
                self.device_name, self.entity_description.key, exc
            )
            return None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return the state attributes."""
        try:
            if not self.coordinator.data or "network_devices" not in self.coordinator.data:
                return {}

            network_devices = self.coordinator.data["network_devices"]
            device_data = network_devices.get(self.device_name, {})
            stats = device_data.get("statistics", {})

            attrs = {
                "device_type": device_data.get("type", "unknown"),
                "mac_address": device_data.get("macaddr", "unknown"),
                "present": device_data.get("present", False),
                "external": device_data.get("external", False),
                "devtype": device_data.get("devtype", "unknown"),
                "txqueuelen": device_data.get("txqueuelen", 0),
                "ipv6": device_data.get("ipv6", False),
                "multicast": device_data.get("multicast", False),
            }

            # Add flow control info if available
            if "flow-control" in device_data:
                flow_control = device_data["flow-control"]
                attrs["flow_control_autoneg"] = flow_control.get("autoneg", False)
                attrs["flow_control_negotiated"] = flow_control.get("negotiated", [])

            # Add bridge info if it's a bridge
            if device_data.get("type") == "bridge":
                bridge_attrs = device_data.get("bridge-attributes", {})
                attrs.update({
                    "bridge_stp": bridge_attrs.get("stp", False),
                    "bridge_priority": bridge_attrs.get("priority", 0),
                    "bridge_ageing_time": bridge_attrs.get("ageing_time", 0),
                    "bridge_members": device_data.get("bridge-members", []),
                })

            # Add link info if available
            if "link-advertising" in device_data:
                attrs["link_advertising"] = device_data.get("link-advertising", [])
                attrs["link_partner_advertising"] = device_data.get("link-partner-advertising", [])
                attrs["link_supported"] = device_data.get("link-supported", [])
                attrs["autoneg"] = device_data.get("autoneg", False)

            return attrs
        except Exception as exc:
            _LOGGER.error(
                "Error getting extra_state_attributes for %s: %s",
                self.device_name, exc
            )
            return {}
