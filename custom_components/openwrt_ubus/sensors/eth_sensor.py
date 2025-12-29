"""Support for OpenWrt router network interface sensors."""

from __future__ import annotations

import logging
from datetime import timedelta
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
    UnitOfInformation,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity,
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
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> SharedDataUpdateCoordinator:
    """Set up the OpenWrt network interface sensors."""

    # Get shared data manager
    data_manager_key = f"data_manager_{entry.entry_id}"
    data_manager = hass.data[DOMAIN][data_manager_key]

    # Get timeout from configuration (priority: options > data > default)
    timeout = entry.options.get(
        CONF_SYSTEM_SENSOR_TIMEOUT,
        entry.data.get(CONF_SYSTEM_SENSOR_TIMEOUT, DEFAULT_SYSTEM_SENSOR_TIMEOUT),
    )
    scan_interval = timedelta(seconds=timeout)

    # Create coordinator using shared data manager
    coordinator = SharedDataUpdateCoordinator(
        hass,
        data_manager,
        ["network_devices"],  # Data types this coordinator needs
        f"{DOMAIN}_eth_{entry.data[CONF_HOST]}",
        scan_interval,
    )

    # Fetch initial data
    await coordinator.async_config_entry_first_refresh()

    host = coordinator.data_manager.entry.data[CONF_HOST]
    device_registry = dr.async_get(hass)
    device_registry.async_get_or_create(
        config_entry_id=entry.entry_id,
        identifiers={(DOMAIN, f"{host}_eth")},
        name=f"{host} Network Interfaces",
        manufacturer="OpenWrt",
        via_device=(DOMAIN, host),  # Link to main router device
    )

    entities = []

    # Get the network devices from coordinator data
    if coordinator.data and "network_devices" in coordinator.data:
        network_devices = coordinator.data["network_devices"]

        # Validate network devices data structure
        if not isinstance(network_devices, dict):
            _LOGGER.error("Invalid network devices data format: %s", type(network_devices))
            network_devices = {}

        _LOGGER.info("Found %d network devices", len(network_devices))
        _LOGGER.debug("Network devices data: %s", network_devices)

        for device_name, device_data in network_devices.items():
            # Skip invalid entries
            if not isinstance(device_data, dict):
                _LOGGER.debug("Skipping invalid device data for %s", device_name)
                continue

            # Skip loopback and external interfaces (like phy0-ap0, phy1-ap0)
            if device_name in ["lo"] or device_data.get("external", False):
                _LOGGER.debug("Skipping device %s (loopback or external)", device_name)
                continue

            _LOGGER.debug("Creating sensors for network device: %s", device_name)

            # Create sensors for each network interface
            for description in SENSOR_DESCRIPTIONS:
                entities.append(
                    NetworkInterfaceSensor(
                        coordinator,
                        description,
                        device_name,
                    )
                )
    else:
        _LOGGER.warning("No network devices found in coordinator data")

    async_add_entities(entities, True)
    _LOGGER.info("Created %d network interface sensor entities", len(entities))

    # Return the coordinator for the main sensor setup
    return coordinator


class NetworkInterfaceSensor(CoordinatorEntity, SensorEntity):
    """Representation of a OpenWrt network interface sensor."""

    def __init__(
        self,
        coordinator: SharedDataUpdateCoordinator,
        description: SensorEntityDescription,
        device_name: str,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator)
        self.entity_description = description
        self.device_name = device_name
        self._host = coordinator.data_manager.entry.data[CONF_HOST]

        # Set unique ID
        self._attr_unique_id = f"{self._host}_{device_name}_{description.key}"
        self._attr_has_entity_name = True

        # Set device info - create a device for each network interface
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, f"{self._host}_{device_name}")},
            name=f"{device_name}",
            manufacturer="OpenWrt",
            model=self._get_device_type(),
            via_device=(DOMAIN, f"{self._host}_eth"),  # Link to main router device
        )

    def _get_device_type(self) -> str:
        """Get device type from coordinator data."""
        if not self.coordinator.data or "network_devices" not in self.coordinator.data:
            return "Network Device"

        network_devices = self.coordinator.data["network_devices"]
        device_data = network_devices.get(self.device_name, {})

        devtype = device_data.get("devtype", "")
        if devtype == "bridge":
            return "Bridge"
        elif devtype == "dsa":
            return "DSA Port"
        elif devtype == "ethernet":
            return "Ethernet"
        elif devtype == "none":
            device_type = device_data.get("type", "Network Device")
            if "pppoe" in self.device_name.lower():
                return "PPPoE"
            elif "tun" in self.device_name.lower():
                return "Tunnel"
            return device_type
        else:
            return device_data.get("type", "Network Device")

    @property
    def native_value(self) -> Any:
        """Return the state of the sensor."""
        if not self.coordinator.data or "network_devices" not in self.coordinator.data:
            return None

        network_devices = self.coordinator.data["network_devices"]
        device_data = network_devices.get(self.device_name, {})

        if self.entity_description.key == "status":
            return "up" if device_data.get("up", False) else "down"
        elif self.entity_description.key == "speed":
            speed = device_data.get("speed", "unknown")
            if isinstance(speed, str) and speed.endswith("F"):
                return speed[:-1]  # Remove 'F' suffix (e.g. "1000F" -> "1000")
            return speed
        elif self.entity_description.key == "carrier":
            return "connected" if device_data.get("carrier", False) else "disconnected"
        elif self.entity_description.key == "mtu":
            return device_data.get("mtu", 0)
        elif self.entity_description.key in [
            "rx_bytes",
            "tx_bytes",
            "rx_packets",
            "tx_packets",
            "rx_errors",
            "tx_errors",
            "rx_dropped",
            "tx_dropped",
        ]:
            stats = device_data.get("statistics", {})
            return stats.get(self.entity_description.key, 0)

        return None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return the state attributes."""
        if not self.coordinator.data or "network_devices" not in self.coordinator.data:
            return {}

        network_devices = self.coordinator.data["network_devices"]
        device_data = network_devices.get(self.device_name, {})

        attrs = {
            "device_type": device_data.get("type", "unknown"),
            "mac_address": device_data.get("macaddr", "unknown"),
            "present": device_data.get("present", False),
            "external": device_data.get("external", False),
            "devtype": device_data.get("devtype", "unknown"),
            "txqueuelen": device_data.get("txqueuelen", 0),
            "ipv6": device_data.get("ipv6", False),
            "multicast": device_data.get("multicast", False),
            "autoneg": device_data.get("autoneg", False),
        }

        # Add flow control info if available
        if "flow-control" in device_data:
            flow_control = device_data["flow-control"]
            attrs.update(
                {
                    "flow_control_autoneg": flow_control.get("autoneg", False),
                    "flow_control_supported": flow_control.get("supported", []),
                    "flow_control_advertising": flow_control.get("link-advertising", []),
                    "flow_control_partner_advertising": flow_control.get("link-partner-advertising", []),
                    "flow_control_negotiated": flow_control.get("negotiated", []),
                }
            )

        # Add bridge info if it's a bridge
        if device_data.get("type") == "bridge":
            bridge_attrs = device_data.get("bridge-attributes", {})
            attrs.update(
                {
                    "bridge_stp": bridge_attrs.get("stp", False),
                    "bridge_priority": bridge_attrs.get("priority", 0),
                    "bridge_ageing_time": bridge_attrs.get("ageing_time", 0),
                    "bridge_hello_time": bridge_attrs.get("hello_time", 1),
                    "bridge_max_age": bridge_attrs.get("max_age", 10),
                    "bridge_forward_delay": bridge_attrs.get("forward_delay", 8),
                    "bridge_igmp_snooping": bridge_attrs.get("igmp_snooping", False),
                    "bridge_members": device_data.get("bridge-members", []),
                }
            )

        # Add link info if available
        if "link-advertising" in device_data:
            attrs.update(
                {
                    "link_advertising": device_data.get("link-advertising", []),
                    "link_partner_advertising": device_data.get("link-partner-advertising", []),
                    "link_supported": device_data.get("link-supported", []),
                }
            )

        # Add conduit for DSA ports
        if "conduit" in device_data:
            attrs["conduit"] = device_data["conduit"]

        return attrs
