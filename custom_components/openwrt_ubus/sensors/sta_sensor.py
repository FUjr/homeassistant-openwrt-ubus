
"""Support for OpenWrt router device statistics sensors."""

from __future__ import annotations

from datetime import timedelta
import logging
import re
import time
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
    UnitOfTime,
    UnitOfInformation,
    UnitOfDataRate
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity,
)

from ..const import (
    DOMAIN,
    CONF_WIRELESS_SOFTWARE,
    CONF_STA_SENSOR_TIMEOUT,
    DEFAULT_WIRELESS_SOFTWARE,
    DEFAULT_STA_SENSOR_TIMEOUT,
)
from ..shared_data_manager import SharedDataUpdateCoordinator

_LOGGER = logging.getLogger(__name__)

SCAN_INTERVAL = timedelta(seconds=30)  # Device stats change more frequently
# Device statistics sensor descriptions (per connected device)
SENSOR_DESCRIPTIONS = [
    SensorEntityDescription(
        key="signal",
        name="Signal Strength",
        device_class=SensorDeviceClass.SIGNAL_STRENGTH,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement="dBm",
        icon="mdi:signal",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="signal_avg",
        name="Average Signal Strength",
        device_class=SensorDeviceClass.SIGNAL_STRENGTH,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement="dBm",
        icon="mdi:signal",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="noise",
        name="Noise Level",
        device_class=SensorDeviceClass.SIGNAL_STRENGTH,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement="dBm",
        icon="mdi:signal-variant",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="connected_time",
        name="Connected Time",
        device_class=SensorDeviceClass.DURATION,
        state_class=SensorStateClass.TOTAL_INCREASING,
        native_unit_of_measurement=UnitOfTime.SECONDS,
        suggested_unit_of_measurement=UnitOfTime.HOURS,
        icon="mdi:clock-outline",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="rx_rate",
        name="RX Rate",
        device_class=SensorDeviceClass.DATA_RATE,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfDataRate.MEGABITS_PER_SECOND,
        suggested_unit_of_measurement=UnitOfDataRate.MEGABITS_PER_SECOND,
        icon="mdi:download",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="tx_rate",
        name="TX Rate",
        device_class=SensorDeviceClass.DATA_RATE,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfDataRate.MEGABITS_PER_SECOND,
        suggested_unit_of_measurement=UnitOfDataRate.MEGABITS_PER_SECOND,
        icon="mdi:upload",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="rx_packets",
        name="RX Packets",
        state_class=SensorStateClass.TOTAL_INCREASING,
        icon="mdi:download",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="tx_packets",
        name="TX Packets",
        state_class=SensorStateClass.TOTAL_INCREASING,
        icon="mdi:upload",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="rx_bytes",
        name="RX Data",
        device_class=SensorDeviceClass.DATA_SIZE,
        state_class=SensorStateClass.TOTAL_INCREASING,
        native_unit_of_measurement=UnitOfInformation.MEGABYTES,
        icon="mdi:download",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="tx_bytes",
        name="TX Data",
        device_class=SensorDeviceClass.DATA_SIZE,
        state_class=SensorStateClass.TOTAL_INCREASING,
        native_unit_of_measurement=UnitOfInformation.MEGABYTES,
        icon="mdi:upload",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="tx_speed",
        name="TX Speed",
        device_class=SensorDeviceClass.DATA_RATE,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfDataRate.KILOBITS_PER_SECOND,
        suggested_unit_of_measurement=UnitOfDataRate.MEGABITS_PER_SECOND,
        icon="mdi:upload",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="rx_speed",
        name="RX Speed",
        device_class=SensorDeviceClass.DATA_RATE,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfDataRate.KILOBITS_PER_SECOND,
        suggested_unit_of_measurement=UnitOfDataRate.MEGABITS_PER_SECOND,
        icon="mdi:download",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="online",
        name="Online",
        icon="mdi:wifi",
        entity_category=None,
    ),
]


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> SharedDataUpdateCoordinator:
    """Set up the device statistics sensors from a config entry."""
    
    # Get shared data manager
    data_manager_key = f"data_manager_{entry.entry_id}"
    data_manager = hass.data[DOMAIN][data_manager_key]
    
    # Get timeout from configuration (priority: options > data > default)
    timeout = entry.options.get(
        CONF_STA_SENSOR_TIMEOUT,
        entry.data.get(CONF_STA_SENSOR_TIMEOUT, DEFAULT_STA_SENSOR_TIMEOUT)
    )
    scan_interval = timedelta(seconds=timeout)
    
    # Create coordinator using shared data manager
    coordinator = SharedDataUpdateCoordinator(
        hass,
        data_manager,
        ["device_statistics"],  # Data types this coordinator needs
        f"{DOMAIN}_devices_{entry.data[CONF_HOST]}",
        scan_interval,
    )
    
    # Store known devices for dynamic entity creation
    coordinator.known_devices = set()
    coordinator.async_add_entities = async_add_entities
    
    # Add update listener for dynamic device creation
    async def _handle_coordinator_update_async():
        """Handle coordinator updates and create new entities for new devices."""
        if not coordinator.data or "device_statistics" not in coordinator.data:
            return
            
        device_stats = coordinator.data["device_statistics"]
        new_devices = set(device_stats.keys()) - coordinator.known_devices
        
        if new_devices:
            _LOGGER.info("Found %d new devices for statistics: %s", len(new_devices), new_devices)
            
            # Get entity registry to check for existing entities
            entity_registry = er.async_get(hass)
            
            new_entities = []
            for mac_address in new_devices:
                # Check each sensor type for this device
                device_sensors_to_add = []
                for description in SENSOR_DESCRIPTIONS:
                    unique_id = f"{entry.data[CONF_HOST]}_sensor_{mac_address}_{description.key}"
                    existing_entity_id = entity_registry.async_get_entity_id(
                        "sensor", DOMAIN, unique_id
                    )
                    
                    if existing_entity_id:
                        _LOGGER.debug(
                            "Device sensor entity %s already exists with entity_id %s, skipping creation",
                            unique_id, existing_entity_id
                        )
                        continue
                    
                    device_sensors_to_add.append(description)
                
                # Only add sensors that don't already exist
                if device_sensors_to_add:
                    new_entities.extend([
                        DeviceStatisticsSensor(coordinator, description, mac_address)
                        for description in device_sensors_to_add
                    ])
                
                coordinator.known_devices.add(mac_address)
            
            # Add new entities only if there are any
            if new_entities:
                async_add_entities(new_entities, True)
                _LOGGER.info("Created %d sensor entities for %d new devices", 
                           len(new_entities), len(new_devices))
            else:
                _LOGGER.debug("No new sensor entities to create for %d devices (all already exist)", 
                            len(new_devices))
    
    # Perform first refresh
    await coordinator.async_config_entry_first_refresh()
    
    # Add initial sensors for any devices already discovered
    initial_entities = []
    if coordinator.data and coordinator.data.get("device_statistics"):
        device_stats = coordinator.data["device_statistics"]
        for mac_address in device_stats:
            coordinator.known_devices.add(mac_address)
            for description in SENSOR_DESCRIPTIONS:
                initial_entities.append(
                    DeviceStatisticsSensor(coordinator, description, mac_address)
                )
    
    # Add initial entities if any
    if initial_entities:
        async_add_entities(initial_entities, True)
        _LOGGER.info("Set up %d initial device statistics sensors", len(initial_entities))
    
    # Create sync wrapper for async coordinator update handler
    def _handle_coordinator_update():
        """Sync wrapper for async coordinator update handler."""
        hass.async_create_task(_handle_coordinator_update_async())
    
    # Register the update listener
    coordinator.async_add_listener(_handle_coordinator_update)
    
    # Return the coordinator for the main sensor module to track
    return coordinator


class DeviceStatisticsSensor(CoordinatorEntity, SensorEntity):
    """Representation of a device statistics sensor."""

    def __init__(
        self,
        coordinator: SharedDataUpdateCoordinator,
        description: SensorEntityDescription,
        mac_address: str,
    ) -> None:
        """Initialize the device statistics sensor."""
        super().__init__(coordinator)
        self.entity_description = description
        self.mac_address = mac_address
        self._host = coordinator.data_manager.entry.data[CONF_HOST]
        # Use sensor-specific unique ID pattern to avoid collision with device tracker
        self._attr_unique_id = f"{self._host}_sensor_{mac_address}_{description.key}"
        self._attr_has_entity_name = True
        
        # Store previous data for speed calculations
        self._previous_rx_bytes = None
        self._previous_tx_bytes = None
        self._previous_update_time = None

    @property
    def device_info(self) -> DeviceInfo:
        """Return device info to link this sensor to a device."""
        # Use the same device identifier as device tracker to link them together
        return DeviceInfo(
            identifiers={(DOMAIN, self.mac_address)},
            manufacturer="Unknown",
            model="WiFi Device",
            connections={("mac", self.mac_address)},
        )

    @property
    def available(self) -> bool:
        """Return True if entity is available."""
        return (
            self.coordinator.last_update_success
            and self.coordinator.data is not None
        )

    @property
    def native_value(self) -> str | int | float | bool | None:
        """Return the state of the sensor."""
        if not self.coordinator.data or "device_statistics" not in self.coordinator.data:
            # Return default values when no data available
            return self._get_default_value()
            
        device_stats = self.coordinator.data["device_statistics"]
        if self.mac_address not in device_stats:
            # Return default values when device not found
            return self._get_default_value()

        device_data = device_stats[self.mac_address]
        key = self.entity_description.key
        current_time = time.time()

        try:
            if key == "signal":
                value = device_data.get("signal")
                return value if value is not None else 0
            if key == "signal_avg":
                value = device_data.get("signal_avg")
                return value if value is not None else 0
            if key == "noise":
                value = device_data.get("noise")
                return value if value is not None else 0
            if key == "connected_time":
                value = device_data.get("connected_time")
                return value if value is not None else 0
            if key == "rx_rate":
                rx_data = device_data.get("rx", {})
                rate_kbps = rx_data.get("rate")
                # Convert kbps to Mbps
                return round(rate_kbps / 1000, 2) if rate_kbps else 0
            if key == "tx_rate":
                tx_data = device_data.get("tx", {})
                rate_kbps = tx_data.get("rate")
                # Convert kbps to Mbps
                return round(rate_kbps / 1000, 2) if rate_kbps else 0
            if key == "rx_packets":
                rx_data = device_data.get("rx", {})
                value = rx_data.get("packets")
                return value if value is not None else 0
            if key == "tx_packets":
                tx_data = device_data.get("tx", {})
                value = tx_data.get("packets")
                return value if value is not None else 0
            if key == "rx_bytes":
                rx_data = device_data.get("rx", {})
                bytes_value = rx_data.get("bytes")
                # Convert bytes to megabytes
                return round(bytes_value / (1024 * 1024), 2) if bytes_value else 0
            if key == "tx_bytes":
                tx_data = device_data.get("tx", {})
                bytes_value = tx_data.get("bytes")
                # Convert bytes to megabytes
                return round(bytes_value / (1024 * 1024), 2) if bytes_value else 0
            if key == "rx_speed":
                rx_data = device_data.get("rx", {})
                current_rx_bytes = rx_data.get("bytes")
                
                if current_rx_bytes is None:
                    return 0
                
                # Calculate speed based on previous data
                if (self._previous_rx_bytes is not None and 
                    self._previous_update_time is not None and 
                    current_time > self._previous_update_time):
                    
                    time_diff = current_time - self._previous_update_time
                    byte_diff = current_rx_bytes - self._previous_rx_bytes
                    
                    if time_diff > 0 and byte_diff >= 0:
                        # Convert bytes/second to Mbps (1 byte/s = 8 bits/s, 1 Mbps = 1,000,000 bits/s)
                        speed_kbps = (byte_diff * 8) / (time_diff * 1_000)
                        speed_kbps = round(speed_mbps, 3)
                    else:
                        speed_kbps = 0
                else:
                    speed_kbps = 0
                
                # Update previous values for next calculation
                self._previous_rx_bytes = current_rx_bytes
                self._previous_update_time = current_time
                
                return speed_kbps
                
            if key == "tx_speed":
                tx_data = device_data.get("tx", {})
                current_tx_bytes = tx_data.get("bytes")
                
                if current_tx_bytes is None:
                    return 0
                
                # Calculate speed based on previous data
                if (self._previous_tx_bytes is not None and 
                    self._previous_update_time is not None and 
                    current_time > self._previous_update_time):
                    
                    time_diff = current_time - self._previous_update_time
                    byte_diff = current_tx_bytes - self._previous_tx_bytes
                    
                    if time_diff > 0 and byte_diff >= 0:
                        # Convert bytes/second to Mbps (1 byte/s = 8 bits/s, 1 Mbps = 1,000,000 bits/s)
                        speed_kbps = (byte_diff * 8) / (time_diff * 1_000)
                        speed_lbps = round(speed_mbps, 3)
                    else:
                        speed_kbps = 0
                else:
                    speed_kbps = 0
                
                # Update previous values for next calculation
                self._previous_tx_bytes = current_tx_bytes
                # Update time only if it hasn't been updated in this cycle
                if self._previous_update_time != current_time:
                    self._previous_update_time = current_time
                
                return speed_kbps
            
            if key == "online":
                # Device is online if it exists in device_statistics
                return True

        except (KeyError, TypeError, ValueError) as exc:
            _LOGGER.debug("Error getting %s for %s: %s", key, self.mac_address, exc)
            return self._get_default_value()

        return self._get_default_value()

    def _get_default_value(self) -> str | int | float | bool:
        """Return default value based on entity description."""
        # For string-based or non-numeric sensors, return "-"
        # For numeric sensors, return 0
        # For boolean sensors, return False
        if self.entity_description.key in ["signal", "signal_avg", "noise"]:
            # Signal strength values are typically numeric but could be unavailable
            return 0
        elif self.entity_description.key in ["connected_time", "rx_packets", "tx_packets", 
                                           "rx_bytes", "tx_bytes", "rx_rate", "tx_rate",
                                           "rx_speed", "tx_speed"]:
            # These are all numeric values
            return 0
        elif self.entity_description.key == "online":
            # Online status - False when offline/no data
            return False
        else:
            # For any other unknown sensor types, default to "-"
            return "-"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return the state attributes."""
        if not self.coordinator.data or "device_statistics" not in self.coordinator.data:
            return {}
            
        device_stats = self.coordinator.data["device_statistics"]
        if self.mac_address not in device_stats:
            return {}

        device_data = device_stats[self.mac_address]

        attributes = {
            "mac_address": self.mac_address,
            "router_host": self._host,
            "last_update": self.coordinator.last_update_success,
        }

        # Add additional device info
        if "authorized" in device_data:
            attributes["authorized"] = device_data["authorized"]
        if "authenticated" in device_data:
            attributes["authenticated"] = device_data["authenticated"]
        if "inactive" in device_data:
            attributes["inactive_time"] = device_data["inactive"]

        # Add wireless info
        rx_data = device_data.get("rx", {})
        tx_data = device_data.get("tx", {})

        if rx_data:
            attributes.update({
                "rx_ht": rx_data.get("ht"),
                "rx_vht": rx_data.get("vht"),
                "rx_he": rx_data.get("he"),
                "rx_mhz": rx_data.get("mhz"),
                "rx_mcs": rx_data.get("mcs"),
                "rx_40mhz": rx_data.get("40mhz"),
                "rx_short_gi": rx_data.get("short_gi"),
            })

        if tx_data:
            attributes.update({
                "tx_ht": tx_data.get("ht"),
                "tx_vht": tx_data.get("vht"),
                "tx_he": tx_data.get("he"),
                "tx_mhz": tx_data.get("mhz"),
                "tx_mcs": tx_data.get("mcs"),
                "tx_40mhz": tx_data.get("40mhz"),
                "tx_short_gi": tx_data.get("short_gi"),
                "tx_failed": tx_data.get("failed"),
                "tx_retries": tx_data.get("retries"),
            })

        return attributes
