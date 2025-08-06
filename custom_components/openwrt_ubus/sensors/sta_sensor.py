
"""Support for OpenWrt router device statistics sensors."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
import logging
import time
from typing import Any, Callable

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    CONF_HOST,
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
    CONF_STA_SENSOR_TIMEOUT,
    DEFAULT_STA_SENSOR_TIMEOUT,
)
from ..shared_data_manager import SharedDataUpdateCoordinator

_LOGGER = logging.getLogger(__name__)

SCAN_INTERVAL = timedelta(seconds=30)  # Device stats change more frequently


@dataclass
class SensorValueMapping:
    """Data class for sensor value mapping configuration."""
    data_keys: list[str | tuple]
    convert_function: Callable
    default_value: Any = None


@dataclass  
class AttributeMapping:
    """Data class for extra attribute mapping configuration."""
    data_keys: list[str | tuple]
    convert_function: Callable


def _get_simple_value(device_data: dict, keys: list[str], sensor_instance=None) -> Any:
    """Get simple value from device data."""
    for key in keys:
        if key in device_data:
            return device_data[key]
    return None


def _get_nested_value(ap_data: dict, keys: list[tuple]) -> Any:
    """Get value from nested dictionary using tuple keys for nested access."""
    def get_value(data: dict, key_path: tuple) -> Any:
        """Recursively get value from nested dictionary using tuple as path."""
        if not isinstance(data, dict) or not key_path:
            return None
        
        current_key = key_path[0]
        if current_key not in data:
            return None
        
        # If this is the last key in the path, return the value
        if len(key_path) == 1:
            return data.get(current_key)
        
        # Otherwise, recursively navigate deeper
        return get_value(data[current_key], key_path[1:])

    for nested_key in keys:
        value = get_value(ap_data, nested_key)
        if value is not None:
            return value
    return None


def _convert_rate_to_mbps(device_data: dict, keys: list[str], sensor_instance=None) -> float | None:
    """Convert rate from kbps to Mbps."""
    for nested_key in keys:
        if isinstance(nested_key, tuple) and len(nested_key) >= 2:
            parent_key = nested_key[0]
            child_key = nested_key[1]
            rate_kbps = device_data.get(parent_key, {}).get(child_key)
            if rate_kbps is not None:
                return round(rate_kbps / 1000, 2)
    return None


def _convert_bytes_to_mb(device_data: dict, keys: list[str], sensor_instance=None) -> float | None:
    """Convert bytes to megabytes."""
    for nested_key in keys:
        if isinstance(nested_key, tuple) and len(nested_key) >= 2:
            parent_key = nested_key[0]
            child_key = nested_key[1]
            bytes_value = device_data.get(parent_key, {}).get(child_key)
            if bytes_value is not None:
                return round(bytes_value / (1024 * 1024), 2)
    return None


def _calculate_speed(device_data: dict, keys: list[str], sensor_instance=None) -> float | None:
    """Calculate speed based on bytes."""
    data_bytes = _get_nested_value(device_data, keys)
    rx = False
    #if key contains rx/tx
    if data_bytes is None:
        return None
    if keys[0][0].startswith("rx"):
        rx = True
    # rx/tx
    if sensor_instance:
        current_time = time.time()
        if sensor_instance._previous_update_time is None:
            sensor_instance._previous_update_time = current_time
            if rx:
                sensor_instance._previous_rx_bytes  = data_bytes
            else:
                sensor_instance._previous_tx_bytes = data_bytes
            return None
        elapsed_time = current_time - sensor_instance._previous_update_time
        sensor_instance._previous_update_time = current_time
        if rx:
            speed = (data_bytes - sensor_instance._previous_rx_bytes) / elapsed_time
            sensor_instance._previous_rx_bytes = data_bytes
        else:
            speed = (data_bytes - sensor_instance._previous_tx_bytes) / elapsed_time
            sensor_instance._previous_tx_bytes = data_bytes
        # Convert to Kbps
        if speed < 0:
            speed = 0
        return speed * 8 / 1024



def _get_online_status(device_data: dict, keys: list[str], sensor_instance=None) -> bool:
    """Return True if device is online (exists in device_statistics)."""
    return True  # If device_data exists, device is online


def _has_required_data(device_data: dict, required_keys: list[str]) -> bool:
    """Check if device data contains required keys."""
    if not required_keys:  # For sensors like "online" that don't need specific keys
        return True
    
    for key in required_keys:
        if isinstance(key, tuple) and len(key) >= 2:
            # For nested keys like ("rx", "rate")
            parent_key = key[0]
            child_key = key[1]
            if parent_key in device_data and child_key in device_data.get(parent_key, {}):
                return True
        elif isinstance(key, str):
            # For simple keys
            if key in device_data:
                return True
    
    return False


# Sensor value mapping: sensor_key -> SensorValueMapping
SENSOR_VALUE_MAPPING = {
    "signal": SensorValueMapping(["signal"], _get_simple_value, None),
    "signal_avg": SensorValueMapping(["signal_avg"], _get_simple_value, None),
    "noise": SensorValueMapping(["noise"], _get_simple_value, None),
    "connected_time": SensorValueMapping(["connected_time"], _get_simple_value, None),
    "rx_rate": SensorValueMapping([("rx", "rate")], _convert_rate_to_mbps, 0),
    "tx_rate": SensorValueMapping([("tx", "rate")], _convert_rate_to_mbps, 0),
    "rx_packets": SensorValueMapping([("rx", "packets")], _get_nested_value, 0),
    "tx_packets": SensorValueMapping([("tx", "packets")], _get_nested_value, 0),
    "rx_bytes": SensorValueMapping([("rx", "bytes")], _convert_bytes_to_mb, 0),
    "tx_bytes": SensorValueMapping([("tx", "bytes")], _convert_bytes_to_mb, 0),
    "rx_speed": SensorValueMapping([("rx", "bytes")], _calculate_speed, 0),
    "tx_speed": SensorValueMapping([("tx", "bytes")], _calculate_speed, 0),
    "online": SensorValueMapping([], _get_online_status, False),
}

# Extra attributes mapping: attr_key -> AttributeMapping
EXTRA_ATTRIBUTES_MAPPING = {
    "authorized": AttributeMapping(["authorized"], _get_simple_value),
    "authenticated": AttributeMapping(["authenticated"], _get_simple_value),
    "inactive_time": AttributeMapping(["inactive"], _get_simple_value),
    "rx_ht": AttributeMapping([("rx", "ht")], _get_nested_value),
    "rx_vht": AttributeMapping([("rx", "vht")], _get_nested_value),
    "rx_he": AttributeMapping([("rx", "he")], _get_nested_value),
    "rx_mhz": AttributeMapping([("rx", "mhz")], _get_nested_value),
    "rx_mcs": AttributeMapping([("rx", "mcs")], _get_nested_value),
    "rx_40mhz": AttributeMapping([("rx", "40mhz")], _get_nested_value),
    "rx_short_gi": AttributeMapping([("rx", "short_gi")], _get_nested_value),
    "tx_ht": AttributeMapping([("tx", "ht")], _get_nested_value),
    "tx_vht": AttributeMapping([("tx", "vht")], _get_nested_value),
    "tx_he": AttributeMapping([("tx", "he")], _get_nested_value),
    "tx_mhz": AttributeMapping([("tx", "mhz")], _get_nested_value),
    "tx_mcs": AttributeMapping([("tx", "mcs")], _get_nested_value),
    "tx_40mhz": AttributeMapping([("tx", "40mhz")], _get_nested_value),
    "tx_short_gi": AttributeMapping([("tx", "short_gi")], _get_nested_value),
    "tx_failed": AttributeMapping([("tx", "failed")], _get_nested_value),
    "tx_retries": AttributeMapping([("tx", "retries")], _get_nested_value),
}
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
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:download",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="tx_packets",
        name="TX Packets",
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:upload",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="rx_bytes",
        name="RX Data",
        device_class=SensorDeviceClass.DATA_SIZE,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfInformation.MEGABYTES,
        icon="mdi:download",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="tx_bytes",
        name="TX Data",
        device_class=SensorDeviceClass.DATA_SIZE,
        state_class=SensorStateClass.MEASUREMENT,
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
        current_devices = set(device_stats.keys())
        
        # Handle new devices
        new_devices = current_devices - coordinator.known_devices
        if new_devices:
            _LOGGER.info("Found %d new STA devices: %s", len(new_devices), new_devices)
            
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
                            "STA sensor entity %s already exists with entity_id %s, skipping creation",
                            unique_id, existing_entity_id
                        )
                        continue
                    
                    # Check if sensor has required data
                    device_data = device_stats.get(mac_address, {})
                    mapping = SENSOR_VALUE_MAPPING.get(description.key)
                    if mapping and _has_required_data(device_data, mapping.data_keys):
                        device_sensors_to_add.append(description)
                
                # Only add sensors that don't already exist and have data
                if device_sensors_to_add:
                    new_entities.extend([
                        DeviceStatisticsSensor(coordinator, description, mac_address)
                        for description in device_sensors_to_add
                    ])
                
                coordinator.known_devices.add(mac_address)
            
            # Add new entities only if there are any
            if new_entities:
                async_add_entities(new_entities, True)
                _LOGGER.info("Created %d STA sensor entities for %d new devices", 
                           len(new_entities), len(new_devices))
            else:
                _LOGGER.debug("No new STA sensor entities to create for %d devices (all already exist or no data)", 
                            len(new_devices))
        
        # Handle removed devices - remove entities for devices that no longer exist
        removed_devices = coordinator.known_devices - current_devices
        if removed_devices:
            _LOGGER.info("Removing %d STA devices: %s", len(removed_devices), removed_devices)
            entity_registry = er.async_get(hass)
            
            for mac_address in removed_devices:
                for description in SENSOR_DESCRIPTIONS:
                    unique_id = f"{entry.data[CONF_HOST]}_sensor_{mac_address}_{description.key}"
                    entity_id = entity_registry.async_get_entity_id("sensor", DOMAIN, unique_id)
                    if entity_id:
                        entity_registry.async_remove(entity_id)
                        _LOGGER.debug("Removed STA sensor entity %s", entity_id)
                
                coordinator.known_devices.discard(mac_address)
        
        # Handle entities for existing devices that no longer have required data
        entity_registry = er.async_get(hass)
        for mac_address in current_devices & coordinator.known_devices:
            device_data = device_stats[mac_address]
            for description in SENSOR_DESCRIPTIONS:
                unique_id = f"{entry.data[CONF_HOST]}_sensor_{mac_address}_{description.key}"
                entity_id = entity_registry.async_get_entity_id("sensor", DOMAIN, unique_id)
                
                if entity_id:
                    # Check if entity should be removed due to missing data
                    mapping = SENSOR_VALUE_MAPPING.get(description.key)
                    if mapping and not _has_required_data(device_data, mapping.data_keys):
                        entity_registry.async_remove(entity_id)
                        _LOGGER.debug("Removed STA sensor entity %s due to missing data", entity_id)
    
    # Perform first refresh
    await coordinator.async_config_entry_first_refresh()
    
    # Add initial sensors for any devices already discovered
    initial_entities = []
    if coordinator.data and coordinator.data.get("device_statistics"):
        device_stats = coordinator.data["device_statistics"]
        for mac_address in device_stats:
            coordinator.known_devices.add(mac_address)
            device_data = device_stats[mac_address]
            
            # Only add sensors that have the required data
            for description in SENSOR_DESCRIPTIONS:
                mapping = SENSOR_VALUE_MAPPING.get(description.key)
                if mapping and _has_required_data(device_data, mapping.data_keys):
                    initial_entities.append(
                        DeviceStatisticsSensor(coordinator, description, mac_address)
                    )
    
    # Add initial entities if any
    if initial_entities:
        async_add_entities(initial_entities, True)
        _LOGGER.info("Set up %d initial STA statistics sensors", len(initial_entities))
    
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
        if not (
            self.coordinator.last_update_success
            and self.coordinator.data is not None
            and "device_statistics" in self.coordinator.data
            and self.mac_address in self.coordinator.data["device_statistics"]
        ):
            return False
        
        # Check if sensor has the required data to show a value
        device_data = self.coordinator.data["device_statistics"][self.mac_address]
        mapping = SENSOR_VALUE_MAPPING.get(self.entity_description.key)
        if not mapping:
            return False
        
        # Return False if none of the required keys exist
        return _has_required_data(device_data, mapping.data_keys)

    @property
    def native_value(self) -> str | int | float | bool | None:
        """Return the state of the sensor."""
        if not self.coordinator.data or "device_statistics" not in self.coordinator.data:
            return None
            
        device_stats = self.coordinator.data["device_statistics"]
        if self.mac_address not in device_stats:
            return None

        device_data = device_stats[self.mac_address]
        key = self.entity_description.key

        # Get value mapping for this sensor
        mapping = SENSOR_VALUE_MAPPING.get(key)
        if not mapping:
            return None
        
        # Check if any required keys exist in data
        if not _has_required_data(device_data, mapping.data_keys):
            return mapping.default_value

        try:
            # For speed calculations, pass the sensor instance
            if key in ["rx_speed", "tx_speed"]:
                return mapping.convert_function(device_data, mapping.data_keys, self)
            else:
                return mapping.convert_function(device_data, mapping.data_keys)
        except (KeyError, TypeError, ValueError) as exc:
            _LOGGER.debug("Error getting %s for %s: %s", key, self.mac_address, exc)
            return mapping.default_value

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

        # Add extra attributes using mapping
        for attr_key, mapping in EXTRA_ATTRIBUTES_MAPPING.items():
            try:
                # Check if required data exists
                if _has_required_data(device_data, mapping.data_keys):
                    value = mapping.convert_function(device_data, mapping.data_keys)
                    if value is not None:  # Only add attribute if value is not None
                        attributes[attr_key] = value
            except (KeyError, TypeError, ValueError) as exc:
                _LOGGER.debug("Error getting attribute %s for %s: %s", attr_key, self.mac_address, exc)
                continue

        return attributes
