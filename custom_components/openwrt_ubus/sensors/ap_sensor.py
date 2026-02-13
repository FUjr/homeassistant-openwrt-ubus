"""Support for OpenWrt router access point sensors."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import timedelta
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
    UnitOfFrequency,
    UnitOfDataRate,
    PERCENTAGE,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr, entity_registry as er
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity,
)

from ..const import (
    DOMAIN,
    CONF_AP_SENSOR_TIMEOUT,
    DEFAULT_AP_SENSOR_TIMEOUT,
)
from ..shared_data_manager import SharedDataUpdateCoordinator

_LOGGER = logging.getLogger(__name__)

SCAN_INTERVAL = timedelta(seconds=60)  # AP info doesn't change frequently


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


def _convert_quality_percentage(ap_data: dict, keys: list[tuple]) -> float | None:
    """Convert quality to percentage."""
    for key_tuple in keys:
        quality = ap_data.get(key_tuple[0])
        quality_max = ap_data.get(key_tuple[1], 100)
        if quality:
            return round((quality / quality_max) * 100, 1)
    return None


def _get_simple_value(ap_data: dict, keys: list[str]) -> Any:
    """Get simple value from AP data."""
    return ap_data.get(keys[0]) if keys else None


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


def _has_required_data(ap_data: dict, required_keys: list[str | tuple]) -> bool:
    """Check if AP data contains required keys."""
    if not required_keys:  # For sensors that don't need specific keys
        return True

    for key in required_keys:
        if isinstance(key, tuple) and len(key) >= 2:
            # For nested keys like ("hardware", "name") or ("quality", "quality_max")
            if len(key) == 2:
                parent_key, child_key = key
                if parent_key in ap_data:
                    if isinstance(ap_data[parent_key], dict) and child_key in ap_data[parent_key]:
                        return True
                    elif parent_key == "quality" and child_key == "quality_max":
                        # Special case for quality percentage calculation
                        return ap_data.get("quality") is not None
            else:
                # For deeper nested keys, use the recursive function
                if _get_nested_value(ap_data, [key]) is not None:
                    return True
        elif isinstance(key, str):
            # For simple keys
            if key in ap_data:
                return True

    return False


# Sensor value mapping: sensor_key -> SensorValueMapping
SENSOR_VALUE_MAPPING = {
    "ssid": SensorValueMapping(["ssid"], _get_simple_value, None),
    "bssid": SensorValueMapping(["bssid"], _get_simple_value, None),
    "channel": SensorValueMapping(["channel"], _get_simple_value, None),
    "frequency": SensorValueMapping(["frequency"], _get_simple_value, None),
    "txpower": SensorValueMapping(["txpower"], _get_simple_value, None),
    "quality": SensorValueMapping([("quality", "quality_max")], _convert_quality_percentage, None),
    "signal": SensorValueMapping(["signal"], _get_simple_value, None),
    "noise": SensorValueMapping(["noise"], _get_simple_value, None),
    "bitrate": SensorValueMapping(["bitrate"], _get_simple_value, None),
    "mode": SensorValueMapping(["mode"], _get_simple_value, None),
    "hwmode": SensorValueMapping(["hwmode"], _get_simple_value, None),
    "htmode": SensorValueMapping(["htmode"], _get_simple_value, None),
    "country": SensorValueMapping(["country"], _get_simple_value, None),
}

# Extra attributes mapping: attr_key -> AttributeMapping
EXTRA_ATTRIBUTES_MAPPING = {
    "phy": AttributeMapping(["phy"], _get_simple_value),
    "center_channel": AttributeMapping(["center_chan1"], _get_simple_value),
    "frequency_offset": AttributeMapping(["frequency_offset"], _get_simple_value),
    "txpower_offset": AttributeMapping(["txpower_offset"], _get_simple_value),
    "hardware_name": AttributeMapping([("hardware", "name")], _get_nested_value),
    "hardware_id": AttributeMapping([("hardware", "id")], _get_nested_value),
    "supported_ht_modes": AttributeMapping(["htmodes"], _get_simple_value),
    "supported_hw_modes": AttributeMapping(["hwmodes"], _get_simple_value),
    "hw_modes_text": AttributeMapping(["hwmodes_text"], _get_simple_value),
    "encryption_enabled": AttributeMapping([("encryption", "enabled")], _get_nested_value),
    "wpa_versions": AttributeMapping([("encryption", "wpa")], _get_nested_value),
    "authentication": AttributeMapping([("encryption", "authentication")], _get_nested_value),
    "ciphers": AttributeMapping([("encryption", "ciphers")], _get_nested_value),
}

# AP sensor descriptions (per access point)
SENSOR_DESCRIPTIONS = [
    SensorEntityDescription(
        key="ssid",
        name="SSID",
        icon="mdi:wifi",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="bssid",
        name="BSSID",
        icon="mdi:access-point",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="channel",
        name="Channel",
        icon="mdi:wifi-marker",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="frequency",
        name="Frequency",
        device_class=SensorDeviceClass.FREQUENCY,
        native_unit_of_measurement=UnitOfFrequency.MEGAHERTZ,
        icon="mdi:sine-wave",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="txpower",
        name="TX Power",
        native_unit_of_measurement="dBm",
        icon="mdi:transmission-tower",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="quality",
        name="Signal Quality",
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=PERCENTAGE,
        icon="mdi:signal",
        entity_category=None,
    ),
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
        key="noise",
        name="Noise Level",
        device_class=SensorDeviceClass.SIGNAL_STRENGTH,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement="dBm",
        icon="mdi:signal-variant",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="bitrate",
        name="Bitrate",
        device_class=SensorDeviceClass.DATA_RATE,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfDataRate.KILOBITS_PER_SECOND,
        suggested_unit_of_measurement=UnitOfDataRate.MEGABITS_PER_SECOND,
        icon="mdi:speedometer",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="mode",
        name="Mode",
        icon="mdi:wifi-cog",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="hwmode",
        name="Hardware Mode",
        icon="mdi:chip",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="htmode",
        name="HT Mode",
        icon="mdi:cog-box",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="country",
        name="Country",
        icon="mdi:flag",
        entity_category=None,
    ),
]


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> SharedDataUpdateCoordinator:
    """Set up the access point sensors from a config entry."""

    # Get shared data manager
    data_manager_key = f"data_manager_{entry.entry_id}"
    data_manager = hass.data[DOMAIN][data_manager_key]

    # Get timeout from configuration (priority: options > data > default)
    timeout = entry.options.get(
        CONF_AP_SENSOR_TIMEOUT,
        entry.data.get(CONF_AP_SENSOR_TIMEOUT, DEFAULT_AP_SENSOR_TIMEOUT),
    )
    scan_interval = timedelta(seconds=timeout)

    # Create coordinator using shared data manager
    coordinator = SharedDataUpdateCoordinator(
        hass,
        data_manager,
        ["ap_info"],  # Data types this coordinator needs
        f"{DOMAIN}_ap_{entry.data[CONF_HOST]}",
        scan_interval,
    )

    # Store known devices for dynamic entity creation
    coordinator.known_devices = set()
    coordinator.async_add_entities = async_add_entities

    # Add update listener for dynamic device creation
    async def _handle_coordinator_update_async():
        """Handle coordinator updates and create new entities for new devices."""
        if not coordinator.data or "ap_info" not in coordinator.data:
            return

        ap_info_data = coordinator.data["ap_info"]
        current_devices = set(ap_info_data.keys())

        # Handle new devices
        new_devices = current_devices - coordinator.known_devices
        if new_devices:
            _LOGGER.info("Found %d new AP devices: %s", len(new_devices), new_devices)

            # Get entity registry to check for existing entities
            entity_registry = er.async_get(hass)

            new_entities = []
            for ap_device in new_devices:
                # Check each sensor type for this device
                device_sensors_to_add = []
                for description in SENSOR_DESCRIPTIONS:
                    unique_id = f"{entry.data[CONF_HOST]}_ap_{ap_device}_{description.key}"
                    existing_entity_id = entity_registry.async_get_entity_id("sensor", DOMAIN, unique_id)

                    if existing_entity_id:
                        _LOGGER.debug(
                            "AP sensor entity %s already exists with entity_id %s, skipping creation",
                            unique_id,
                            existing_entity_id,
                        )
                        continue

                    # Check if sensor has required data
                    ap_data = ap_info_data.get(ap_device, {})
                    mapping = SENSOR_VALUE_MAPPING.get(description.key)
                    if mapping and _has_required_data(ap_data, mapping.data_keys):
                        device_sensors_to_add.append(description)

                # Only add sensors that don't already exist and have data
                if device_sensors_to_add:
                    new_entities.extend(
                        [ApSensor(coordinator, description, ap_device) for description in device_sensors_to_add]
                    )

                coordinator.known_devices.add(ap_device)

            # Add new entities only if there are any
            if new_entities:
                async_add_entities(new_entities, True)
                _LOGGER.info(
                    "Created %d AP sensor entities for %d new devices",
                    len(new_entities),
                    len(new_devices),
                )
            else:
                _LOGGER.debug(
                    "No new AP sensor entities to create for %d devices (all already exist or no data)",
                    len(new_devices),
                )

        # Handle removed devices - remove entities for devices that no longer exist
        removed_devices = coordinator.known_devices - current_devices
        if removed_devices:
            _LOGGER.info("Removing %d AP devices: %s", len(removed_devices), removed_devices)
            entity_registry = er.async_get(hass)

            for ap_device in removed_devices:
                coordinator.known_devices.discard(ap_device)

    # Perform first refresh
    await coordinator.async_config_entry_first_refresh()

    host = coordinator.data_manager.entry.data[CONF_HOST]
    device_registry = dr.async_get(hass)
    device_registry.async_get_or_create(
        config_entry_id=entry.entry_id,
        identifiers={(DOMAIN, f"{host}_ap")},
        name=f"{host} Access Points",
        manufacturer="OpenWrt",
        via_device=(DOMAIN, host),  # Link to main router device
    )

    # Add initial sensors for any devices already discovered
    initial_entities = []
    if coordinator.data and coordinator.data.get("ap_info"):
        ap_info_data = coordinator.data["ap_info"]
        for ap_device in ap_info_data:
            coordinator.known_devices.add(ap_device)
            ap_data = ap_info_data[ap_device]

            # Only add sensors that have the required data
            for description in SENSOR_DESCRIPTIONS:
                mapping = SENSOR_VALUE_MAPPING.get(description.key)
                if mapping and _has_required_data(ap_data, mapping.data_keys):
                    initial_entities.append(ApSensor(coordinator, description, ap_device))

    # Add initial entities if any
    if initial_entities:
        async_add_entities(initial_entities, True)
        _LOGGER.info("Set up %d initial AP sensors", len(initial_entities))

    # Create sync wrapper for async coordinator update handler
    def _handle_coordinator_update():
        """Sync wrapper for async coordinator update handler."""
        hass.async_create_task(_handle_coordinator_update_async())

    # Register the update listener
    coordinator.async_add_listener(_handle_coordinator_update)

    # Return the coordinator for the main sensor module to track
    return coordinator


class ApSensor(CoordinatorEntity, SensorEntity):
    """Representation of an access point sensor."""

    def __init__(
        self,
        coordinator: SharedDataUpdateCoordinator,
        description: SensorEntityDescription,
        ap_device: str,
    ) -> None:
        """Initialize the access point sensor."""
        super().__init__(coordinator)
        self.entity_description = description
        self.ap_device = ap_device
        self._host = coordinator.data_manager.entry.data[CONF_HOST]
        # Use AP-specific unique ID pattern
        self._attr_unique_id = f"{self._host}_ap_{ap_device}_{description.key}"
        self._attr_has_entity_name = True

    @property
    def device_info(self) -> DeviceInfo:
        """Return device info to link this sensor to a device."""
        # Get device name from AP data if available
        device_name = f"AP {self.ap_device}"
        if (
            self.coordinator.data
            and "ap_info" in self.coordinator.data
            and self.ap_device in self.coordinator.data["ap_info"]
        ):
            ap_data = self.coordinator.data["ap_info"][self.ap_device]
            if "device_name" in ap_data:
                device_name = ap_data["device_name"]

        # Create a device for each AP interface
        return DeviceInfo(
            identifiers={(DOMAIN, f"{self._host}_ap_{self.ap_device}")},
            name=device_name,
            manufacturer="OpenWrt",
            model="Access Point",
            via_device=(DOMAIN, f"{self._host}_ap"),
        )

    @property
    def available(self) -> bool:
        """Return True if entity is available."""
        if not (
            self.coordinator.last_update_success
            and self.coordinator.data is not None
            and "ap_info" in self.coordinator.data
            and self.ap_device in self.coordinator.data["ap_info"]
        ):
            return False

        # Check if sensor has the required data to show a value
        ap_data = self.coordinator.data["ap_info"][self.ap_device]
        mapping = SENSOR_VALUE_MAPPING.get(self.entity_description.key)
        if not mapping:
            return False

        # Return False if none of the required keys exist
        return _has_required_data(ap_data, mapping.data_keys)

    @property
    def native_value(self) -> str | int | float | None:
        """Return the state of the sensor."""
        if not self.coordinator.data or "ap_info" not in self.coordinator.data:
            return None

        ap_info_data = self.coordinator.data["ap_info"]
        if self.ap_device not in ap_info_data:
            return None

        ap_data = ap_info_data[self.ap_device]
        key = self.entity_description.key

        # Get value mapping for this sensor
        mapping = SENSOR_VALUE_MAPPING.get(key)
        if not mapping:
            return None

        # Check if any required keys exist in data
        if not _has_required_data(ap_data, mapping.data_keys):
            return mapping.default_value

        try:
            return mapping.convert_function(ap_data, mapping.data_keys)
        except (KeyError, TypeError, ValueError) as exc:
            _LOGGER.debug("Error getting %s for %s: %s", key, self.ap_device, exc)
            return mapping.default_value

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return the state attributes."""
        if not self.coordinator.data or "ap_info" not in self.coordinator.data:
            return {}

        ap_info_data = self.coordinator.data["ap_info"]
        if self.ap_device not in ap_info_data:
            return {}

        ap_data = ap_info_data[self.ap_device]

        attributes = {
            "ap_device": self.ap_device,
            "router_host": self._host,
            "last_update": self.coordinator.last_update_success,
        }

        # Add extra attributes using mapping
        for attr_key, mapping in EXTRA_ATTRIBUTES_MAPPING.items():
            try:
                # Check if required data exists
                if _has_required_data(ap_data, mapping.data_keys):
                    value = mapping.convert_function(ap_data, mapping.data_keys)
                    if value is not None:  # Only add attribute if value is not None
                        attributes[attr_key] = value
            except (KeyError, TypeError, ValueError) as exc:
                _LOGGER.debug(
                    "Error getting attribute %s for %s: %s",
                    attr_key,
                    self.ap_device,
                    exc,
                )
                continue

        return attributes
