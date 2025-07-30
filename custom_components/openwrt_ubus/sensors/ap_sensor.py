"""Support for OpenWrt router access point sensors."""

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
    UnitOfElectricPotential,
    UnitOfFrequency,
    UnitOfDataRate,
    PERCENTAGE,
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
    CONF_AP_SENSOR_TIMEOUT,
    DEFAULT_AP_SENSOR_TIMEOUT,
)
from ..shared_data_manager import SharedDataUpdateCoordinator

_LOGGER = logging.getLogger(__name__)

SCAN_INTERVAL = timedelta(seconds=60)  # AP info doesn't change frequently

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
        entry.data.get(CONF_AP_SENSOR_TIMEOUT, DEFAULT_AP_SENSOR_TIMEOUT)
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
        new_devices = set(ap_info_data.keys()) - coordinator.known_devices
        
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
                    existing_entity_id = entity_registry.async_get_entity_id(
                        "sensor", DOMAIN, unique_id
                    )
                    
                    if existing_entity_id:
                        _LOGGER.debug(
                            "AP sensor entity %s already exists with entity_id %s, skipping creation",
                            unique_id, existing_entity_id
                        )
                        continue
                    
                    device_sensors_to_add.append(description)
                
                # Only add sensors that don't already exist
                if device_sensors_to_add:
                    new_entities.extend([
                        ApSensor(coordinator, description, ap_device)
                        for description in device_sensors_to_add
                    ])
                
                coordinator.known_devices.add(ap_device)
            
            # Add new entities only if there are any
            if new_entities:
                async_add_entities(new_entities, True)
                _LOGGER.info("Created %d AP sensor entities for %d new devices", 
                           len(new_entities), len(new_devices))
            else:
                _LOGGER.debug("No new AP sensor entities to create for %d devices (all already exist)", 
                            len(new_devices))
    
    # Perform first refresh
    await coordinator.async_config_entry_first_refresh()
    
    # Add initial sensors for any devices already discovered
    initial_entities = []
    if coordinator.data and coordinator.data.get("ap_info"):
        ap_info_data = coordinator.data["ap_info"]
        for ap_device in ap_info_data:
            coordinator.known_devices.add(ap_device)
            for description in SENSOR_DESCRIPTIONS:
                initial_entities.append(
                    ApSensor(coordinator, description, ap_device)
                )
    
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
        if (self.coordinator.data and "ap_info" in self.coordinator.data 
            and self.ap_device in self.coordinator.data["ap_info"]):
            ap_data = self.coordinator.data["ap_info"][self.ap_device]
            if "device_name" in ap_data:
                device_name = ap_data["device_name"]
        
        # Create a device for each AP interface
        return DeviceInfo(
            identifiers={(DOMAIN, f"{self._host}_ap_{self.ap_device}")},
            name=device_name,
            manufacturer="OpenWrt",
            model="Access Point",
            via_device=(DOMAIN, self._host),
        )

    @property
    def available(self) -> bool:
        """Return True if entity is available."""
        return (
            self.coordinator.last_update_success
            and self.coordinator.data is not None
            and "ap_info" in self.coordinator.data
            and self.ap_device in self.coordinator.data["ap_info"]
        )

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

        try:
            if key == "ssid":
                return ap_data.get("ssid")
            elif key == "bssid":
                return ap_data.get("bssid")
            elif key == "channel":
                return ap_data.get("channel")
            elif key == "frequency":
                return ap_data.get("frequency")
            elif key == "txpower":
                return ap_data.get("txpower")
            elif key == "quality":
                quality = ap_data.get("quality")
                quality_max = ap_data.get("quality_max", 100)
                if quality is not None and quality_max:
                    return round((quality / quality_max) * 100, 1)
                return None
            elif key == "signal":
                return ap_data.get("signal")
            elif key == "noise":
                return ap_data.get("noise")
            elif key == "bitrate":
                return ap_data.get("bitrate")
            elif key == "mode":
                return ap_data.get("mode")
            elif key == "hwmode":
                return ap_data.get("hwmode")
            elif key == "htmode":
                return ap_data.get("htmode")
            elif key == "country":
                return ap_data.get("country")

        except (KeyError, TypeError, ValueError) as exc:
            _LOGGER.debug("Error getting %s for %s: %s", key, self.ap_device, exc)
            return None

        return None

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

        # Add PHY information
        if "phy" in ap_data:
            attributes["phy"] = ap_data["phy"]

        # Add frequency information
        if "center_chan1" in ap_data:
            attributes["center_channel"] = ap_data["center_chan1"]
        if "frequency_offset" in ap_data:
            attributes["frequency_offset"] = ap_data["frequency_offset"]
        if "txpower_offset" in ap_data:
            attributes["txpower_offset"] = ap_data["txpower_offset"]

        # Add encryption information
        encryption = ap_data.get("encryption", {})
        if encryption:
            attributes.update({
                "encryption_enabled": encryption.get("enabled", False),
                "wpa_versions": encryption.get("wpa", []),
                "authentication": encryption.get("authentication", []),
                "ciphers": encryption.get("ciphers", []),
            })

        # Add supported modes
        if "htmodes" in ap_data:
            attributes["supported_ht_modes"] = ap_data["htmodes"]
        if "hwmodes" in ap_data:
            attributes["supported_hw_modes"] = ap_data["hwmodes"]
        if "hwmodes_text" in ap_data:
            attributes["hw_modes_text"] = ap_data["hwmodes_text"]

        # Add hardware information
        hardware = ap_data.get("hardware", {})
        if hardware:
            if "name" in hardware:
                attributes["hardware_name"] = hardware["name"]
            if "id" in hardware:
                attributes["hardware_id"] = hardware["id"]

        return attributes
