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
    PERCENTAGE,
    UnitOfElectricPotential,
    UnitOfTemperature,
    SIGNAL_STRENGTH_DECIBELS_MILLIWATT,
    SIGNAL_STRENGTH_DECIBELS,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity,
)

from ..const import (
    DOMAIN,
    CONF_QMODEM_SENSOR_TIMEOUT,
    DEFAULT_QMODEM_SENSOR_TIMEOUT,
)
from ..shared_data_manager import SharedDataUpdateCoordinator

_LOGGER = logging.getLogger(__name__)

SCAN_INTERVAL = timedelta(minutes=2)  # QModem info changes more frequently

SENSOR_DESCRIPTIONS = [
    # QModem Base Information sensors
    SensorEntityDescription(
        key="qmodem_manufacturer",
        name="Modem Manufacturer",
        icon="mdi:sim",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="qmodem_revision",
        name="Modem Revision",
        icon="mdi:sim",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="qmodem_at_port",
        name="Modem AT Port",
        icon="mdi:serial-port",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="qmodem_temperature",
        name="Modem Temperature",
        icon="mdi:thermometer",
        device_class=SensorDeviceClass.TEMPERATURE,
        native_unit_of_measurement=UnitOfTemperature.CELSIUS,
        entity_category=None,
    ),
    SensorEntityDescription(
        key="qmodem_voltage",
        name="Modem Voltage",
        icon="mdi:flash",
        device_class=SensorDeviceClass.VOLTAGE,
        native_unit_of_measurement=UnitOfElectricPotential.MILLIVOLT,
        suggested_unit_of_measurement=UnitOfElectricPotential.VOLT,
        suggested_display_precision=3,
        entity_category=None,
    ),
    SensorEntityDescription(
        key="qmodem_connect_status",
        name="Modem Connect Status",
        icon="mdi:cellphone-wireless",
        entity_category=None,
    ),
    # QModem SIM Information sensors
    SensorEntityDescription(
        key="qmodem_sim_status",
        name="SIM Status",
        icon="mdi:sim",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="qmodem_isp",
        name="Internet Service Provider",
        icon="mdi:network-outline",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="qmodem_sim_slot",
        name="SIM Slot",
        icon="mdi:sim",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="qmodem_imei",
        name="IMEI",
        icon="mdi:sim",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="qmodem_imsi",
        name="IMSI",
        icon="mdi:sim",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="qmodem_iccid",
        name="ICCID",
        icon="mdi:sim",
        entity_category=None,
    ),
    # QModem Signal Quality sensors (progress_bar type)
    SensorEntityDescription(
        key="qmodem_lte_rsrp",
        name="LTE RSRP",
        device_class=SensorDeviceClass.SIGNAL_STRENGTH,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=SIGNAL_STRENGTH_DECIBELS_MILLIWATT,
        icon="mdi:signal-cellular-3",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="qmodem_lte_rsrq",
        name="LTE RSRQ",
        device_class=SensorDeviceClass.SIGNAL_STRENGTH,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=SIGNAL_STRENGTH_DECIBELS,
        icon="mdi:signal-cellular-3",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="qmodem_lte_rssi",
        name="LTE RSSI",
        device_class=SensorDeviceClass.SIGNAL_STRENGTH,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=SIGNAL_STRENGTH_DECIBELS_MILLIWATT,
        icon="mdi:signal-cellular-3",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="qmodem_lte_sinr",
        name="LTE SINR",
        device_class=SensorDeviceClass.SIGNAL_STRENGTH,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=SIGNAL_STRENGTH_DECIBELS,
        icon="mdi:signal-cellular-3",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="qmodem_nr5g_rsrp",
        name="5G NR RSRP",
        device_class=SensorDeviceClass.SIGNAL_STRENGTH,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=SIGNAL_STRENGTH_DECIBELS_MILLIWATT,
        icon="mdi:signal-5g",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="qmodem_nr5g_rsrq",
        name="5G NR RSRQ",
        device_class=SensorDeviceClass.SIGNAL_STRENGTH,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=SIGNAL_STRENGTH_DECIBELS,
        icon="mdi:signal-5g",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="qmodem_nr5g_sinr",
        name="5G NR SINR",
        device_class=SensorDeviceClass.SIGNAL_STRENGTH,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=SIGNAL_STRENGTH_DECIBELS,
        icon="mdi:signal-5g",
        entity_category=None,
    ),
]


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> SharedDataUpdateCoordinator | None:
    """Set up OpenWrt QModem sensors from a config entry."""
    # Check if modem_ctrl is available from the initial setup
    modem_ctrl_available = hass.data.get(DOMAIN, {}).get("modem_ctrl_available", False)

    if not modem_ctrl_available:
        _LOGGER.info("QModem entities not created - modem_ctrl is not available")
        return None

    # Get shared data manager
    data_manager_key = f"data_manager_{entry.entry_id}"
    data_manager = hass.data[DOMAIN][data_manager_key]

    # Get timeout from configuration (priority: options > data > default)
    timeout = entry.options.get(
        CONF_QMODEM_SENSOR_TIMEOUT,
        entry.data.get(CONF_QMODEM_SENSOR_TIMEOUT, DEFAULT_QMODEM_SENSOR_TIMEOUT),
    )
    scan_interval = timedelta(seconds=timeout)

    # Create coordinator using shared data manager
    coordinator = SharedDataUpdateCoordinator(
        hass,
        data_manager,
        ["qmodem_info"],  # Data types this coordinator needs
        f"{DOMAIN}_qmodem_{entry.data[CONF_HOST]}",
        scan_interval,
    )

    # Fetch initial data
    await coordinator.async_config_entry_first_refresh()

    # Create QModem sensor entities
    entities = [QModemSensor(coordinator, description) for description in SENSOR_DESCRIPTIONS]
    async_add_entities(entities, True)
    _LOGGER.info("QModem entities created - modem_ctrl is available")

    return coordinator


class QModemSensor(CoordinatorEntity, SensorEntity):
    """Representation of a QModem sensor."""

    def __init__(
        self,
        coordinator: SharedDataUpdateCoordinator,
        description: SensorEntityDescription,
    ) -> None:
        """Initialize the QModem sensor."""
        super().__init__(coordinator)
        self.entity_description = description
        self._host = coordinator.data_manager.entry.data[CONF_HOST]
        self.hass = coordinator.hass  # Add reference to hass
        # Remove the 'qmodem_' prefix from description.key to avoid duplication
        key_without_prefix = description.key.replace("qmodem_", "", 1)
        self._attr_unique_id = f"{self._host}_qmodem_{key_without_prefix}"
        self._attr_has_entity_name = True

    @property
    def device_info(self) -> DeviceInfo:
        """Return device info for the QModem device."""
        # Try to get manufacturer from QModem data
        manufacturer = "Unknown"
        model = "QModem Device"

        if self.coordinator.data and self.coordinator.data.get("qmodem_info"):
            qmodem_info = self.coordinator.data["qmodem_info"]
            try:
                manufacturer_value = self._extract_qmodem_value(qmodem_info, "qmodem_manufacturer")
                if manufacturer_value:
                    manufacturer = manufacturer_value

                revision_value = self._extract_qmodem_value(qmodem_info, "qmodem_revision")
                if revision_value:
                    model = f"QModem {revision_value}"
            except Exception:
                pass  # Use default values if extraction fails

        # Create a separate device for QModem
        return DeviceInfo(
            identifiers={(DOMAIN, f"{self._host}_qmodem")},
            name=f"QModem ({self._host})",
            manufacturer=manufacturer,
            model=model,
            configuration_url=f"http://{self._host}",
            via_device=(DOMAIN, self._host),
        )

    @property
    def native_value(self) -> Any:
        """Return the value reported by the sensor."""
        if not self.coordinator.data:
            _LOGGER.debug("No coordinator data available for %s", self.entity_description.key)
            return None

        qmodem_info = self.coordinator.data.get("qmodem_info")
        if qmodem_info is None:
            _LOGGER.debug("No qmodem_info in coordinator data for %s", self.entity_description.key)
            return None

        # Parse the qmodem data and extract the requested value
        try:
            value = self._extract_qmodem_value(qmodem_info, self.entity_description.key)
            return value if value is not None else "no_data"
        except Exception as exc:
            _LOGGER.error(
                "Error extracting qmodem value for %s: %s",
                self.entity_description.key,
                exc,
            )
            _LOGGER.debug("QModem data causing error: %s", qmodem_info)
            return "error"

    def _extract_qmodem_value(self, qmodem_info: dict, key: str) -> Any:
        """Extract specific value from QModem info."""
        # Follow the same pattern as backup_sensor.py QModemCoordinator
        info_list = qmodem_info.get("info", [])
        if not info_list:
            _LOGGER.debug("No info list found in qmodem_info for key %s", key)
            return None

        # Process each info item
        for info_item in info_list:
            modem_info_list = info_item.get("modem_info", [])
            if not modem_info_list:
                continue

            # Track context for LTE vs 5G NR signals
            current_context = None
            lte_signals = {}
            nr5g_signals = {}

            # Process each modem info item to find our value
            for item in modem_info_list:
                class_origin = item.get("class_origin", "")
                item_key = item.get("key", "")
                value = item.get("value", "")
                item_type = item.get("type", "")

                # Update context based on special keys
                if item_key == "LTE":
                    current_context = "LTE"
                elif item_key.startswith("NR"):  # NR5G-NSA or any NR variant for 5G
                    current_context = "NR5G"

                # Process based on sensor key and class origin
                if class_origin == "Base Information":
                    result = self._process_base_info_item(item_key, value, key)
                    if result is not None:
                        return result
                elif class_origin == "SIM Information":
                    result = self._process_sim_info_item(item_key, value, key)
                    if result is not None:
                        return result
                elif item_type == "progress_bar" and class_origin == "Cell Information":
                    # Store signal values with context
                    if current_context == "LTE" and item_key in [
                        "RSRP",
                        "RSRQ",
                        "RSSI",
                        "SINR",
                    ]:
                        lte_signals[item_key] = value
                    elif current_context == "NR5G" and item_key in [
                        "RSRP",
                        "RSRQ",
                        "SINR",
                    ]:
                        nr5g_signals[item_key] = value

        # Check if we found the requested signal value
        if key == "qmodem_lte_rsrp" and "RSRP" in lte_signals:
            numeric_match = re.search(r"(-?\d+)", str(lte_signals["RSRP"]))
            return int(numeric_match.group(1)) if numeric_match else None
        elif key == "qmodem_lte_rsrq" and "RSRQ" in lte_signals:
            numeric_match = re.search(r"(-?\d+)", str(lte_signals["RSRQ"]))
            return int(numeric_match.group(1)) if numeric_match else None
        elif key == "qmodem_lte_rssi" and "RSSI" in lte_signals:
            numeric_match = re.search(r"(-?\d+)", str(lte_signals["RSSI"]))
            return int(numeric_match.group(1)) if numeric_match else None
        elif key == "qmodem_lte_sinr" and "SINR" in lte_signals:
            numeric_match = re.search(r"(\d+)", str(lte_signals["SINR"]))
            return int(numeric_match.group(1)) if numeric_match else None
        elif key == "qmodem_nr5g_rsrp" and "RSRP" in nr5g_signals:
            numeric_match = re.search(r"(-?\d+)", str(nr5g_signals["RSRP"]))
            return int(numeric_match.group(1)) if numeric_match else None
        elif key == "qmodem_nr5g_rsrq" and "RSRQ" in nr5g_signals:
            numeric_match = re.search(r"(-?\d+)", str(nr5g_signals["RSRQ"]))
            return int(numeric_match.group(1)) if numeric_match else None
        elif key == "qmodem_nr5g_sinr" and "SINR" in nr5g_signals:
            numeric_match = re.search(r"(\d+)", str(nr5g_signals["SINR"]))
            return int(numeric_match.group(1)) if numeric_match else None

        _LOGGER.debug("No matching value found for key %s in qmodem data", key)
        return None

    def _process_base_info_item(self, item_key: str, value: str, target_key: str) -> Any:
        """Process base information item and return value if it matches target key."""
        key_mapping = {
            "manufacturer": "qmodem_manufacturer",
            "revision": "qmodem_revision",
            "at_port": "qmodem_at_port",
            "temperature": "qmodem_temperature",
            "voltage": "qmodem_voltage",
            "connect_status": "qmodem_connect_status",
        }

        if item_key in key_mapping and key_mapping[item_key] == target_key:
            if target_key == "qmodem_temperature":
                # Extract numeric value from temperature string (e.g., "71°C")
                numeric_match = re.search(r"(\d+)", str(value))
                return int(numeric_match.group(1)) if numeric_match else None
            elif target_key == "qmodem_voltage":
                # Extract numeric value from voltage string (e.g., "3980 mV")
                numeric_match = re.search(r"(\d+)", str(value))
                return int(numeric_match.group(1)) if numeric_match else None
            else:
                return str(value) if value else None
        return None

    def _process_sim_info_item(self, item_key: str, value: str, target_key: str) -> Any:
        """Process SIM information item and return value if it matches target key."""
        key_mapping = {
            "SIM Status": "qmodem_sim_status",
            "ISP": "qmodem_isp",
            "SIM Slot": "qmodem_sim_slot",
            "IMEI": "qmodem_imei",
            "IMSI": "qmodem_imsi",
            "ICCID": "qmodem_iccid",
        }

        if item_key in key_mapping and key_mapping[item_key] == target_key:
            # Clean up value - remove newlines and extra spaces
            clean_value = str(value).replace("\n", " ").strip() if value else None
            return clean_value if clean_value else None
        return None

    @property
    def available(self) -> bool:
        """Return True if coordinator is available and qmodem/modem_ctrl is accessible."""
        # Always show as available if coordinator is updating successfully
        # This allows the entity to display "Unknown" state instead of being disabled
        if not self.coordinator.last_update_success:
            # Only mark as unavailable if there's a clear connection failure
            return True  # Changed: be more permissive about availability

        # Even if no qmodem data, keep entity available to show proper state
        return True

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        """Return additional state attributes."""
        attributes = {
            "router_host": self._host,
            "last_update": self.coordinator.last_update_success,
            "device_type": "qmodem",
        }

        # Add status information based on data availability
        if self.coordinator.data:
            qmodem_info = self.coordinator.data.get("qmodem_info")
            if qmodem_info is not None:
                attributes["data_status"] = "available"
                attributes["raw_data"] = str(qmodem_info)
            else:
                attributes["data_status"] = "no_data"
        else:
            attributes["data_status"] = "no_coordinator_data"

        # Add coordinator status
        attributes["coordinator_last_update_success"] = self.coordinator.last_update_success
        if hasattr(self.coordinator, "last_exception") and self.coordinator.last_exception:
            attributes["last_error"] = str(self.coordinator.last_exception)

        return attributes
