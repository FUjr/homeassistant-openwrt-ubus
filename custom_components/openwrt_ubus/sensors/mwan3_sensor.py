"""Support for OpenWrt router MWAN3 (Multi-WAN) information sensors."""

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
from homeassistant.const import UnitOfTime, CONF_HOST
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity,
)

from ..const import (
    DOMAIN,
    CONF_USE_HTTPS,
    DEFAULT_USE_HTTPS,
    CONF_MWAN3_SENSOR_TIMEOUT,
    DEFAULT_MWAN3_SENSOR_TIMEOUT,
    build_configuration_url,
)
from ..shared_data_manager import SharedDataUpdateCoordinator

_LOGGER = logging.getLogger(__name__)

SCAN_INTERVAL = timedelta(minutes=1)  # MWAN3 status changes reasonably frequently

# Per-interface sensor descriptions (will be created for each interface)
INTERFACE_SENSOR_DESCRIPTIONS = [
    SensorEntityDescription(
        key="status",
        name="Status",
        icon="mdi:wan",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="uptime",
        name="Uptime",
        device_class=SensorDeviceClass.DURATION,
        state_class=SensorStateClass.TOTAL_INCREASING,
        native_unit_of_measurement=UnitOfTime.SECONDS,
        suggested_unit_of_measurement=UnitOfTime.DAYS,
        icon="mdi:timer-outline",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="enabled",
        name="Enabled",
        icon="mdi:power",
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    SensorEntityDescription(
        key="running",
        name="Running",
        icon="mdi:play-circle",
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    SensorEntityDescription(
        key="tracking",
        name="Tracking",
        icon="mdi:target",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="up",
        name="Up",
        icon="mdi:arrow-up-circle",
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    SensorEntityDescription(
        key="track_ips_total",
        name="Track IPs Total",
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:ip-network",
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    SensorEntityDescription(
        key="track_ips_up",
        name="Track IPs Up",
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:check-circle",
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    SensorEntityDescription(
        key="track_ips_skipped",
        name="Track IPs Skipped",
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:skip-next-circle",
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    SensorEntityDescription(
        key="track_ips_down",
        name="Track IPs Down",
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:close-circle",
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
]

# Per-policy sensor descriptions (will be created for each policy)
POLICY_SENSOR_DESCRIPTIONS = [
    SensorEntityDescription(
        key="ipv4_active_interfaces",
        name="IPv4 Active Interfaces",
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:counter",
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    SensorEntityDescription(
        key="ipv4_primary_interface",
        name="IPv4 Primary Interface",
        icon="mdi:star",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="ipv4_interface_list",
        name="IPv4 Interface List",
        icon="mdi:format-list-numbered",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="ipv6_active_interfaces",
        name="IPv6 Active Interfaces",
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:counter",
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    SensorEntityDescription(
        key="ipv6_primary_interface",
        name="IPv6 Primary Interface",
        icon="mdi:star",
        entity_category=None,
    ),
    SensorEntityDescription(
        key="ipv6_interface_list",
        name="IPv6 Interface List",
        icon="mdi:format-list-numbered",
        entity_category=None,
    ),
]


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> SharedDataUpdateCoordinator | None:
    """Set up OpenWrt MWAN3 sensors from a config entry."""
    # Check if mwan3 is available from the initial setup
    mwan3_available = hass.data.get(DOMAIN, {}).get("mwan3_available", False)

    if not mwan3_available:
        _LOGGER.info("MWAN3 entities not created - mwan3 is not available")
        return None

    # Get shared data manager
    data_manager_key = f"data_manager_{entry.entry_id}"
    data_manager = hass.data[DOMAIN][data_manager_key]

    # Get timeout from configuration (priority: options > data > default)
    timeout = entry.options.get(
        CONF_MWAN3_SENSOR_TIMEOUT,
        entry.data.get(CONF_MWAN3_SENSOR_TIMEOUT, DEFAULT_MWAN3_SENSOR_TIMEOUT),
    )
    scan_interval = timedelta(seconds=timeout)

    # Create coordinator using shared data manager
    coordinator = SharedDataUpdateCoordinator(
        hass,
        data_manager,
        ["mwan3_status"],  # Data types this coordinator needs
        f"{DOMAIN}_mwan3_{entry.data[CONF_HOST]}",
        scan_interval,
    )

    # Store known interfaces and policies for dynamic entity creation
    coordinator.known_interfaces = set()
    coordinator.known_policies = set()
    coordinator.async_add_entities = async_add_entities

    # Add update listener for dynamic interface creation
    async def _handle_coordinator_update_async():
        """Handle coordinator updates and create new entities for new interfaces."""
        if not coordinator.data or "mwan3_status" not in coordinator.data:
            return

        mwan3_data = coordinator.data["mwan3_status"]
        if not mwan3_data or not isinstance(mwan3_data, dict):
            return

        # Get current interfaces
        interfaces = mwan3_data.get("interfaces", {})
        current_interfaces = set(interfaces.keys())

        # Handle new interfaces
        new_interfaces = current_interfaces - coordinator.known_interfaces
        if new_interfaces:
            _LOGGER.info("Found %d new MWAN3 interfaces: %s", len(new_interfaces), new_interfaces)

            # Get entity registry to check for existing entities
            entity_registry = er.async_get(hass)

            new_entities = []
            for interface in new_interfaces:
                # Check each sensor type for this interface
                interface_sensors_to_add = []
                for description in INTERFACE_SENSOR_DESCRIPTIONS:
                    unique_id = f"{entry.data[CONF_HOST]}_mwan3_intf_{interface}_{description.key}"
                    existing_entity_id = entity_registry.async_get_entity_id("sensor", DOMAIN, unique_id)

                    if existing_entity_id:
                        _LOGGER.info(
                            "MWAN3 sensor %s already exists as %s, skipping",
                            unique_id,
                            existing_entity_id,
                        )
                        continue

                    # Check if interface has required data
                    interface_data = interfaces.get(interface, {})
                    if isinstance(interface_data, dict) and interface_data:
                        interface_sensors_to_add.append(description)

                # Only add sensors that don't already exist and have data
                if interface_sensors_to_add:
                    new_entities.extend(
                        [
                            MWAN3InterfaceSensor(coordinator, description, interface)
                            for description in interface_sensors_to_add
                        ]
                    )

                coordinator.known_interfaces.add(interface)

            # Add new entities only if there are any
            if new_entities:
                async_add_entities(new_entities, True)
                _LOGGER.debug("Added %d new MWAN3 interface entities", len(new_entities))

        # Handle new policies
        policies = mwan3_data.get("policies", {})
        current_policies = set()

        # Collect all policy names from both IPv4 and IPv6
        if isinstance(policies, dict):
            for ip_version in ["ipv4", "ipv6"]:
                if ip_version in policies and isinstance(policies[ip_version], dict):
                    current_policies.update(policies[ip_version].keys())

        new_policies = current_policies - coordinator.known_policies
        if new_policies:
            _LOGGER.info("Found %d new MWAN3 policies: %s", len(new_policies), new_policies)

            # Get entity registry to check for existing entities
            entity_registry = er.async_get(hass)

            new_policy_entities = []
            for policy in new_policies:
                # Check each sensor type for this policy
                policy_sensors_to_add = []
                for description in POLICY_SENSOR_DESCRIPTIONS:
                    unique_id = f"{entry.data[CONF_HOST]}_mwan3_policy_{policy}_{description.key}"
                    existing_entity_id = entity_registry.async_get_entity_id("sensor", DOMAIN, unique_id)

                    if existing_entity_id:
                        _LOGGER.debug(
                            "MWAN3 policy sensor %s already exists as %s, skipping",
                            unique_id,
                            existing_entity_id,
                        )
                        continue

                    # Always add policy sensors (they handle empty policies)
                    policy_sensors_to_add.append(description)

                # Add all policy sensors
                if policy_sensors_to_add:
                    new_policy_entities.extend(
                        [MWAN3PolicySensor(coordinator, description, policy) for description in policy_sensors_to_add]
                    )

                coordinator.known_policies.add(policy)

            # Add new policy entities only if there are any
            if new_policy_entities:
                async_add_entities(new_policy_entities, True)
                _LOGGER.debug("Added %d new MWAN3 policy entities", len(new_policy_entities))

    # Create sync wrapper for async coordinator update handler
    def _handle_coordinator_update():
        """Sync wrapper for async coordinator update handler."""
        hass.async_create_task(_handle_coordinator_update_async())

    # Register the update listener
    coordinator.async_add_listener(_handle_coordinator_update)

    # Fetch initial data to potentially create initial entities
    await coordinator.async_config_entry_first_refresh()

    host = coordinator.data_manager.entry.data[CONF_HOST]
    device_registry = dr.async_get(hass)
    device_registry.async_get_or_create(
        config_entry_id=entry.entry_id,
        identifiers={(DOMAIN, f"{host}_mwan3")},
        name=f"{host} MWAN3 Interfaces and Policies",
        manufacturer="OpenWrt",
        via_device=(DOMAIN, host),  # Link to main router device
    )

    # Create initial entities for existing interfaces and policies
    initial_entities = []

    # Create entities for existing interfaces and policies if data is available
    if coordinator.data and "mwan3_status" in coordinator.data:
        mwan3_data = coordinator.data["mwan3_status"]
        if isinstance(mwan3_data, dict):
            # Create interface entities
            interfaces = mwan3_data.get("interfaces", {})
            if isinstance(interfaces, dict):
                for interface in interfaces:
                    interface_data = interfaces.get(interface)
                    if isinstance(interface_data, dict) and interface_data:
                        initial_entities.extend(
                            [
                                MWAN3InterfaceSensor(coordinator, description, interface)
                                for description in INTERFACE_SENSOR_DESCRIPTIONS
                            ]
                        )
                        coordinator.known_interfaces.add(interface)

            # Create policy entities
            policies = mwan3_data.get("policies", {})
            if isinstance(policies, dict):
                current_policies = set()
                # Collect all policy names from both IPv4 and IPv6
                for ip_version in ["ipv4", "ipv6"]:
                    ip_policies = policies.get(ip_version)
                    if isinstance(ip_policies, dict):
                        current_policies.update(ip_policies.keys())

                for policy in current_policies:
                    initial_entities.extend(
                        [
                            MWAN3PolicySensor(coordinator, description, policy)
                            for description in POLICY_SENSOR_DESCRIPTIONS
                        ]
                    )
                    coordinator.known_policies.add(policy)

    # Add all initial entities
    if initial_entities:
        async_add_entities(initial_entities, True)
        _LOGGER.info(
            "Created %d initial MWAN3 entities (%d interfaces, %d policies)",
            len(initial_entities),
            len(coordinator.known_interfaces),
            len(coordinator.known_policies),
        )

    _LOGGER.info("MWAN3 coordinator and global entities created - mwan3 is available")
    return coordinator


class MWAN3InterfaceSensor(CoordinatorEntity, SensorEntity):
    """Representation of a MWAN3 interface-specific sensor."""

    def __init__(
        self,
        coordinator: SharedDataUpdateCoordinator,
        description: SensorEntityDescription,
        interface: str,
    ) -> None:
        """Initialize the MWAN3 interface sensor."""
        super().__init__(coordinator)
        self.entity_description = description
        self._host = coordinator.data_manager.entry.data[CONF_HOST]
        self._interface = interface
        self.hass = coordinator.hass
        self._attr_unique_id = f"{self._host}_mwan3_intf_{interface}_{description.key}"
        self._attr_has_entity_name = True

    @property
    def device_info(self) -> DeviceInfo:
        """Return device info for the MWAN3 interface device."""
        # Create a separate device for each MWAN3 interface
        return DeviceInfo(
            identifiers={(DOMAIN, f"{self._host}_mwan3_intf_{self._interface}")},
            name=f"MWAN3 Interface {self._interface} ({self._host})",
            manufacturer="OpenWrt",
            model="MWAN3 Interface",
            configuration_url=build_configuration_url(
                self._host,
                self.coordinator.data_manager.entry.data.get(CONF_USE_HTTPS, DEFAULT_USE_HTTPS),
            ),
            via_device=(DOMAIN, f"{self._host}_mwan3"),
        )

    @property
    def native_value(self) -> Any:
        """Return the value reported by the sensor."""
        if not self.coordinator.data:
            _LOGGER.debug(
                "No coordinator data available for interface %s, key %s",
                self._interface,
                self.entity_description.key,
            )
            return None

        mwan3_status = self.coordinator.data.get("mwan3_status")
        if mwan3_status is None:
            _LOGGER.debug(
                "No mwan3_status in coordinator data for interface %s, key %s",
                self._interface,
                self.entity_description.key,
            )
            return None

        # Parse the MWAN3 data and extract the requested value for this interface
        try:
            return self._extract_interface_value(mwan3_status, self._interface, self.entity_description.key)
        except Exception as exc:
            _LOGGER.warning(
                "Error extracting MWAN3 value for interface %s, key %s: %s",
                self._interface,
                self.entity_description.key,
                exc,
            )
            return None

    def _extract_interface_value(self, mwan3_data: Any, interface: str, key: str) -> Any:
        """Extract a specific value from MWAN3 interface data."""
        if not isinstance(mwan3_data, dict):
            _LOGGER.debug("MWAN3 data is not a dictionary: %s", type(mwan3_data))
            return None

        interfaces = mwan3_data.get("interfaces", {})
        interface_data = interfaces.get(interface, {})

        if not isinstance(interface_data, dict):
            _LOGGER.debug(
                "Interface %s data is not a dictionary: %s",
                interface,
                type(interface_data),
            )
            return None

        # Extract values based on the sensor key
        if key == "status":
            return interface_data.get("status", "unknown")
        if key == "uptime":
            uptime = interface_data.get("uptime")
            if uptime is not None:
                try:
                    return int(uptime)
                except (ValueError, TypeError):
                    return 0
            return 0
        if key == "enabled":
            enabled = interface_data.get("enabled")
            if isinstance(enabled, bool):
                return "On" if enabled else "Off"
            return "Unknown"
        if key == "running":
            running = interface_data.get("running")
            if isinstance(running, bool):
                return "On" if running else "Off"
            return "Unknown"
        if key == "tracking":
            return interface_data.get("tracking", "Unknown")
        if key == "up":
            up = interface_data.get("up")
            if isinstance(up, bool):
                return "On" if up else "Off"
            return "Unknown"
        if key == "track_ips_total":
            track_ips = interface_data.get("track_ip", [])
            if isinstance(track_ips, list):
                return len(track_ips)
            return 0
        if key == "track_ips_up":
            track_ips = interface_data.get("track_ip", [])
            if isinstance(track_ips, list):
                return sum(1 for ip_entry in track_ips if isinstance(ip_entry, dict) and ip_entry.get("status") == "up")
            return 0
        if key == "track_ips_skipped":
            track_ips = interface_data.get("track_ip", [])
            if isinstance(track_ips, list):
                return sum(
                    1 for ip_entry in track_ips if isinstance(ip_entry, dict) and ip_entry.get("status") == "skipped"
                )
            return 0
        if key == "track_ips_down":
            track_ips = interface_data.get("track_ip", [])
            if isinstance(track_ips, list):
                return sum(
                    1 for ip_entry in track_ips if isinstance(ip_entry, dict) and ip_entry.get("status") == "down"
                )
            return 0

        # If key is not recognized, try to get it directly
        return interface_data.get(key)

    @property
    def available(self) -> bool:
        """Return if entity is available."""
        if not (
            self.coordinator.last_update_success
            and self.coordinator.data is not None
            and self.coordinator.data.get("mwan3_status") is not None
        ):
            return False

        # Check if the specific interface still exists
        mwan3_status = self.coordinator.data.get("mwan3_status", {})
        interfaces = mwan3_status.get("interfaces", {})
        return self._interface in interfaces


class MWAN3PolicySensor(CoordinatorEntity, SensorEntity):
    """Representation of a MWAN3 policy-specific sensor."""

    def __init__(
        self,
        coordinator: SharedDataUpdateCoordinator,
        description: SensorEntityDescription,
        policy: str,
    ) -> None:
        """Initialize the MWAN3 policy sensor."""
        super().__init__(coordinator)
        self.entity_description = description
        self._host = coordinator.data_manager.entry.data[CONF_HOST]
        self._policy = policy
        self.hass = coordinator.hass
        self._attr_unique_id = f"{self._host}_mwan3_policy_{policy}_{description.key}"
        self._attr_has_entity_name = True

    @property
    def device_info(self) -> DeviceInfo:
        """Return device info for the MWAN3 policy device."""
        # Create a separate device for each MWAN3 policy
        return DeviceInfo(
            identifiers={(DOMAIN, f"{self._host}_mwan3_policy_{self._policy}")},
            name=f"MWAN3 Policy {self._policy} ({self._host})",
            manufacturer="OpenWrt",
            model="MWAN3 Policy",
            configuration_url=build_configuration_url(
                self._host,
                self.coordinator.data_manager.entry.data.get(CONF_USE_HTTPS, DEFAULT_USE_HTTPS),
            ),
            via_device=(DOMAIN, f"{self._host}_mwan3"),
        )

    @property
    def native_value(self) -> Any:
        """Return the value reported by the sensor."""
        if not self.coordinator.data:
            _LOGGER.debug(
                "No coordinator data available for policy %s, key %s",
                self._policy,
                self.entity_description.key,
            )
            return None

        mwan3_status = self.coordinator.data.get("mwan3_status")
        if mwan3_status is None:
            _LOGGER.debug(
                "No mwan3_status in coordinator data for policy %s, key %s",
                self._policy,
                self.entity_description.key,
            )
            return None

        # Parse the MWAN3 data and extract the requested value for this policy
        try:
            return self._extract_policy_value(mwan3_status, self._policy, self.entity_description.key)
        except Exception as exc:
            _LOGGER.warning(
                "Error extracting MWAN3 value for policy %s, key %s: %s",
                self._policy,
                self.entity_description.key,
                exc,
            )
            return None

    def _extract_policy_value(self, mwan3_data: Any, policy: str, key: str) -> Any:
        """Extract a specific value from MWAN3 policy data."""
        if not isinstance(mwan3_data, dict):
            _LOGGER.debug("MWAN3 data is not a dictionary: %s", type(mwan3_data))
            return None

        policies = mwan3_data.get("policies", {})
        if not isinstance(policies, dict):
            _LOGGER.debug("Policies data is not a dictionary: %s", type(policies))
            return None

        # Determine IP version from key
        ip_version = "ipv4" if key.startswith("ipv4_") else "ipv6"
        policy_data = policies.get(ip_version, {}).get(policy, [])

        if not isinstance(policy_data, list):
            _LOGGER.debug(
                "Policy %s %s data is not a list: %s",
                policy,
                ip_version,
                type(policy_data),
            )
            return ""

        # Extract values based on the sensor key
        if key.endswith("_active_interfaces"):
            return len(policy_data)
        if key.endswith("_primary_interface"):
            if not policy_data:
                return ""
            # Find interface with highest percent
            primary = max(
                policy_data,
                key=lambda x: x.get("percent", 0) if isinstance(x, dict) else 0,
            )
            return primary.get("interface", "") if isinstance(primary, dict) else ""
        if key.endswith("_interface_list"):
            if not policy_data:
                return ""
            # Sort by percent descending and format as "interface (percent%)"
            sorted_interfaces = sorted(
                [x for x in policy_data if isinstance(x, dict)],
                key=lambda x: x.get("percent", 0),
                reverse=True,
            )
            return ", ".join(
                f"{iface.get('interface', 'unknown')} ({iface.get('percent', 0)}%)" for iface in sorted_interfaces
            )

        # If key is not recognized, return empty string
        return ""

    @property
    def available(self) -> bool:
        """Return if entity is available."""
        if not (
            self.coordinator.last_update_success
            and self.coordinator.data is not None
            and self.coordinator.data.get("mwan3_status") is not None
        ):
            return False

        # Check if the specific policy still exists in either IPv4 or IPv6
        mwan3_status = self.coordinator.data.get("mwan3_status", {})
        policies = mwan3_status.get("policies", {})

        # Policy is available if it exists in either IPv4 or IPv6
        for ip_version in ["ipv4", "ipv6"]:
            ip_policies = policies.get(ip_version)
            if isinstance(ip_policies, dict) and self._policy in ip_policies:
                return True

        return False
