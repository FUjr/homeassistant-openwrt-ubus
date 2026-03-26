"""Config flow for openwrt ubus integration."""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import (
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
    ConfigEntry,
)
from homeassistant.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_USERNAME,
    CONF_IP_ADDRESS,
    CONF_VERIFY_SSL,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from . import API_DEF_TIMEOUT
from .Ubus import Ubus
from .Ubus.const import API_RPC_CALL
from .extended_ubus import ExtendedUbus
from .const import (
    CONF_DHCP_SOFTWARE,
    CONF_WIRELESS_SOFTWARE,
    CONF_USE_HTTPS,
    CONF_PORT,
    CONF_ENDPOINT,
    CONF_ENABLE_QMODEM_SENSORS,
    CONF_ENABLE_STA_SENSORS,
    CONF_ENABLE_SYSTEM_SENSORS,
    CONF_ENABLE_AP_SENSORS,
    CONF_ENABLE_ETH_SENSORS,
    CONF_ENABLE_MWAN3_SENSORS,
    CONF_ENABLE_SERVICE_CONTROLS,
    CONF_ENABLE_DEVICE_KICK_BUTTONS,
    CONF_ENABLE_WIRED_TRACKER,
    CONF_WIRED_TRACKER_NAME_PRIORITY,
    CONF_WIRED_TRACKER_WHITELIST,
    CONF_WIRED_TRACKER_INTERFACES,
    CONF_ENABLE_WIRELESS_TRACKERS,
    CONF_WIRELESS_TRACKER_WHITELIST,
    CONF_SELECT_ALL_STA,
    CONF_SELECTED_STA,
    CONF_SELECTED_SERVICES,
    CONF_SYSTEM_SENSOR_TIMEOUT,
    CONF_QMODEM_SENSOR_TIMEOUT,
    CONF_STA_SENSOR_TIMEOUT,
    CONF_AP_SENSOR_TIMEOUT,
    CONF_MWAN3_SENSOR_TIMEOUT,
    CONF_SERVICE_TIMEOUT,
    CONF_TRACKING_METHOD,
    DEFAULT_DHCP_SOFTWARE,
    DEFAULT_WIRELESS_SOFTWARE,
    DEFAULT_USE_HTTPS,
    DEFAULT_PORT_HTTP,
    DEFAULT_PORT_HTTPS,
    DEFAULT_ENDPOINT,
    DEFAULT_ENABLE_QMODEM_SENSORS,
    DEFAULT_ENABLE_STA_SENSORS,
    DEFAULT_ENABLE_SYSTEM_SENSORS,
    DEFAULT_ENABLE_AP_SENSORS,
    DEFAULT_ENABLE_ETH_SENSORS,
    DEFAULT_ENABLE_MWAN3_SENSORS,
    DEFAULT_ENABLE_SERVICE_CONTROLS,
    DEFAULT_ENABLE_DEVICE_KICK_BUTTONS,
    DEFAULT_ENABLE_WIRED_TRACKER,
    DEFAULT_WIRED_TRACKER_NAME_PRIORITY,
    DEFAULT_WIRED_TRACKER_WHITELIST,
    DEFAULT_WIRED_TRACKER_INTERFACES,
    DEFAULT_ENABLE_WIRELESS_TRACKERS,
    DEFAULT_SELECT_ALL_STA,
    DEFAULT_SELECTED_STA,
    CONF_CONSIDER_HOME,
    DEFAULT_CONSIDER_HOME,
    DEFAULT_SYSTEM_SENSOR_TIMEOUT,
    DEFAULT_QMODEM_SENSOR_TIMEOUT,
    DEFAULT_STA_SENSOR_TIMEOUT,
    DEFAULT_AP_SENSOR_TIMEOUT,
    DEFAULT_MWAN3_SENSOR_TIMEOUT,
    DEFAULT_SERVICE_TIMEOUT,
    DEFAULT_TRACKING_METHOD,
    DHCP_SOFTWARES,
    DOMAIN,
    WIRELESS_SOFTWARES,
    TRACKING_METHODS,
    API_SUBSYS_RC,
    API_METHOD_LIST,
    build_ubus_url,
)

_LOGGER = logging.getLogger(__name__)

# Step 1: Connection configuration
STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_HOST): str,
        vol.Optional(CONF_IP_ADDRESS): str,
        vol.Optional(CONF_USE_HTTPS, default=DEFAULT_USE_HTTPS): bool,
        vol.Optional(CONF_PORT): vol.All(vol.Coerce(int), vol.Range(min=1, max=65535)),
        vol.Optional(CONF_VERIFY_SSL, default=False): bool,
        vol.Optional(CONF_ENDPOINT, default=DEFAULT_ENDPOINT): str,
        vol.Required(CONF_USERNAME): str,
        vol.Required(CONF_PASSWORD): str,
        vol.Optional(CONF_WIRELESS_SOFTWARE, default=DEFAULT_WIRELESS_SOFTWARE): vol.In(WIRELESS_SOFTWARES),
        vol.Optional(CONF_DHCP_SOFTWARE, default=DEFAULT_DHCP_SOFTWARE): vol.In(DHCP_SOFTWARES),
        vol.Optional(CONF_TRACKING_METHOD, default=DEFAULT_TRACKING_METHOD): vol.In(TRACKING_METHODS),
    }
)

# Step 2: Sensor configuration
STEP_SENSORS_DATA_SCHEMA = vol.Schema(
    {
        vol.Optional(CONF_ENABLE_SYSTEM_SENSORS, default=DEFAULT_ENABLE_SYSTEM_SENSORS): bool,
        vol.Optional(CONF_ENABLE_QMODEM_SENSORS, default=DEFAULT_ENABLE_QMODEM_SENSORS): bool,
        vol.Optional(CONF_ENABLE_STA_SENSORS, default=DEFAULT_ENABLE_STA_SENSORS): bool,
        vol.Optional(CONF_ENABLE_AP_SENSORS, default=DEFAULT_ENABLE_AP_SENSORS): bool,
        vol.Optional(CONF_ENABLE_ETH_SENSORS, default=DEFAULT_ENABLE_ETH_SENSORS): bool,
        vol.Optional(CONF_ENABLE_MWAN3_SENSORS, default=DEFAULT_ENABLE_MWAN3_SENSORS): bool,
        vol.Optional(CONF_ENABLE_SERVICE_CONTROLS, default=DEFAULT_ENABLE_SERVICE_CONTROLS): bool,
        vol.Optional(CONF_ENABLE_DEVICE_KICK_BUTTONS, default=DEFAULT_ENABLE_DEVICE_KICK_BUTTONS): bool,
        vol.Optional(CONF_ENABLE_WIRELESS_TRACKERS, default=DEFAULT_ENABLE_WIRELESS_TRACKERS): bool,
        vol.Optional(CONF_ENABLE_WIRED_TRACKER, default=DEFAULT_ENABLE_WIRED_TRACKER): bool,
    }
)

# Step 3: Timeout configuration
STEP_TIMEOUTS_DATA_SCHEMA = vol.Schema(
    {
        vol.Optional(CONF_SYSTEM_SENSOR_TIMEOUT, default=DEFAULT_SYSTEM_SENSOR_TIMEOUT): vol.All(
            vol.Coerce(int), vol.Range(min=10, max=300)
        ),
        vol.Optional(CONF_QMODEM_SENSOR_TIMEOUT, default=DEFAULT_QMODEM_SENSOR_TIMEOUT): vol.All(
            vol.Coerce(int), vol.Range(min=30, max=600)
        ),
        vol.Optional(CONF_STA_SENSOR_TIMEOUT, default=DEFAULT_STA_SENSOR_TIMEOUT): vol.All(
            vol.Coerce(int), vol.Range(min=10, max=300)
        ),
        vol.Optional(CONF_AP_SENSOR_TIMEOUT, default=DEFAULT_AP_SENSOR_TIMEOUT): vol.All(
            vol.Coerce(int), vol.Range(min=30, max=600)
        ),
        vol.Optional(CONF_MWAN3_SENSOR_TIMEOUT, default=DEFAULT_MWAN3_SENSOR_TIMEOUT): vol.All(
            vol.Coerce(int), vol.Range(min=30, max=600)
        ),
        vol.Optional(CONF_SERVICE_TIMEOUT, default=DEFAULT_SERVICE_TIMEOUT): vol.All(
            vol.Coerce(int), vol.Range(min=10, max=300)
        ),
    }
)


async def validate_input(hass: HomeAssistant, data: dict[str, Any]) -> dict[str, Any]:
    """Validate the user input allows us to connect.

    Data has the keys from STEP_USER_DATA_SCHEMA with values provided by the user.
    """
    ubus = create_ubus_from_config(hass, data)

    try:
        # Test connection
        session_id = await ubus.connect()
        if session_id is None:
            raise CannotConnect("Failed to connect to OpenWrt device")

    except Exception as exc:
        _LOGGER.exception("Unexpected exception during connection test")
        raise CannotConnect("Failed to connect to OpenWrt device") from exc
    finally:
        # Always close the session to prevent leaks
        await ubus.close()

    # Return info that you want to store in the config entry.
    return {"title": f"OpenWrt ubus {data[CONF_HOST]}"}


def create_ubus_from_config(hass: HomeAssistant, data: dict) -> ExtendedUbus:
    session = async_get_clientsession(hass, verify_ssl=data.get(CONF_VERIFY_SSL, False))
    hostname = data[CONF_HOST]
    ip = data.get(CONF_IP_ADDRESS, None)
    use_https = data.get(CONF_USE_HTTPS, DEFAULT_USE_HTTPS)
    port = data.get(CONF_PORT)
    endpoint = data.get(CONF_ENDPOINT, DEFAULT_ENDPOINT)
    url = build_ubus_url(hostname, use_https, ip, port, endpoint)
    return ExtendedUbus(
        url,
        hostname,
        data[CONF_USERNAME],
        data[CONF_PASSWORD],
        session=session,
        timeout=API_DEF_TIMEOUT,
        verify=data.get(CONF_VERIFY_SSL, False),
    )


async def get_services_list(hass: HomeAssistant, data: dict[str, Any]) -> list[str]:
    """Get list of available services from OpenWrt."""
    ubus = create_ubus_from_config(hass, data)

    try:
        session_id = await ubus.connect()
        if session_id is None:
            return []

        # Call rc list to get services
        response = await ubus.api_call(API_RPC_CALL, API_SUBSYS_RC, API_METHOD_LIST, {})
        if response and isinstance(response, dict):
            services = list(response.keys())
            return sorted(services)

    except Exception as exc:
        _LOGGER.warning("Failed to get services list: %s", exc)
        return []
    finally:
        await ubus.close()

    return []


async def get_connected_wifi_devices(hass: HomeAssistant, data: dict[str, Any]) -> dict[str, str]:
    """Get list of connected WiFi devices from OpenWrt with hostname resolution."""
    ubus = create_ubus_from_config(hass, data)
    try:
        session_id = await ubus.connect()
        if session_id is None:
            return {}

        is_hostapd = data.get(CONF_WIRELESS_SOFTWARE, DEFAULT_WIRELESS_SOFTWARE) == "hostapd"

        ap_devices_result = await ubus.get_ap_devices()
        if not ap_devices_result:
            return {}

        ap_devices = ubus.parse_ap_devices(ap_devices_result)
        if not ap_devices:
            return {}

        # sta_data is {ap_name: {"devices": [mac_list], "statistics": {mac: data}}}
        sta_data = await ubus.get_all_sta_data_batch(ap_devices, is_hostapd=is_hostapd)

        # Collect all MAC addresses from all APs
        all_macs = set()
        if sta_data:
            for ap_name, ap_sta_info in sta_data.items():
                if isinstance(ap_sta_info, dict):
                    for mac in ap_sta_info.get("devices", []):
                        all_macs.add(str(mac).upper())

        if not all_macs:
            return {}

        # Try to map MAC addresses to hostnames
        mac2name: dict[str, str] = {}
        try:
            # /etc/ethers has the highest priority
            ethers_mapping = await ubus.get_ethers_mapping()
            if ethers_mapping and isinstance(ethers_mapping, dict):
                for mac, info in ethers_mapping.items():
                    if isinstance(info, dict):
                        mac2name[str(mac).upper()] = str(info.get("hostname", ""))

            # DHCP leases as secondary source
            dhcp_software = data.get(CONF_DHCP_SOFTWARE, DEFAULT_DHCP_SOFTWARE)
            if dhcp_software == "dnsmasq":
                result = await ubus.get_uci_config("dhcp", "dnsmasq")
                leasefile = "/tmp/dhcp.leases"
                if result and "values" in result:
                    values = result["values"].values()
                    leasefile = next(iter(values), {}).get("leasefile", "/tmp/dhcp.leases")
                lease_result = await ubus.file_read(leasefile)
                if lease_result and "data" in lease_result:
                    for line in lease_result["data"].splitlines():
                        hosts = line.split(" ")
                        if len(hosts) >= 4:
                            mac_upper = hosts[1].upper()
                            if mac_upper not in mac2name:
                                mac2name[mac_upper] = hosts[3]
            elif dhcp_software == "odhcpd":
                result = await ubus.get_dhcp_method("ipv4leases")
                if result and "device" in result:
                    for device in result["device"].values():
                        for lease in device.get("leases", []):
                            mac = lease.get("mac", "")
                            if mac and len(mac) == 12:
                                mac = ":".join(mac[i: i + 2] for i in range(0, len(mac), 2))
                                mac_upper = mac.upper()
                                if mac_upper not in mac2name:
                                    mac2name[mac_upper] = lease.get("hostname", "")
        except Exception as exc:
            _LOGGER.debug("Failed to get hostname mappings (non-fatal): %s", exc)

        # Build display strings: "Hostname (MAC)" or just "MAC"
        devices: dict[str, str] = {}
        for mac_upper in all_macs:
            hostname = mac2name.get(mac_upper, "")
            if hostname and hostname != "*":
                devices[mac_upper] = f"{hostname} ({mac_upper})"
            else:
                devices[mac_upper] = mac_upper

        return devices

    except Exception as exc:
        _LOGGER.exception("Failed to get connected wifi devices: %s", exc)
        return {}
    finally:
        await ubus.close()


class OpenwrtUbusConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for openwrt ubus."""

    VERSION = 1

    def __init__(self) -> None:
        """Initialize the config flow."""
        self._connection_data: dict[str, Any] = {}
        self._sensor_data: dict[str, Any] = {}
        self._services_data: dict[str, Any] = {}
        self._available_services: list[str] = []
        self._available_sta_devices: dict[str, str] = {}

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        """Create the options flow."""
        return OpenwrtUbusOptionsFlow(config_entry)

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                info = await validate_input(self.hass, user_input)
            except CannotConnect:
                errors["base"] = "cannot_connect"
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except Exception:
                _LOGGER.exception("Unexpected exception")
                errors["base"] = "unknown"
            else:
                # Check if already configured
                await self.async_set_unique_id(user_input[CONF_HOST])
                self._abort_if_unique_id_configured()

                # Store connection data and proceed to sensor configuration
                self._connection_data = user_input
                return await self.async_step_sensors()

        return self.async_show_form(step_id="user", data_schema=STEP_USER_DATA_SCHEMA, errors=errors)

    async def async_step_sensors(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Handle the sensor configuration step."""
        if user_input is not None:
            self._sensor_data = user_input

            # If sta sensors enabled, proceed to selection config
            if user_input.get(CONF_ENABLE_STA_SENSORS, DEFAULT_ENABLE_STA_SENSORS):
                return await self.async_step_sta_sensors_config()

            # If wireless tracker is enabled, proceed to wireless tracker configuration
            if user_input.get(CONF_ENABLE_WIRELESS_TRACKERS, False):
                return await self.async_step_wireless_tracker_config()

            # If wired tracker is enabled, proceed to wired tracker configuration
            if user_input.get(CONF_ENABLE_WIRED_TRACKER, False):
                return await self.async_step_wired_tracker_config()

            # If service controls are enabled, proceed to services selection
            if user_input.get(CONF_ENABLE_SERVICE_CONTROLS, False):
                return await self.async_step_services()

            return await self.async_step_timeouts()

        return self.async_show_form(
            step_id="sensors",
            data_schema=STEP_SENSORS_DATA_SCHEMA,
            description_placeholders={"host": self._connection_data[CONF_HOST]},
        )

    async def async_step_sta_sensors_config(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Handle the station sensors device selection step."""
        if user_input is not None:
            self._sensor_data.update(user_input)

            # If wired tracker is enabled, proceed to wired tracker configuration
            if self._sensor_data.get(CONF_ENABLE_WIRED_TRACKER, False):
                return await self.async_step_wired_tracker_config()

            # If service controls are enabled, proceed to services selection
            if self._sensor_data.get(CONF_ENABLE_SERVICE_CONTROLS, False):
                return await self.async_step_services()

            return await self.async_step_timeouts()

        # Fetch currently connected devices for checkboxes
        if not self._available_sta_devices:
            self._available_sta_devices = await get_connected_wifi_devices(self.hass, self._connection_data)

        sta_sensors_schema = vol.Schema(
            {
                vol.Required(
                    CONF_SELECT_ALL_STA,
                    default=DEFAULT_SELECT_ALL_STA,
                ): cv.boolean,
                vol.Optional(
                    CONF_SELECTED_STA,
                    default=DEFAULT_SELECTED_STA,
                ): cv.multi_select({mac: name for mac, name in self._available_sta_devices.items()}),
            }
        )

        return self.async_show_form(
            step_id="sta_sensors_config",
            data_schema=sta_sensors_schema,
            description_placeholders={"host": self._connection_data[CONF_HOST]},
        )

    async def async_step_wired_tracker_config(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Handle the wired tracker configuration step."""
        if user_input is not None:
            # Merge wired tracker config into sensor data
            self._sensor_data.update(user_input)

            # If service controls are enabled, proceed to services selection
            if self._sensor_data.get(CONF_ENABLE_SERVICE_CONTROLS, False):
                return await self.async_step_services()

            return await self.async_step_timeouts()

        # Create schema for wired tracker configuration
        wired_tracker_schema = vol.Schema(
            {
                vol.Optional(
                    CONF_WIRED_TRACKER_NAME_PRIORITY,
                    default=DEFAULT_WIRED_TRACKER_NAME_PRIORITY,
                ): vol.In(["ipv4", "ipv6", "mac"]),
                vol.Optional(
                    CONF_WIRED_TRACKER_WHITELIST,
                    default="",
                ): cv.string,
                vol.Optional(
                    CONF_WIRED_TRACKER_INTERFACES,
                    default="",
                ): cv.string,
            }
        )

        return self.async_show_form(
            step_id="wired_tracker_config",
            data_schema=wired_tracker_schema,
            description_placeholders={"host": self._connection_data[CONF_HOST]},
        )

    async def async_step_wireless_tracker_config(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Handle the wireless tracker configuration step."""
        if user_input is not None:
            # Merge wireless tracker config into sensor data
            self._sensor_data.update(user_input)

            # Process whitelist from comma-separated string
            if CONF_WIRELESS_TRACKER_WHITELIST in self._sensor_data:
                whitelist_str = self._sensor_data[CONF_WIRELESS_TRACKER_WHITELIST]
                if isinstance(whitelist_str, str):
                    self._sensor_data[CONF_WIRELESS_TRACKER_WHITELIST] = [
                        item.strip() for item in whitelist_str.split(",") if item.strip()
                    ]

            # If wired tracker is enabled, proceed to wired tracker configuration
            if self._sensor_data.get(CONF_ENABLE_WIRED_TRACKER, False):
                return await self.async_step_wired_tracker_config()

            # If service controls are enabled, proceed to services selection
            if self._sensor_data.get(CONF_ENABLE_SERVICE_CONTROLS, False):
                return await self.async_step_services()

            return await self.async_step_timeouts()

        # Create schema for wireless tracker configuration
        wireless_tracker_schema = vol.Schema(
            {
                vol.Optional(
                    CONF_WIRELESS_TRACKER_WHITELIST,
                    default="",
                ): cv.string,
            }
        )

        return self.async_show_form(
            step_id="wireless_tracker_config",
            data_schema=wireless_tracker_schema,
            description_placeholders={"host": self._connection_data[CONF_HOST]},
        )

    async def async_step_services(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Handle the services selection step."""
        errors: dict[str, str] = {}

        if user_input is not None:
            self._services_data = user_input
            return await self.async_step_timeouts()

        # Get available services
        if not self._available_services:
            try:
                self._available_services = await get_services_list(self.hass, self._connection_data)
            except Exception as exc:
                _LOGGER.warning("Failed to get services list: %s", exc)
                errors["base"] = "cannot_get_services"

        if not self._available_services and not errors:
            errors["base"] = "no_services_found"

        # Create multi-select schema for services
        services_schema = vol.Schema({})
        if self._available_services:
            services_schema = vol.Schema(
                {
                    vol.Optional(CONF_SELECTED_SERVICES, default=[]): cv.multi_select(
                        {service: service for service in self._available_services}
                    ),
                }
            )

        return self.async_show_form(
            step_id="services",
            data_schema=services_schema,
            errors=errors,
            description_placeholders={
                "host": self._connection_data[CONF_HOST],
                "services_count": str(len(self._available_services)) if self._available_services else "0",
            },
        )

    async def async_step_timeouts(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Handle the timeout configuration step."""
        if user_input is not None:
            # Process wired tracker whitelist and interfaces from comma-separated strings
            if CONF_WIRED_TRACKER_WHITELIST in self._sensor_data:
                whitelist_str = self._sensor_data[CONF_WIRED_TRACKER_WHITELIST]
                if isinstance(whitelist_str, str):
                    self._sensor_data[CONF_WIRED_TRACKER_WHITELIST] = [
                        item.strip() for item in whitelist_str.split(",") if item.strip()
                    ]

            if CONF_WIRED_TRACKER_INTERFACES in self._sensor_data:
                interfaces_str = self._sensor_data[CONF_WIRED_TRACKER_INTERFACES]
                if isinstance(interfaces_str, str):
                    self._sensor_data[CONF_WIRED_TRACKER_INTERFACES] = [
                        item.strip() for item in interfaces_str.split(",") if item.strip()
                    ]

            # Combine all configuration data
            config_data = {
                **self._connection_data,
                **self._sensor_data,
                **self._services_data,
                **user_input,
            }

            info = {"title": f"OpenWrt ubus {config_data[CONF_HOST]}"}
            return self.async_create_entry(title=info["title"], data=config_data)

        return self.async_show_form(
            step_id="timeouts",
            data_schema=STEP_TIMEOUTS_DATA_SCHEMA,
            description_placeholders={"host": self._connection_data[CONF_HOST]},
        )


class OpenwrtUbusOptionsFlow(OptionsFlow):
    """Handle options flow for OpenWrt ubus."""

    def __init__(self, config_entry: ConfigEntry) -> None:
        """Initialize options flow."""
        super().__init__()
        self._available_services: list[str] = []
        self._available_sta_devices: dict[str, str] = {}
        self._temp_data: dict[str, Any] = {}

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Manage the options."""
        if user_input is not None:
            # Check if we need to refresh services
            if user_input.get("refresh_services", False):
                return await self.async_step_services()

            # Process wireless tracker whitelist string into list
            if CONF_WIRELESS_TRACKER_WHITELIST in user_input:
                whitelist_str = user_input.get(CONF_WIRELESS_TRACKER_WHITELIST, "")
                if whitelist_str:
                    user_input[CONF_WIRELESS_TRACKER_WHITELIST] = [
                        prefix.strip() for prefix in whitelist_str.split(",") if prefix.strip()
                    ]
                else:
                    user_input[CONF_WIRELESS_TRACKER_WHITELIST] = []

            # Process wired tracker whitelist string into list
            if CONF_WIRED_TRACKER_WHITELIST in user_input:
                whitelist_str = user_input.get(CONF_WIRED_TRACKER_WHITELIST, "")
                if whitelist_str:
                    # Split by comma and strip whitespace
                    user_input[CONF_WIRED_TRACKER_WHITELIST] = [
                        prefix.strip() for prefix in whitelist_str.split(",") if prefix.strip()
                    ]
                else:
                    user_input[CONF_WIRED_TRACKER_WHITELIST] = []

            # Process interfaces string into list
            if CONF_WIRED_TRACKER_INTERFACES in user_input:
                interfaces_str = user_input.get(CONF_WIRED_TRACKER_INTERFACES, "")
                if interfaces_str:
                    # Split by comma and strip whitespace
                    user_input[CONF_WIRED_TRACKER_INTERFACES] = [
                        iface.strip() for iface in interfaces_str.split(",") if iface.strip()
                    ]
                else:
                    user_input[CONF_WIRED_TRACKER_INTERFACES] = []

            # Get current data and merge with new options
            new_data = dict(self.config_entry.data)
            new_data.update(user_input)
            self._temp_data = user_input

            # If sta sensors enabled, proceed to selection config
            if user_input.get(CONF_ENABLE_STA_SENSORS, DEFAULT_ENABLE_STA_SENSORS):
                return await self.async_step_sta_sensors_config()

            return await self._update_and_reload(user_input)

        # Create form with all configurable options
        current_data = self.config_entry.data
        options_schema = vol.Schema(
            {
                vol.Optional(CONF_USE_HTTPS, default=current_data.get(CONF_USE_HTTPS, DEFAULT_USE_HTTPS)): bool,
                vol.Optional(
                    CONF_PORT,
                    description={"suggested_value": current_data.get(CONF_PORT)},
                ): vol.All(vol.Coerce(int), vol.Range(min=1, max=65535)),
                vol.Optional(CONF_VERIFY_SSL, default=current_data.get(CONF_VERIFY_SSL, False)): bool,
                vol.Optional(
                    CONF_ENDPOINT,
                    default=current_data.get(CONF_ENDPOINT, DEFAULT_ENDPOINT),
                ): str,
                vol.Optional(
                    CONF_WIRELESS_SOFTWARE,
                    default=current_data.get(CONF_WIRELESS_SOFTWARE, DEFAULT_WIRELESS_SOFTWARE),
                ): vol.In(WIRELESS_SOFTWARES),
                vol.Optional(
                    CONF_DHCP_SOFTWARE,
                    default=current_data.get(CONF_DHCP_SOFTWARE, DEFAULT_DHCP_SOFTWARE),
                ): vol.In(DHCP_SOFTWARES),
                vol.Optional(
                    CONF_TRACKING_METHOD,
                    default=current_data.get(CONF_TRACKING_METHOD, DEFAULT_TRACKING_METHOD),
                ): vol.In(TRACKING_METHODS),
                vol.Optional(
                    CONF_ENABLE_SYSTEM_SENSORS,
                    default=current_data.get(CONF_ENABLE_SYSTEM_SENSORS, DEFAULT_ENABLE_SYSTEM_SENSORS),
                ): bool,
                vol.Optional(
                    CONF_ENABLE_QMODEM_SENSORS,
                    default=current_data.get(CONF_ENABLE_QMODEM_SENSORS, DEFAULT_ENABLE_QMODEM_SENSORS),
                ): bool,
                vol.Optional(
                    CONF_ENABLE_STA_SENSORS,
                    default=current_data.get(CONF_ENABLE_STA_SENSORS, DEFAULT_ENABLE_STA_SENSORS),
                ): bool,
                vol.Optional(
                    CONF_SELECT_ALL_STA,
                    default=current_data.get(CONF_SELECT_ALL_STA, DEFAULT_SELECT_ALL_STA),
                ): bool,
                vol.Optional(
                    CONF_ENABLE_AP_SENSORS,
                    default=current_data.get(CONF_ENABLE_AP_SENSORS, DEFAULT_ENABLE_AP_SENSORS),
                ): bool,
                vol.Optional(
                    CONF_ENABLE_ETH_SENSORS,
                    default=current_data.get(CONF_ENABLE_ETH_SENSORS, DEFAULT_ENABLE_ETH_SENSORS),
                ): bool,
                vol.Optional(
                    CONF_ENABLE_MWAN3_SENSORS,
                    default=current_data.get(CONF_ENABLE_MWAN3_SENSORS, DEFAULT_ENABLE_MWAN3_SENSORS),
                ): bool,
                vol.Optional(
                    CONF_ENABLE_SERVICE_CONTROLS,
                    default=current_data.get(CONF_ENABLE_SERVICE_CONTROLS, DEFAULT_ENABLE_SERVICE_CONTROLS),
                ): bool,
                vol.Optional(
                    CONF_ENABLE_DEVICE_KICK_BUTTONS,
                    default=current_data.get(
                        CONF_ENABLE_DEVICE_KICK_BUTTONS,
                        DEFAULT_ENABLE_DEVICE_KICK_BUTTONS,
                    ),
                ): bool,
                 vol.Optional(
                     CONF_ENABLE_WIRELESS_TRACKERS,
                     default=current_data.get(CONF_ENABLE_WIRELESS_TRACKERS, DEFAULT_ENABLE_WIRELESS_TRACKERS),
                 ): bool,
                 vol.Optional(
                     CONF_WIRELESS_TRACKER_WHITELIST,
                     description={"suggested_value": ",".join(current_data.get(CONF_WIRELESS_TRACKER_WHITELIST, []))},
                 ): str,
                 vol.Optional(
                     CONF_ENABLE_WIRED_TRACKER,
                     default=current_data.get(CONF_ENABLE_WIRED_TRACKER, DEFAULT_ENABLE_WIRED_TRACKER),
                 ): bool,

                vol.Optional(
                    CONF_WIRED_TRACKER_NAME_PRIORITY,
                    default=current_data.get(CONF_WIRED_TRACKER_NAME_PRIORITY, DEFAULT_WIRED_TRACKER_NAME_PRIORITY),
                ): vol.In(["ipv4", "ipv6", "mac"]),
                vol.Optional(
                    CONF_WIRED_TRACKER_WHITELIST,
                    description={"suggested_value": ",".join(current_data.get(CONF_WIRED_TRACKER_WHITELIST, []))},
                ): str,
                vol.Optional(
                    CONF_WIRED_TRACKER_INTERFACES,
                    description={"suggested_value": ",".join(current_data.get(CONF_WIRED_TRACKER_INTERFACES, []))},
                ): str,
                vol.Optional(
                    CONF_SYSTEM_SENSOR_TIMEOUT,
                    default=current_data.get(CONF_SYSTEM_SENSOR_TIMEOUT, DEFAULT_SYSTEM_SENSOR_TIMEOUT),
                ): vol.All(vol.Coerce(int), vol.Range(min=10, max=300)),
                vol.Optional(
                    CONF_QMODEM_SENSOR_TIMEOUT,
                    default=current_data.get(CONF_QMODEM_SENSOR_TIMEOUT, DEFAULT_QMODEM_SENSOR_TIMEOUT),
                ): vol.All(vol.Coerce(int), vol.Range(min=30, max=600)),
                vol.Optional(
                    CONF_STA_SENSOR_TIMEOUT,
                    default=current_data.get(CONF_STA_SENSOR_TIMEOUT, DEFAULT_STA_SENSOR_TIMEOUT),
                ): vol.All(vol.Coerce(int), vol.Range(min=10, max=300)),
                vol.Optional(
                    CONF_AP_SENSOR_TIMEOUT,
                    default=current_data.get(CONF_AP_SENSOR_TIMEOUT, DEFAULT_AP_SENSOR_TIMEOUT),
                ): vol.All(vol.Coerce(int), vol.Range(min=30, max=600)),
                vol.Optional(
                    CONF_MWAN3_SENSOR_TIMEOUT,
                    default=current_data.get(CONF_MWAN3_SENSOR_TIMEOUT, DEFAULT_MWAN3_SENSOR_TIMEOUT),
                ): vol.All(vol.Coerce(int), vol.Range(min=30, max=600)),
                vol.Optional(
                    CONF_CONSIDER_HOME,
                    default=current_data.get(CONF_CONSIDER_HOME, DEFAULT_CONSIDER_HOME),
                ): vol.All(vol.Coerce(int), vol.Range(min=0, max=1800)),
                vol.Optional("refresh_services", default=False): bool,
            }
        )

        return self.async_show_form(
            step_id="init",
            data_schema=options_schema,
            description_placeholders={"host": self.config_entry.data[CONF_HOST]},
        )

    async def async_step_services(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Handle services configuration."""
        errors: dict[str, str] = {}

        if user_input is not None:
            # Update config with selected services
            new_data = dict(self.config_entry.data)
            new_data.update(user_input)

            # Update the config entry
            self.hass.config_entries.async_update_entry(self.config_entry, data=new_data)

            # Reload the integration
            await self.hass.config_entries.async_reload(self.config_entry.entry_id)

            return self.async_create_entry(title="", data={})

        # Get available services
        if not self._available_services:
            try:
                self._available_services = await get_services_list(self.hass, self.config_entry.data)
            except Exception as exc:
                _LOGGER.warning("Failed to get services list: %s", exc)
                errors["base"] = "cannot_get_services"

        if not self._available_services and not errors:
            errors["base"] = "no_services_found"

        # Create multi-select schema for services
        current_services = self.config_entry.data.get(CONF_SELECTED_SERVICES, [])
        services_schema = vol.Schema({})
        if self._available_services:
            services_schema = vol.Schema(
                {
                    vol.Optional(CONF_SELECTED_SERVICES, default=current_services): cv.multi_select(
                        {service: service for service in self._available_services}
                    ),
                }
            )

        return self.async_show_form(
            step_id="services",
            data_schema=services_schema,
            errors=errors,
            description_placeholders={
                "host": self.config_entry.data[CONF_HOST],
                "services_count": str(len(self._available_services)) if self._available_services else "0",
            },
        )

    async def async_step_sta_sensors_config(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Handle station sensors device selection in the options flow."""
        if user_input is not None:
            config_data = {**self._temp_data, **user_input}
            return await self._update_and_reload(config_data)

        # Fetch currently connected devices
        if not self._available_sta_devices:
            self._available_sta_devices = await get_connected_wifi_devices(self.hass, self.config_entry.data)

        # Include previously selected offline devices so they can be toggled off
        current_selected = self.config_entry.data.get(CONF_SELECTED_STA, [])
        for mac in current_selected:
            if mac not in self._available_sta_devices:
                self._available_sta_devices[mac] = f"Offline Device ({mac})"

        current_data = self.config_entry.data
        sta_sensors_schema = vol.Schema(
            {
                vol.Required(
                    CONF_SELECT_ALL_STA,
                    default=current_data.get(CONF_SELECT_ALL_STA, DEFAULT_SELECT_ALL_STA),
                ): cv.boolean,
                vol.Optional(
                    CONF_SELECTED_STA,
                    default=current_selected,
                ): cv.multi_select({mac: name for mac, name in self._available_sta_devices.items()}),
            }
        )

        return self.async_show_form(
            step_id="sta_sensors_config",
            data_schema=sta_sensors_schema,
            description_placeholders={"host": self.config_entry.data[CONF_HOST]},
        )

    async def _update_and_reload(self, user_input: dict[str, Any]) -> ConfigFlowResult:
        """Persist options and reload the integration."""
        new_data = dict(self.config_entry.data)
        new_data.update(user_input)
        self.hass.config_entries.async_update_entry(self.config_entry, data=new_data)
        await self.hass.config_entries.async_reload(self.config_entry.entry_id)
        return self.async_create_entry(title="", data={})


class CannotConnect(HomeAssistantError):
    """Error to indicate we cannot connect."""


class InvalidAuth(HomeAssistantError):
    """Error to indicate there is invalid auth."""
