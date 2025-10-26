"""Config flow for openwrt ubus integration."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult, OptionsFlow, ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers import config_validation as cv

from .const import (
    CONF_DHCP_SOFTWARE,
    CONF_WIRELESS_SOFTWARE,
    CONF_USE_HTTPS,
    CONF_VERIFY_SSL,
    CONF_CERT_PATH,
    CONF_ENABLE_QMODEM_SENSORS,
    CONF_ENABLE_STA_SENSORS,
    CONF_ENABLE_SYSTEM_SENSORS,
    CONF_ENABLE_AP_SENSORS,
    CONF_ENABLE_ETH_SENSORS,
    CONF_ENABLE_SERVICE_CONTROLS,
    CONF_ENABLE_DEVICE_KICK_BUTTONS,
    CONF_SELECTED_SERVICES,
    CONF_SYSTEM_SENSOR_TIMEOUT,
    CONF_QMODEM_SENSOR_TIMEOUT,
    CONF_STA_SENSOR_TIMEOUT,
    CONF_AP_SENSOR_TIMEOUT,
    CONF_SERVICE_TIMEOUT,
    DEFAULT_DHCP_SOFTWARE,
    DEFAULT_WIRELESS_SOFTWARE,
    DEFAULT_USE_HTTPS,
    DEFAULT_VERIFY_SSL,
    DEFAULT_ENABLE_QMODEM_SENSORS,
    DEFAULT_ENABLE_STA_SENSORS,
    DEFAULT_ENABLE_SYSTEM_SENSORS,
    DEFAULT_ENABLE_AP_SENSORS,
    DEFAULT_ENABLE_ETH_SENSORS,
    DEFAULT_ENABLE_SERVICE_CONTROLS,
    DEFAULT_ENABLE_DEVICE_KICK_BUTTONS,
    DEFAULT_SELECTED_SERVICES,
    DEFAULT_SYSTEM_SENSOR_TIMEOUT,
    DEFAULT_QMODEM_SENSOR_TIMEOUT,
    DEFAULT_STA_SENSOR_TIMEOUT,
    DEFAULT_AP_SENSOR_TIMEOUT,
    DEFAULT_SERVICE_TIMEOUT,
    DHCP_SOFTWARES,
    DOMAIN,
    WIRELESS_SOFTWARES,
    API_SUBSYS_RC,
    API_METHOD_LIST,
)
from .Ubus import Ubus
from .Ubus.const import API_RPC_CALL
from .ubus_client import create_enhanced_ubus_client
from .security_utils import safe_log_data

_LOGGER = logging.getLogger(__name__)

# Step 1: Connection configuration
STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_HOST): str,
        vol.Required(CONF_USERNAME): str,
        vol.Required(CONF_PASSWORD): str,
        vol.Optional(CONF_USE_HTTPS, default=DEFAULT_USE_HTTPS): bool,
        vol.Optional(CONF_VERIFY_SSL, default=DEFAULT_VERIFY_SSL): bool,
        vol.Optional(CONF_CERT_PATH): str,
        vol.Optional(CONF_WIRELESS_SOFTWARE, default=DEFAULT_WIRELESS_SOFTWARE): vol.In(
            WIRELESS_SOFTWARES
        ),
        vol.Optional(CONF_DHCP_SOFTWARE, default=DEFAULT_DHCP_SOFTWARE): vol.In(
            DHCP_SOFTWARES
        ),
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
        vol.Optional(CONF_ENABLE_SERVICE_CONTROLS, default=DEFAULT_ENABLE_SERVICE_CONTROLS): bool,
        vol.Optional(CONF_ENABLE_DEVICE_KICK_BUTTONS, default=DEFAULT_ENABLE_DEVICE_KICK_BUTTONS): bool,
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
        vol.Optional(CONF_SERVICE_TIMEOUT, default=DEFAULT_SERVICE_TIMEOUT): vol.All(
            vol.Coerce(int), vol.Range(min=10, max=300)
        ),
    }
)


async def validate_input(hass: HomeAssistant, data: dict[str, Any]) -> dict[str, Any]:
    """Validate the user input allows us to connect.

    Data has the keys from STEP_USER_DATA_SCHEMA with values provided by the user.
    """
    # Get Home Assistant's HTTP client session
    session = async_get_clientsession(hass)

    # Build URL with proper protocol and explicit port to avoid HTTPS redirection
    protocol = "https" if data.get(CONF_USE_HTTPS, DEFAULT_USE_HTTPS) else "http"
    port = "443" if protocol == "https" else "80"
    url = f"{protocol}://{data[CONF_HOST]}:{port}/ubus"

    # Configure SSL verification
    verify_ssl = data.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL)
    cert_path = data.get(CONF_CERT_PATH)

    # Debug configuration values - inline implementation
    use_https_raw = data.get(CONF_USE_HTTPS)
    _LOGGER.info("Configuration Debug [validate_input]:")
    _LOGGER.info("  Raw CONF_USE_HTTPS value: %s", use_https_raw)
    _LOGGER.info("  DEFAULT_USE_HTTPS: %s", DEFAULT_USE_HTTPS)
    _LOGGER.info("  Computed use_https: %s", use_https_raw)
    _LOGGER.info("  Computed protocol: %s", protocol)

    # Debug logging for URL construction
    _LOGGER.debug("Connection details: CONF_USE_HTTPS=%s (default: %s), computed protocol=%s, port=%s, URL=%s",
                 use_https_raw, DEFAULT_USE_HTTPS, protocol, port, url)
    _LOGGER.debug("SSL settings: verify_ssl=%s (default: %s), cert_path=%s",
                 verify_ssl, DEFAULT_VERIFY_SSL, cert_path)
    _LOGGER.info("Attempting connection to OpenWrt device at %s with protocol %s", data[CONF_HOST], protocol)

    # If using HTTPS with unverified SSL, warn user
    if protocol == "https" and not verify_ssl:
        _LOGGER.warning("HTTPS enabled with SSL verification disabled - this is insecure but necessary for unsigned certificates")

    safe_log_data(data, "debug", "Attempting connection with these parameters (credentials redacted)")

    ubus = create_enhanced_ubus_client(
        url,
        data[CONF_USERNAME],
        data[CONF_PASSWORD],
        session=session,
        verify_ssl=verify_ssl,
        cert_file=cert_path
    )

    try:
        # Test connection
        _LOGGER.info("Attempting to connect to %s://%s with user %s", protocol, data[CONF_HOST], data[CONF_USERNAME])
        _LOGGER.info("Full connection URL: %s", url)
        _LOGGER.info("SSL settings: verify_ssl=%s, cert_path=%s", verify_ssl, cert_path)

        session_id = await ubus.connect()

        if session_id is None:
            _LOGGER.error("=== CONNECTION FAILURE DETAILS ===")
            _LOGGER.error("Device: %s://%s", protocol, data[CONF_HOST])
            _LOGGER.error("Username: %s", data[CONF_USERNAME])
            _LOGGER.error("SSL Verification: %s", verify_ssl)
            _LOGGER.error("Certificate Path: %s", cert_path)
            _LOGGER.error("Session ID returned: %s", session_id)
            _LOGGER.error("Possible causes:")
            _LOGGER.error("1. Wrong username/password")
            _LOGGER.error("2. User lacks ubus API permissions")
            _LOGGER.error("3. ubus service not running on device")
            _LOGGER.error("4. Network firewall blocking connection")
            _LOGGER.error("5. SSL/TLS handshake failure (if HTTPS)")
            _LOGGER.error("6. Device running different OpenWrt version")
            _LOGGER.error("=== END FAILURE DETAILS ===")
            raise CannotConnect("Failed to connect to OpenWrt device - session_id is None")

        _LOGGER.info("Successfully connected to OpenWrt device at %s://%s", protocol, data[CONF_HOST])
        _LOGGER.debug("Received session_id: %s", session_id)

    except ConnectionRefusedError as exc:
        _LOGGER.error("Connection refused: OpenWrt device at %s is not accepting connections", data[CONF_HOST])
        raise CannotConnect(f"Connection refused - check if OpenWrt device is running and accessible") from exc
    except asyncio.TimeoutError as exc:
        _LOGGER.error("Connection timeout: OpenWrt device at %s did not respond in time", data[CONF_HOST])
        raise CannotConnect("Connection timeout - check network connectivity") from exc
    except PermissionError as exc:
        _LOGGER.error("Authentication failed: Invalid credentials for %s on %s", data[CONF_USERNAME], data[CONF_HOST])
        raise CannotConnect("Authentication failed - check username and password") from exc
    except Exception as exc:
        _LOGGER.exception("Unexpected exception during connection test: %s", str(exc))
        _LOGGER.error("Connection details - Protocol: %s, Host: %s, Username: %s, Verify SSL: %s, Cert Path: %s",
                     protocol, data[CONF_HOST], data[CONF_USERNAME], verify_ssl, cert_path)
        _LOGGER.error("Exception type: %s, Exception message: %s", type(exc).__name__, str(exc))
        raise CannotConnect(f"Failed to connect to OpenWrt device: {str(exc)}") from exc
    finally:
        # Always close the session to prevent leaks
        await ubus.close()

    # Return info that you want to store in the config entry.
    return {"title": f"OpenWrt ubus {data[CONF_HOST]}"}


async def get_services_list(hass: HomeAssistant, data: dict[str, Any]) -> list[str]:
    """Get list of available services from OpenWrt."""
    session = async_get_clientsession(hass)

    # Build URL with proper protocol and explicit port to avoid HTTPS redirection
    protocol = "https" if data.get(CONF_USE_HTTPS, DEFAULT_USE_HTTPS) else "http"
    port = "443" if protocol == "https" else "80"
    url = f"{protocol}://{data[CONF_HOST]}:{port}/ubus"

    # Configure SSL verification
    verify_ssl = data.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL)
    cert_path = data.get(CONF_CERT_PATH)

    # Debug logging for services list
    _LOGGER.debug("Services list - Connection details: CONF_USE_HTTPS=%s (default: %s), computed protocol=%s, port=%s, URL=%s",
                 data.get(CONF_USE_HTTPS), DEFAULT_USE_HTTPS, protocol, port, url)

    # If using HTTPS with unverified SSL, warn user
    if protocol == "https" and not verify_ssl:
        _LOGGER.warning("HTTPS enabled with SSL verification disabled - this is insecure but necessary for unsigned certificates")

    ubus = create_enhanced_ubus_client(
        url,
        data[CONF_USERNAME],
        data[CONF_PASSWORD],
        session=session,
        verify_ssl=verify_ssl,
        cert_file=cert_path
    )
    
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


class OpenwrtUbusConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for openwrt ubus."""

    VERSION = 1

    def __init__(self) -> None:
        """Initialize the config flow."""
        self._connection_data: dict[str, Any] = {}
        self._sensor_data: dict[str, Any] = {}
        self._services_data: dict[str, Any] = {}
        self._available_services: list[str] = []

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        """Create the options flow."""
        return OpenwrtUbusOptionsFlow(config_entry)

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
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

        return self.async_show_form(
            step_id="user", data_schema=STEP_USER_DATA_SCHEMA, errors=errors
        )

    async def async_step_sensors(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the sensor configuration step."""
        if user_input is not None:
            self._sensor_data = user_input
            
            # If service controls are enabled, proceed to services selection
            if user_input.get(CONF_ENABLE_SERVICE_CONTROLS, False):
                return await self.async_step_services()
            
            return await self.async_step_timeouts()

        return self.async_show_form(
            step_id="sensors",
            data_schema=STEP_SENSORS_DATA_SCHEMA,
            description_placeholders={
                "host": self._connection_data[CONF_HOST]
            }
        )

    async def async_step_services(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
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
            services_schema = vol.Schema({
                vol.Optional(CONF_SELECTED_SERVICES, default=[]): cv.multi_select(
                    {service: service for service in self._available_services}
                ),
            })
        
        return self.async_show_form(
            step_id="services",
            data_schema=services_schema,
            errors=errors,
            description_placeholders={
                "host": self._connection_data[CONF_HOST],
                "services_count": str(len(self._available_services)) if self._available_services else "0"
            }
        )

    async def async_step_timeouts(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the timeout configuration step."""
        if user_input is not None:
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
            description_placeholders={
                "host": self._connection_data[CONF_HOST]
            }
        )


class OpenwrtUbusOptionsFlow(OptionsFlow):
    """Handle options flow for OpenWrt ubus."""

    def __init__(self, config_entry: ConfigEntry) -> None:
        """Initialize options flow."""
        super().__init__()
        self._available_services: list[str] = []

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Manage the options."""
        if user_input is not None:
            # Check if we need to refresh services
            if user_input.get("refresh_services", False):
                return await self.async_step_services()
            
            # Get current data and merge with new options
            new_data = dict(self.config_entry.data)
            new_data.update(user_input)
            
            # Update the config entry with new data
            self.hass.config_entries.async_update_entry(
                self.config_entry, data=new_data
            )
            
            # Reload the integration to apply changes
            await self.hass.config_entries.async_reload(self.config_entry.entry_id)
            
            return self.async_create_entry(title="", data={})

        # Create form with all configurable options
        current_data = self.config_entry.data
        options_schema = vol.Schema(
            {
                vol.Optional(
                    CONF_WIRELESS_SOFTWARE,
                    default=current_data.get(CONF_WIRELESS_SOFTWARE, DEFAULT_WIRELESS_SOFTWARE)
                ): vol.In(WIRELESS_SOFTWARES),
                vol.Optional(
                    CONF_DHCP_SOFTWARE,
                    default=current_data.get(CONF_DHCP_SOFTWARE, DEFAULT_DHCP_SOFTWARE)
                ): vol.In(DHCP_SOFTWARES),
                vol.Optional(
                    CONF_ENABLE_SYSTEM_SENSORS,
                    default=current_data.get(CONF_ENABLE_SYSTEM_SENSORS, DEFAULT_ENABLE_SYSTEM_SENSORS)
                ): bool,
                vol.Optional(
                    CONF_ENABLE_QMODEM_SENSORS,
                    default=current_data.get(CONF_ENABLE_QMODEM_SENSORS, DEFAULT_ENABLE_QMODEM_SENSORS)
                ): bool,
                vol.Optional(
                    CONF_ENABLE_STA_SENSORS,
                    default=current_data.get(CONF_ENABLE_STA_SENSORS, DEFAULT_ENABLE_STA_SENSORS)
                ): bool,
                vol.Optional(
                    CONF_ENABLE_AP_SENSORS,
                    default=current_data.get(CONF_ENABLE_AP_SENSORS, DEFAULT_ENABLE_AP_SENSORS)
                ): bool,
                vol.Optional(
                    CONF_ENABLE_ETH_SENSORS,
                    default=current_data.get(CONF_ENABLE_ETH_SENSORS, DEFAULT_ENABLE_ETH_SENSORS)
                ): bool,
                vol.Optional(
                    CONF_ENABLE_SERVICE_CONTROLS,
                    default=current_data.get(CONF_ENABLE_SERVICE_CONTROLS, DEFAULT_ENABLE_SERVICE_CONTROLS)
                ): bool,
                vol.Optional(
                    CONF_ENABLE_DEVICE_KICK_BUTTONS,
                    default=current_data.get(CONF_ENABLE_DEVICE_KICK_BUTTONS, DEFAULT_ENABLE_DEVICE_KICK_BUTTONS)
                ): bool,
                vol.Optional(
                    CONF_SYSTEM_SENSOR_TIMEOUT,
                    default=current_data.get(CONF_SYSTEM_SENSOR_TIMEOUT, DEFAULT_SYSTEM_SENSOR_TIMEOUT)
                ): vol.All(vol.Coerce(int), vol.Range(min=10, max=300)),
                vol.Optional(
                    CONF_QMODEM_SENSOR_TIMEOUT,
                    default=current_data.get(CONF_QMODEM_SENSOR_TIMEOUT, DEFAULT_QMODEM_SENSOR_TIMEOUT)
                ): vol.All(vol.Coerce(int), vol.Range(min=30, max=600)),
                vol.Optional(
                    CONF_STA_SENSOR_TIMEOUT,
                    default=current_data.get(CONF_STA_SENSOR_TIMEOUT, DEFAULT_STA_SENSOR_TIMEOUT)
                ): vol.All(vol.Coerce(int), vol.Range(min=10, max=300)),
                vol.Optional(
                    CONF_AP_SENSOR_TIMEOUT,
                    default=current_data.get(CONF_AP_SENSOR_TIMEOUT, DEFAULT_AP_SENSOR_TIMEOUT)
                ): vol.All(vol.Coerce(int), vol.Range(min=30, max=600)),
                vol.Optional("refresh_services", default=False): bool,
            }
        )

        return self.async_show_form(
            step_id="init",
            data_schema=options_schema,
            description_placeholders={
                "host": self.config_entry.data[CONF_HOST]
            }
        )

    async def async_step_services(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle services configuration."""
        errors: dict[str, str] = {}
        
        if user_input is not None:
            # Update config with selected services
            new_data = dict(self.config_entry.data)
            new_data.update(user_input)
            
            # Update the config entry
            self.hass.config_entries.async_update_entry(
                self.config_entry, data=new_data
            )
            
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
            services_schema = vol.Schema({
                vol.Optional(CONF_SELECTED_SERVICES, default=current_services): cv.multi_select(
                    {service: service for service in self._available_services}
                ),
            })
        
        return self.async_show_form(
            step_id="services",
            data_schema=services_schema,
            errors=errors,
            description_placeholders={
                "host": self.config_entry.data[CONF_HOST],
                "services_count": str(len(self._available_services)) if self._available_services else "0"
            }
        )


class CannotConnect(HomeAssistantError):
    """Error to indicate we cannot connect."""


class InvalidAuth(HomeAssistantError):
    """Error to indicate there is invalid auth."""
