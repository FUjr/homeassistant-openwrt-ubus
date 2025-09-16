"""Shared data manager for OpenWrt ubus API calls to reduce router load."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from functools import wraps
import logging
from typing import Any, Dict, Optional

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .extended_ubus import ExtendedUbus
from .const import (
    CONF_DHCP_SOFTWARE, 
    CONF_WIRELESS_SOFTWARE, 
    CONF_SYSTEM_SENSOR_TIMEOUT,
    CONF_QMODEM_SENSOR_TIMEOUT,
    CONF_STA_SENSOR_TIMEOUT,
    CONF_AP_SENSOR_TIMEOUT,
    CONF_SERVICE_TIMEOUT,
    DOMAIN, 
    DEFAULT_DHCP_SOFTWARE, 
    DEFAULT_WIRELESS_SOFTWARE,
    DEFAULT_SYSTEM_SENSOR_TIMEOUT,
    DEFAULT_QMODEM_SENSOR_TIMEOUT,
    DEFAULT_STA_SENSOR_TIMEOUT,
    DEFAULT_AP_SENSOR_TIMEOUT,
    DEFAULT_SERVICE_TIMEOUT,
)

_LOGGER = logging.getLogger(__name__)


def ubus_auto_reconnect(max_retries: int = 1):
    """Decorator to handle permission denied errors and auto-reconnect ubus client.
    
    Args:
        max_retries: Maximum number of reconnection attempts (default: 1)
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(self, *args, **kwargs):
            retries = 0
            while retries <= max_retries:
                try:
                    return await func(self, *args, **kwargs)
                except PermissionError as exc:
                    if "Access denied" in str(exc) and retries < max_retries:
                        _LOGGER.warning(
                            "Permission denied in %s, attempting to reconnect (attempt %d/%d)", 
                            func.__name__, retries + 1, max_retries + 1
                        )
                        
                        # Clear all ubus clients to force reconnection
                        for client_type, client in self._ubus_clients.items():
                            try:
                                await client.close()
                                _LOGGER.debug("Closed ubus client: %s", client_type)
                            except Exception as close_exc:
                                _LOGGER.debug("Error closing ubus client %s: %s", client_type, close_exc)
                        
                        self._ubus_clients.clear()
                        _LOGGER.info("Cleared all ubus clients, will reconnect on next call")
                        
                        retries += 1
                        if retries <= max_retries:
                            # Small delay before retry
                            await asyncio.sleep(0.5)
                            continue
                    
                    # If we've exhausted retries or it's not an access denied error, re-raise
                    _LOGGER.error("Permission denied in %s after %d retries", func.__name__, retries)
                    raise
                except Exception as exc:
                    # For non-permission errors, don't retry
                    raise
            
            # This should never be reached, but just in case
            raise RuntimeError(f"Unexpected state in {func.__name__} after {retries} retries")
        return wrapper
    return decorator


class SharedUbusDataManager:
    """Shared data manager for ubus API calls to reduce router load."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry):
        """Initialize the shared data manager."""
        self.hass = hass
        self.entry = entry
        self._data_cache: Dict[str, Dict[str, Any]] = {}
        self._last_update: Dict[str, datetime] = {}
        
        # Get timeout values from configuration (priority: options > data > default)
        system_timeout = entry.options.get(
            CONF_SYSTEM_SENSOR_TIMEOUT,
            entry.data.get(CONF_SYSTEM_SENSOR_TIMEOUT, DEFAULT_SYSTEM_SENSOR_TIMEOUT)
        )
        qmodem_timeout = entry.options.get(
            CONF_QMODEM_SENSOR_TIMEOUT,
            entry.data.get(CONF_QMODEM_SENSOR_TIMEOUT, DEFAULT_QMODEM_SENSOR_TIMEOUT)
        )
        sta_timeout = entry.options.get(
            CONF_STA_SENSOR_TIMEOUT,
            entry.data.get(CONF_STA_SENSOR_TIMEOUT, DEFAULT_STA_SENSOR_TIMEOUT)
        )
        ap_timeout = entry.options.get(
            CONF_AP_SENSOR_TIMEOUT,
            entry.data.get(CONF_AP_SENSOR_TIMEOUT, DEFAULT_AP_SENSOR_TIMEOUT)
        )
        service_timeout = entry.options.get(
            CONF_SERVICE_TIMEOUT,
            entry.data.get(CONF_SERVICE_TIMEOUT, DEFAULT_SERVICE_TIMEOUT)
        )
        
        self._update_intervals: Dict[str, timedelta] = {
            "system_info": timedelta(seconds=system_timeout),
            "system_board": timedelta(seconds=system_timeout * 2),  # Board info changes less frequently
            "qmodem_info": timedelta(seconds=qmodem_timeout),
            "device_statistics": timedelta(seconds=sta_timeout),
            "dhcp_leases": timedelta(seconds=sta_timeout),
            "hostapd_clients": timedelta(seconds=sta_timeout),
            "iwinfo_stations": timedelta(seconds=sta_timeout),
            "ap_info": timedelta(seconds=ap_timeout),
            "service_status": timedelta(seconds=service_timeout),  # Use configured service timeout
            "hostapd_available": timedelta(minutes=30),  # Very long cache - hostapd availability rarely changes
            "conntrack_count": timedelta(seconds=system_timeout),  # Connection tracking count
            "system_temperatures": timedelta(seconds=system_timeout),  # System temperature sensors
            "dhcp_clients_count": timedelta(seconds=sta_timeout),  # DHCP clients count
        }
        self._update_locks: Dict[str, asyncio.Lock] = {
            key: asyncio.Lock() for key in self._update_intervals
        }
        
        # Initialize ubus clients
        self._ubus_clients: Dict[str, ExtendedUbus] = {}
        self._session = None
        
    async def _get_ubus_client(self, client_type: str = "default") -> ExtendedUbus:
        """Get or create ubus client instance."""
        if client_type not in self._ubus_clients:
            if self._session is None:
                self._session = async_get_clientsession(self.hass)
            
            url = f"http://{self.entry.data[CONF_HOST]}/ubus"
            username = self.entry.data[CONF_USERNAME]
            password = self.entry.data[CONF_PASSWORD]
            
            # Use ExtendedUbus for all client types now
            client = ExtendedUbus(url, username, password, session=self._session)
            
            # Connect to the client
            try:
                session_id = await client.connect()
                if session_id is None:
                    raise UpdateFailed(f"Failed to connect to OpenWrt device")
                self._ubus_clients[client_type] = client
            except Exception as exc:
                _LOGGER.error("Failed to connect ubus client %s: %s", client_type, exc)
                raise UpdateFailed(f"Failed to connect ubus client {client_type}: {exc}")
                
        return self._ubus_clients[client_type]

    def get_ubus_connection(self) -> ExtendedUbus:
        """Get an existing ubus connection for external use."""
        # Return the default client if available, otherwise create one
        if "default" in self._ubus_clients:
            return self._ubus_clients["default"]
        
        # If no client exists, we need to create one synchronously
        # This is for cases where switch/button entities need immediate access
        # Note: This should ideally be called after the data manager has been initialized
        raise RuntimeError("No ubus client available. Data manager not initialized.")

    async def get_ubus_connection_async(self) -> ExtendedUbus:
        """Get or create a ubus connection asynchronously."""
        return await self._get_ubus_client("default")

    async def _should_update(self, data_type: str) -> bool:
        """Check if data should be updated based on interval."""
        if data_type not in self._last_update:
            return True
        
        interval = self._update_intervals.get(data_type, timedelta(minutes=1))
        return datetime.now() - self._last_update[data_type] > interval

    @ubus_auto_reconnect(max_retries=1)
    async def _fetch_system_info(self) -> Dict[str, Any]:
        """Fetch system information."""
        client = await self._get_ubus_client()
        try:
            system_info = await client.system_info()
            return {"system_info": system_info}
        except Exception as exc:
            _LOGGER.error("Error fetching system info: %s", exc)
            raise UpdateFailed(f"Error fetching system info: {exc}")

    @ubus_auto_reconnect(max_retries=1)
    async def _fetch_system_board(self) -> Dict[str, Any]:
        """Fetch system board information."""
        client = await self._get_ubus_client()
        try:
            board_info = await client.system_board()
            return {"system_board": board_info}
        except Exception as exc:
            _LOGGER.error("Error fetching system board: %s", exc)
            raise UpdateFailed(f"Error fetching system board: {exc}")

    @ubus_auto_reconnect(max_retries=1)
    async def _fetch_qmodem_info(self) -> Dict[str, Any]:
        """Fetch QModem information if available."""
        client = await self._get_ubus_client("qmodem")
        try:
            qmodem_info = await client.get_qmodem_info()
            _LOGGER.debug("QModem data fetched successfully")
            return {"qmodem_info": qmodem_info}
        except Exception as exc:
            _LOGGER.debug("Error fetching QModem info: %s", exc)
            return {"qmodem_info": None}

    @ubus_auto_reconnect(max_retries=1)
    async def _fetch_hostapd_available(self) -> Dict[str, Any]:
        """Check if hostapd is available via ubus list."""
        client = await self._get_ubus_client()
        try:
            hostapd_available = await client.check_hostapd_available()
            _LOGGER.debug("Hostapd availability check: %s", hostapd_available)
            return {"hostapd_available": hostapd_available}
        except Exception as exc:
            _LOGGER.debug("Error checking hostapd availability: %s", exc)
            return {"hostapd_available": False}

    @ubus_auto_reconnect(max_retries=1)
    async def _fetch_ap_info(self) -> Dict[str, Any]:
        """Fetch access point information."""
        client = await self._get_ubus_client("ap")
        try:
            # First get list of AP devices
            ap_devices_result = await client.get_ap_devices()
            ap_devices = client.parse_ap_devices(ap_devices_result)
            
            # Use batch API to get AP info for all devices
            ap_info_data = await client.get_all_ap_info_batch(ap_devices)
            
            _LOGGER.debug("AP info data fetched successfully: %d devices", len(ap_info_data))
            return {"ap_info": ap_info_data}
        except Exception as exc:
            _LOGGER.debug("Error fetching AP info: %s", exc)
            return {"ap_info": {}}

    @ubus_auto_reconnect(max_retries=1)
    async def _fetch_service_status(self) -> dict:
        """Fetch service status using batch API."""
        try:
            ubus = await self.get_ubus_connection_async()
            
            # Get services with status in batch call to reduce API requests
            services_data = await ubus.list_services(include_status=True)
            
            if not services_data:
                _LOGGER.warning("Failed to fetch service status data")
                return {}
            
            _LOGGER.debug("Fetched service status for %d services", len(services_data))
            
            # Log a sample of the service data for debugging
            if services_data:
                sample_service = next(iter(services_data.items()))
                _LOGGER.debug("Sample service data: %s = %s", sample_service[0], sample_service[1])
                
            return services_data
            
        except Exception as exc:
            _LOGGER.error("Error fetching service status: %s", exc)
            raise UpdateFailed(f"Error communicating with OpenWrt: {exc}") from exc

    @ubus_auto_reconnect(max_retries=1)
    async def _fetch_device_statistics(self) -> Dict[str, Any]:
        """Fetch device statistics from wireless interfaces."""
        wireless_software = self.entry.data.get(CONF_WIRELESS_SOFTWARE, "iwinfo")
        dhcp_software = self.entry.data.get(CONF_DHCP_SOFTWARE, "dnsmasq")
        
        try:
            # Get MAC to name/IP mapping first
            mac2name = await self._get_mac2name_mapping(dhcp_software)
            
            # Get device statistics and connection info
            if wireless_software == "hostapd":
                return await self._fetch_hostapd_data(mac2name)
            elif wireless_software == "iwinfo":
                return await self._fetch_iwinfo_data(mac2name)
            else:
                return {}
        except Exception as exc:
            _LOGGER.error("Error fetching device statistics: %s", exc)
            raise UpdateFailed(f"Error fetching device statistics: {exc}")

    @ubus_auto_reconnect(max_retries=1)
    async def _fetch_hostapd_data(self, mac2name: Dict[str, Dict[str, str]]) -> Dict[str, Any]:
        """Fetch data from hostapd using optimized batch calls."""
        client = await self._get_ubus_client("hostapd")
        try:
            # Get AP devices
            ap_devices_result = await client.get_hostapd()
            ap_devices = client.parse_hostapd_ap_devices(ap_devices_result) if ap_devices_result else []
            
            device_statistics = {}
            
            # Use batch call to get STA data for all AP devices at once
            sta_data_batch = await client.get_all_sta_data_batch(ap_devices, is_hostapd=True)
            
            for ap_device in ap_devices:
                if ap_device not in sta_data_batch:
                    continue
                    
                sta_devices = sta_data_batch[ap_device].get('devices', [])
                sta_stats = sta_data_batch[ap_device].get('statistics', {})
                
                for mac in sta_devices:
                    normalized_mac = mac.upper()
                    hostname = mac2name.get(normalized_mac, {}).get("hostname", normalized_mac.replace(":", ""))
                    ip_address = mac2name.get(normalized_mac, {}).get("ip", "Unknown IP")
                    
                    # Merge connection info with detailed statistics
                    device_info = {
                        "mac": normalized_mac,
                        "hostname": hostname,
                        "ap_device": ap_device,
                        "connected": True,
                        "ip_address": ip_address,
                    }
                    
                    # Add statistics if available
                    if normalized_mac in sta_stats:
                        device_info.update(sta_stats[normalized_mac])
                    
                    device_statistics[normalized_mac] = device_info
            
            return {"device_statistics": device_statistics}
        except Exception as exc:
            _LOGGER.error("Error fetching hostapd data: %s", exc)
            raise UpdateFailed(f"Error fetching hostapd data: {exc}")

    @ubus_auto_reconnect(max_retries=3)
    async def _fetch_iwinfo_data(self, mac2name: Dict[str, Dict[str, str]]) -> Dict[str, Any]:
        """Fetch data from iwinfo using optimized batch calls."""
        client = await self._get_ubus_client("iwinfo")
        try:
            # Get AP devices
            ap_devices_result = await client.get_ap_devices()
            ap_devices = client.parse_ap_devices(ap_devices_result) if ap_devices_result else []
            
            # Skip if no wireless devices found
            if not ap_devices:
                return {}
            
            device_statistics = {}
            
            # Use batch call to get STA data for all AP devices at once
            sta_data_batch = await client.get_all_sta_data_batch(ap_devices, is_hostapd=False)
            
            for ap_device in ap_devices:
                if ap_device not in sta_data_batch:
                    continue
                    
                sta_devices = sta_data_batch[ap_device].get('devices', [])
                sta_stats = sta_data_batch[ap_device].get('statistics', {})
                
                for mac in sta_devices:
                    normalized_mac = mac.upper()
                    hostname = mac2name.get(normalized_mac, {}).get("hostname", normalized_mac.replace(":", ""))
                    ip_address = mac2name.get(normalized_mac, {}).get("ip", "Unknown IP")
                    
                    # Merge connection info with detailed statistics
                    device_info = {
                        "mac": normalized_mac,
                        "hostname": hostname,
                        "ap_device": ap_device,
                        "connected": True,
                        "ip_address": ip_address,
                    }
                    
                    # Add statistics if available
                    if normalized_mac in sta_stats:
                        device_info.update(sta_stats[normalized_mac])
                    
                    device_statistics[normalized_mac] = device_info
            
            return {"device_statistics": device_statistics}
        except Exception as exc:
            _LOGGER.error("Error fetching iwinfo data: %s", exc)
            raise UpdateFailed(f"Error fetching iwinfo data: {exc}")

    @ubus_auto_reconnect(max_retries=1)
    async def _get_mac2name_mapping(self, dhcp_software: str) -> Dict[str, Dict[str, str]]:
        """Generate MAC to name/IP mapping based on DHCP server."""
        mac2name = {}
        client = await self._get_ubus_client()
        
        try:
            if dhcp_software == "dnsmasq":
                # Get dnsmasq lease file location
                result = await client.get_uci_config("dhcp", "dnsmasq")
                if result and "values" in result:
                    values = result["values"].values()
                    leasefile = next(iter(values), {}).get("leasefile", "/tmp/dhcp.leases")
                    
                    # Read lease file
                    lease_result = await client.file_read(leasefile)
                    if lease_result and "data" in lease_result:
                        for line in lease_result["data"].splitlines():
                            hosts = line.split(" ")
                            if len(hosts) >= 4:
                                mac2name[hosts[1].upper()] = {
                                    "hostname": hosts[3],
                                    "ip": hosts[2]
                                }
            elif dhcp_software == "odhcpd":
                # Get odhcpd leases
                result = await client.get_dhcp_method("ipv4leases")
                if result and "device" in result:
                    for device in result["device"].values():
                        for lease in device.get("leases", []):
                            mac = lease.get("mac", "")
                            # Convert aabbccddeeff to aa:bb:cc:dd:ee:ff
                            if mac and len(mac) == 12:
                                mac = ":".join(mac[i:i+2] for i in range(0, len(mac), 2))
                                mac2name[mac.upper()] = {
                                    "hostname": lease.get("hostname", ""),
                                    "ip": lease.get("ip", "")
                                }
        except Exception as exc:
            _LOGGER.warning("Failed to get MAC to name mapping: %s", exc)
        
        return mac2name

    @ubus_auto_reconnect(max_retries=1)
    async def _fetch_conntrack_count(self) -> Dict[str, Any]:
        """Fetch connection tracking count."""
        client = await self._get_ubus_client()
        try:
            conntrack_count = await client.get_conntrack_count()
            return {"conntrack_count": conntrack_count}
        except Exception as exc:
            _LOGGER.error("Error fetching connection tracking count: %s", exc)
            raise UpdateFailed(f"Error fetching connection tracking count: {exc}")
            
    @ubus_auto_reconnect(max_retries=1)
    async def _fetch_system_temperatures(self) -> Dict[str, Any]:
        """Fetch system temperature sensors."""
        client = await self._get_ubus_client()
        try:
            temperatures = await client.get_system_temperatures()
            return {"system_temperatures": temperatures}
        except Exception as exc:
            _LOGGER.error("Error fetching system temperatures: %s", exc)
            raise UpdateFailed(f"Error fetching system temperatures: {exc}")
            
    @ubus_auto_reconnect(max_retries=1)
    async def _fetch_dhcp_clients_count(self) -> Dict[str, Any]:
        """Fetch DHCP clients count."""
        client = await self._get_ubus_client()
        try:
            clients_count = await client.get_dhcp_clients_count()
            return {"dhcp_clients_count": clients_count}
        except Exception as exc:
            _LOGGER.error("Error fetching DHCP clients count: %s", exc)
            raise UpdateFailed(f"Error fetching DHCP clients count: {exc}")

    @ubus_auto_reconnect(max_retries=1)
    async def _fetch_system_data_batch(self, system_types: set) -> Dict[str, Any]:
        """Fetch system data in batch with auto-reconnect protection."""
        combined_data = {}
        system_client = await self._get_ubus_client()
        
        if "system_info" in system_types:
            if await self._should_update("system_info"):
                async with self._update_locks["system_info"]:
                    system_info = await system_client.system_info()
                    self._data_cache["system_info"] = system_info  # Store raw data
                    self._last_update["system_info"] = datetime.now()
            combined_data["system_info"] = self._data_cache["system_info"]
        
        if "system_board" in system_types:
            if await self._should_update("system_board"):
                async with self._update_locks["system_board"]:
                    board_info = await system_client.system_board()
                    self._data_cache["system_board"] = board_info  # Store raw data
                    self._last_update["system_board"] = datetime.now()
            combined_data["system_board"] = self._data_cache["system_board"]
        
        return combined_data

    async def get_data(self, data_type: str) -> Dict[str, Any]:
        """Get cached data or fetch if needed."""
        async with self._update_locks[data_type]:
            if not await self._should_update(data_type) and data_type in self._data_cache:
                # Return cached data in the expected format for coordinator
                return {data_type: self._data_cache[data_type]}

            try:
                if data_type == "system_info":
                    data = await self._fetch_system_info()
                elif data_type == "system_board":
                    data = await self._fetch_system_board()
                elif data_type == "qmodem_info":
                    data = await self._fetch_qmodem_info()
                elif data_type == "hostapd_available":
                    data = await self._fetch_hostapd_available()
                elif data_type == "device_statistics":
                    data = await self._fetch_device_statistics()
                elif data_type == "ap_info":
                    data = await self._fetch_ap_info()
                elif data_type == "service_status":
                    # This method returns raw data, so we need to wrap it
                    raw_data = await self._fetch_service_status()
                    data = {data_type: raw_data}
                elif data_type == "conntrack_count":
                    data = await self._fetch_conntrack_count()
                elif data_type == "system_temperatures":
                    data = await self._fetch_system_temperatures()
                elif data_type == "dhcp_clients_count":
                    data = await self._fetch_dhcp_clients_count()
                else:
                    raise ValueError(f"Unknown data type: {data_type}")

                # Store the actual data (extract from wrapper if needed)
                if data_type in data:
                    self._data_cache[data_type] = data[data_type]
                else:
                    # For methods that already return wrapped data
                    self._data_cache[data_type] = data
                
                self._last_update[data_type] = datetime.now()
                # Return data in the expected format for coordinator
                return data
            except Exception as exc:
                _LOGGER.error("Error fetching data for %s: %s", data_type, exc)
                # Return cached data if available
                if data_type in self._data_cache:
                    _LOGGER.debug("Returning cached data for %s", data_type)
                    return {data_type: self._data_cache[data_type]}
                raise

    async def get_combined_data(self, data_types: list[str]) -> Dict[str, Any]:
        """Get multiple data types in a single call to optimize API usage."""
        combined_data = {}
        
        # Group data types that can be fetched together
        system_types = {"system_info", "system_board"} & set(data_types)
        other_types = set(data_types) - system_types
        
        # Fetch system data together if needed
        if system_types:
            try:
                system_data = await self._fetch_system_data_batch(system_types)
                combined_data.update(system_data)
            except Exception as exc:
                _LOGGER.error("Error fetching system data: %s", exc)
                # Use cached data if available
                for data_type in system_types:
                    if data_type in self._data_cache:
                        combined_data.update(self._data_cache[data_type])
        
        # Fetch other data types individually
        for data_type in other_types:
            try:
                data = await self.get_data(data_type)
                combined_data.update(data)
            except Exception as exc:
                _LOGGER.error("Error fetching %s: %s", data_type, exc)
        
        return combined_data

    async def close(self):
        """Close all ubus client connections."""
        for client in self._ubus_clients.values():
            try:
                await client.close()
            except Exception as exc:
                _LOGGER.debug("Error closing ubus client: %s", exc)
        self._ubus_clients.clear()

    def set_update_interval(self, data_type: str, interval: timedelta):
        """Set custom update interval for a data type."""
        self._update_intervals[data_type] = interval
        if data_type not in self._update_locks:
            self._update_locks[data_type] = asyncio.Lock()

    def invalidate_cache(self, data_type: str = None):
        """Invalidate cache for specific data type or all data."""
        if data_type:
            self._data_cache.pop(data_type, None)
            self._last_update.pop(data_type, None)
        else:
            self._data_cache.clear()
            self._last_update.clear()

    async def force_reconnect_all_clients(self):
        """Force reconnection of all ubus clients (for testing/debugging)."""
        _LOGGER.info("Forcing reconnection of all ubus clients")
        for client_type, client in self._ubus_clients.items():
            try:
                await client.close()
                _LOGGER.debug("Closed ubus client: %s", client_type)
            except Exception as exc:
                _LOGGER.debug("Error closing ubus client %s: %s", client_type, exc)
        
        self._ubus_clients.clear()
        _LOGGER.info("All ubus clients cleared, will reconnect on next call")


class SharedDataUpdateCoordinator(DataUpdateCoordinator):
    """Coordinator that uses shared data manager."""

    def __init__(
        self,
        hass: HomeAssistant,
        data_manager: SharedUbusDataManager,
        data_types: list[str],
        name: str,
        update_interval: timedelta,
    ):
        """Initialize the coordinator."""
        super().__init__(
            hass,
            _LOGGER,
            name=name,
            update_interval=update_interval,
        )
        self.data_manager = data_manager
        self.data_types = data_types

    async def _async_update_data(self):
        """Fetch data using shared manager."""
        try:
            return await self.data_manager.get_combined_data(self.data_types)
        except Exception as exc:
            raise UpdateFailed(f"Error communicating with API: {exc}")

    async def async_shutdown(self):
        """Shutdown the coordinator."""
        # Note: Don't close the data manager here as it might be shared
        # The data manager will be closed when the integration is unloaded
        pass
