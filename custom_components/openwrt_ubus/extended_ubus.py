"""Extended Ubus client with specific OpenWrt functionality."""

import logging

from .Ubus import Ubus
from .Ubus.interface import PreparedCall
from .const import (
    API_RPC_CALL,
    API_RPC_LIST,
    API_PARAM_CONFIG,
    API_PARAM_PATH,
    API_PARAM_TYPE,
    API_SUBSYS_DHCP,
    API_SUBSYS_FILE,
    API_SUBSYS_HOSTAPD,
    API_SUBSYS_IWINFO,
    API_SUBSYS_SYSTEM,
    API_SUBSYS_UCI,
    API_SUBSYS_QMODEM,
    API_SUBSYS_RC,
    API_SUBSYS_WIRELESS,
    API_METHOD_BOARD,
    API_METHOD_GET,
    API_METHOD_GET_AP,
    API_METHOD_GET_CLIENTS,
    API_METHOD_GET_STA,
    API_METHOD_GET_QMODEM,
    API_METHOD_INFO,
    API_METHOD_READ,
    API_METHOD_DEL_CLIENT,
    API_METHOD_LIST,
    API_METHOD_INIT,
    API_METHOD_SET,
    API_METHOD_COMMIT,
)

_LOGGER = logging.getLogger(__name__)


class ExtendedUbus(Ubus):
    """Extended Ubus client with specific OpenWrt functionality."""

    def __init__(
            self,
            host,
            username,
            password,
            session,
    ):
        super().__init__(host, username, password, session)
        self._interface_to_ssid_cache = {}  # Cache for interface->SSID mapping

    async def get_interface_to_ssid_mapping(self):
        """Get mapping of physical interface names to SSIDs."""
        try:
            # Check cache first
            if self._interface_to_ssid_cache:
                return self._interface_to_ssid_cache

            # Get wireless status
            result = await self.api_call(
                API_RPC_CALL,
                API_SUBSYS_WIRELESS,
                "status",
                {}
            )

            if not result:
                return {}

            mapping = {}

            # Parse the wireless status to build interface->SSID mapping
            for radio_name, radio_data in result.items():
                if isinstance(radio_data, dict) and "interfaces" in radio_data:
                    for interface in radio_data["interfaces"]:
                        ifname = interface.get("ifname")
                        config = interface.get("config", {})
                        ssid = config.get("ssid")

                        if ifname and ssid:
                            mapping[ifname] = ssid
                            _LOGGER.debug("Mapped interface %s to SSID %s", ifname, ssid)

            # Cache the mapping
            self._interface_to_ssid_cache = mapping
            return mapping

        except Exception as exc:
            _LOGGER.error("Error getting interface to SSID mapping: %s", exc)
            return {}

    async def file_read(self, path):
        """Read file content."""
        return await self.api_call(
            API_RPC_CALL,
            API_SUBSYS_FILE,
            API_METHOD_READ,
            {API_PARAM_PATH: path},
        )

    # --- ETH SENSOR DEBUG/ERROR LOGGING PATCH ---

    async def get_eth_sensor_coordinator(self, eth_sensor_id):
        """
        Try to get the coordinator for a given eth_sensor.
        This is a stub for demonstration and error logging.
        """
        try:
            # Simulate loading the eth_sensor module
            _LOGGER.debug("Loading sensor module: eth_sensor")
            # Simulate error accessing coordinator
            raise KeyError(eth_sensor_id)
        except KeyError as exc:
            _LOGGER.error(
                "Error accessing coordinator for eth_sensor: '%s'", eth_sensor_id
            )
            _LOGGER.debug("Sensor module eth_sensor returned no coordinator")
            return None

    # --- END ETH SENSOR PATCH ---

    async def get_ethers_mapping(self):
        """Read /etc/ethers file to get MAC to hostname mapping."""
        try:
            result = await self.file_read("/etc/ethers")
            if not result or "data" not in result:
                return {}

            mapping = {}
            for line in result["data"].splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                parts = line.split()
                if len(parts) >= 2:
                    mac = parts[0].upper()
                    hostname = parts[1]
                    mapping[mac] = {
                        "hostname": hostname,
                        "ip": hostname  # Use hostname as fallback for IP field
                    }
                    _LOGGER.debug("Added ethers mapping: %s -> %s", mac, hostname)

            return mapping

        except Exception as exc:
            _LOGGER.debug("Error reading /etc/ethers: %s", exc)
            return {}

    async def get_conntrack_count(self):
        """Read connection tracking count from /proc/sys/net/netfilter/nf_conntrack_count."""
        try:
            result = await self.file_read("/proc/sys/net/netfilter/nf_conntrack_count")
            if result and "data" in result:
                # Convert the data to an integer
                return int(result["data"].strip())
            return None
        except Exception as exc:
            _LOGGER.debug("Error reading connection tracking count: %s", exc)
            return None

    async def get_system_temperatures(self):
        """Read system temperature sensors from /sys/class/hwmon/*/temp1_input."""
        try:
            # First, list all hwmon directories
            hwmon_list_result = await self.api_call(
                API_RPC_CALL,
                API_SUBSYS_FILE,
                "list",
                {"path": "/sys/class/hwmon/"},
            )
            _LOGGER.debug("hwmon list result: %s", hwmon_list_result)
            if not hwmon_list_result or "entries" not in hwmon_list_result:
                _LOGGER.debug("No hwmon directories found or empty entries in result")
                return {}

            temperatures = {}

            # Process each hwmon directory
            for entry in hwmon_list_result["entries"]:
                if entry["type"] != "directory":
                    continue

                hwmon_dir = entry["name"]
                hwmon_path = f"/sys/class/hwmon/{hwmon_dir}"

                # Try to read the name file
                try:
                    name_result = await self.file_read(f"{hwmon_path}/name")
                    _LOGGER.debug("Read %s/name => %s", hwmon_path, name_result)
                    sensor_name = f"hwmon{hwmon_dir}"  # Default name based on directory
                    if name_result and "data" in name_result:
                        sensor_name = name_result["data"].strip()
                    elif name_result is not None:
                        _LOGGER.debug("Name result exists but no 'data' field: %s", name_result)
                        # If result is a list with error code, try to continue anyway
                        if isinstance(name_result, list) and len(name_result) > 0:
                            _LOGGER.debug("Name file read returned error code: %s, using default name", name_result)

                    # Try multiple temperature inputs if available
                    temp_path = f"{hwmon_path}/temp1_input"
                    temp_result = await self.file_read(temp_path)
                    _LOGGER.debug("Read %s => %s", temp_path, temp_result)
                    _LOGGER.debug("Temp result type: %s", type(temp_result))
                    if temp_result and "data" in temp_result:
                        temp_value = int(temp_result["data"].strip()) / 1000.0
                        temperatures[sensor_name] = temp_value
                    elif temp_result is not None:
                        _LOGGER.debug("Temp result exists but no 'data' field: %s", temp_result)

                except (ValueError, TypeError) as exc:
                    _LOGGER.debug("Error converting temperature value from %s: %s", temp_result, exc)
                    continue

            return temperatures

        except Exception as exc:
            _LOGGER.debug("Error reading system temperatures: %s", exc)
            return {}

    async def get_dhcp_clients_count(self):
        """Read DHCP leases file and count non-empty lines to determine client count."""
        try:
            result = await self.file_read("/tmp/dhcp.leases")
            if result and "data" in result:
                # Count non-empty lines
                lines = result["data"].splitlines()
                client_count = sum(1 for line in lines if line.strip())
                return client_count
            return 0
        except Exception as exc:
            _LOGGER.debug("Error reading DHCP leases file: %s", exc)
            return 0

    async def get_dhcp_method(self, method):
        """Get DHCP method."""
        return await self.api_call(API_RPC_CALL, API_SUBSYS_DHCP, method)

    async def get_hostapd(self):
        """Get hostapd data."""
        return await self.api_call(API_RPC_LIST, API_SUBSYS_HOSTAPD)

    async def get_uci_config(self, _config, _type):
        """Get UCI config."""
        return await self.api_call(
            API_RPC_CALL,
            API_SUBSYS_UCI,
            API_METHOD_GET,
            {
                API_PARAM_CONFIG: _config,
                API_PARAM_TYPE: _type,
            },
        )

    async def uci_get_option(self, config: str, section: str | None = None, option: str | None = None):
        """Get a specific UCI option value."""
        params: dict = {API_PARAM_CONFIG: config}
        if section is not None:
            params["section"] = section
        if option is not None:
            params["option"] = option
        return await self.api_call(
            API_RPC_CALL,
            API_SUBSYS_UCI,
            API_METHOD_GET,
            params,
        )

    async def uci_set_option(self, config: str, section: str, option: str, value):
        """Set a specific UCI option value.

        Args:
            config: UCI config name (e.g., "firewall")
            section: Section name or type/index
            option: Option key to set
            value: Option value - may be a string or list of strings for UCI list-type options.
                   Lists are passed through as JSON arrays to ubus.

        Note:
            Call `uci_commit_config()` after calling this method to write changes to disk.
            Consider calling `service_action()` to restart affected services (e.g., restart
            "dnsmasq" after changing DHCP configuration, or "network" after interface changes).
        """
        params = {
            "config": config,
            "section": section,
            "values": {
                option: value,
            },
        }
        return await self.api_call(
            API_RPC_CALL,
            API_SUBSYS_UCI,
            API_METHOD_SET,
            params,
        )

    async def uci_commit_config(self, config: str):
        """Commit changes to a UCI config."""
        params = {
            "config": config,
        }
        return await self.api_call(
            API_RPC_CALL,
            API_SUBSYS_UCI,
            API_METHOD_COMMIT,
            params,
        )

    async def list_modem_ctrl(self):
        """List available modem_ctrl subsystems."""
        return await self.api_call(API_RPC_LIST, API_SUBSYS_QMODEM)

    async def get_qmodem_info(self):
        """Get QModem info."""
        return await self.api_call(API_RPC_CALL, API_SUBSYS_QMODEM, API_METHOD_GET_QMODEM)

    async def get_system_method(self, method):
        """Get system method."""
        return await self.api_call(API_RPC_CALL, API_SUBSYS_SYSTEM, method)

    async def system_board(self):
        """System board."""
        return await self.get_system_method(API_METHOD_BOARD)

    async def system_info(self):
        """System info."""
        return await self.get_system_method(API_METHOD_INFO)

    async def system_stat(self):
        """Kernel system statistics."""
        return await self.file_read("/proc/stat")

    # iwinfo specific methods
    async def get_ap_devices(self):
        """Get access point devices."""
        return await self.api_call(API_RPC_CALL, API_SUBSYS_IWINFO, API_METHOD_GET_AP)

    async def get_root_partition_info(self):
        """Get root partition information (total, free, used, avail in MB)."""
        try:
            result = await self.api_call(API_RPC_CALL, API_SUBSYS_SYSTEM, API_METHOD_INFO)
            _LOGGER.debug("system info raw result: %s", result)
            if result and "root" in result:
                # Convert KB to MB
                try:
                    return {
                        "total": result["root"]["total"] / 1024,
                        "free": result["root"]["free"] / 1024,
                        "used": result["root"]["used"] / 1024,
                        "avail": result["root"]["avail"] / 1024
                    }
                except Exception as exc:
                    _LOGGER.debug("Error parsing root partition values: %s", exc)
                    return {"total": 0, "free": 0, "used": 0, "avail": 0}
            return {"total": 0, "free": 0, "used": 0, "avail": 0}
        except Exception as exc:
            _LOGGER.error("Failed to get root partition info: %s", exc)
            return {"total": 0, "free": 0, "used": 0, "avail": 0}

    def parse_sta_devices(self, result):
        """Parse station devices from the ubus result."""
        sta_devices = []
        if not result:
            return sta_devices

        # Handle different response formats from iwinfo
        if isinstance(result, list):
            # Direct list format - normalize MAC addresses to uppercase
            sta_devices.extend(
                device["mac"].upper() for device in result if isinstance(device, dict) and "mac" in device
            )
        elif isinstance(result, dict):
            # Dictionary format with "results" key - normalize MAC addresses to uppercase
            sta_devices.extend(
                device["mac"].upper() for device in result.get("results", [])
                if isinstance(device, dict) and "mac" in device
            )
        return sta_devices

    def parse_sta_statistics(self, result):
        """Parse detailed station statistics from the ubus result."""
        sta_statistics = {}
        if not result:
            return sta_statistics

        # Handle different response formats from iwinfo
        devices_list = []
        if isinstance(result, list):
            # Direct list format
            devices_list = result
        elif isinstance(result, dict):
            # Dictionary format with "results" key
            devices_list = result.get("results", [])
        else:
            _LOGGER.warning("Unexpected result type in parse_sta_statistics: %s", type(result).__name__)
            return sta_statistics

        # iwinfo format - each device has detailed statistics
        for device in devices_list:
            if isinstance(device, dict) and "mac" in device:
                # Normalize MAC address to uppercase for consistent lookups
                mac = device["mac"].upper()
                sta_statistics[mac] = device
            else:
                _LOGGER.debug("Invalid device format: %s", device)

        return sta_statistics

    def parse_ap_devices(self, result):
        """Parse access point devices from the ubus result."""
        return list(result.get("devices", []))

    def parse_ap_info(self, result, ap_device):
        """Parse access point information from the ubus result."""
        if not result:
            return {}

        # The result should contain the AP information directly
        ap_info = dict(result)
        ap_info["device"] = ap_device  # Add device name for identification

        # Set device name based on SSID and mode
        if "ssid" in ap_info and "mode" in ap_info:
            ssid = ap_info["ssid"]
            mode = ap_info["mode"].lower() if ap_info["mode"] else "unknown"
            ap_info["device_name"] = f"{ssid}({mode})"
        else:
            ap_info["device_name"] = ap_device

        return ap_info

    # hostapd specific methods
    def parse_hostapd_sta_devices(self, result):
        """Parse station devices from hostapd ubus result."""
        sta_devices = []
        if not result:
            return sta_devices

        for key in result.get("clients", {}):
            device = result["clients"][key]
            if device.get("authorized"):
                sta_devices.append(key)
        return sta_devices

    def parse_hostapd_sta_statistics(self, result):
        """Parse detailed station statistics from hostapd ubus result."""
        sta_statistics = {}
        if not result:
            return sta_statistics

        # hostapd format - each device has detailed statistics
        for mac, device in result.get("clients", {}).items():
            if device.get("authorized"):
                sta_statistics[mac] = device
        return sta_statistics

    async def get_all_sta_data_batch(self, ap_devices: list[str], is_hostapd=False):
        """Get station data for all AP devices using batch call."""
        if not ap_devices:
            return {}

        # Build API calls for all AP devices
        prepared_calls: list[PreparedCall] = []
        for ap_device in ap_devices:
            if is_hostapd:
                # For hostapd, ap_device is the hostapd interface name
                api_call = PreparedCall(
                    rpc_method=API_RPC_CALL,
                    subsystem=ap_device,
                    method=API_METHOD_GET_CLIENTS,
                    params=None,
                    rpc_id=ap_device,
                )
            else:
                # For iwinfo, ap_device is the wireless interface name
                api_call = PreparedCall(
                    rpc_method=API_RPC_CALL,
                    subsystem=API_SUBSYS_IWINFO,
                    method=API_METHOD_GET_STA,
                    params={"device": ap_device},
                    rpc_id=ap_device,
                )
            prepared_calls.append(api_call)

        # Execute batch call
        results = await self.batch_call(prepared_calls)
        if not results:
            return {}

        # Process results
        sta_data = {}
        for ap_device, result in results:
            try:
                if isinstance(result, dict) and result:
                    if is_hostapd:
                        sta_data[ap_device] = {
                            'devices': self.parse_hostapd_sta_devices(result),
                            'statistics': self.parse_hostapd_sta_statistics(result)
                        }
                    else:
                        sta_data[ap_device] = {
                            'devices': self.parse_sta_devices(result),
                            'statistics': self.parse_sta_statistics(result)
                        }
                elif isinstance(result, Exception):
                    _LOGGER.error("Exception in batch call for %s: %s", ap_device, result)
                    continue
                else:
                    _LOGGER.debug("Unexpected result type for %s: %s", ap_device, type(result))
                    continue
            except (IndexError, KeyError) as exc:
                _LOGGER.debug("Error parsing sta data index %s: %s", ap_device, exc)
        return sta_data

    async def get_all_ap_info_batch(self, ap_devices: list[str]):
        """Get AP info for all AP devices using batch call."""
        if not ap_devices:
            return {}

        # Build API calls for all AP devices
        prepared_calls: list[PreparedCall] = []
        for ap_device in ap_devices:
            prepared_calls.append(
                PreparedCall(
                    rpc_method=API_RPC_CALL,
                    subsystem=API_SUBSYS_IWINFO,
                    method=API_METHOD_INFO,
                    params={"device": ap_device},
                    rpc_id=ap_device,
                )
            )

        # Execute batch call
        results = await self.batch_call(prepared_calls)
        if not results:
            return {}

        # Process results
        ap_info_data = {}
        for ap_device, result in results:
            try:
                if isinstance(result, dict) and result:
                    # Only add AP if it has an SSID
                    if (ap_info := self.parse_ap_info(result, ap_device)) and ap_info.get("ssid"):
                        ap_info_data[ap_device] = ap_info
                        _LOGGER.debug("AP info fetched for device %s with SSID %s", ap_device, ap_info.get("ssid"))
                    else:
                        _LOGGER.debug("Skipping AP device %s - no SSID found", ap_device)
                elif isinstance(result, Exception):
                    _LOGGER.error("Exception in batch call for %s: %s", ap_device, result)
                    continue
                else:
                    _LOGGER.debug("Unexpected result type for %s: %s", ap_device, type(result))
                    continue
            except (IndexError, KeyError) as exc:
                _LOGGER.debug("Error parsing AP info for %s: %s", ap_device, exc)

        return ap_info_data

    # RC (service control) specific methods
    async def list_services(self, include_status=False):
        """List available services, optionally including their status."""
        if not include_status:
            # Just get service list
            return await self.api_call(API_RPC_CALL, API_SUBSYS_RC, API_METHOD_LIST)

        # Get service list first
        service_list_result = await self.api_call(API_RPC_CALL, API_SUBSYS_RC, API_METHOD_LIST)
        if not service_list_result:
            _LOGGER.warning("Failed to get service list from RC")
            return {}

        _LOGGER.debug("Got service list: %s", service_list_result)

        # Build batch calls for each service status
        services_with_status = {}
        prepared_calls: list[PreparedCall] = []

        for service_name in service_list_result:
            # Use "list" method with service name to get specific service status
            prepared_calls.append(
                PreparedCall(
                    rpc_method=API_RPC_CALL,
                    subsystem=API_SUBSYS_RC,
                    method=API_METHOD_LIST,
                    params={"name": service_name},
                    rpc_id=service_name,
                )
            )

        # Execute batch call for all service statuses
        if prepared_calls:
            _LOGGER.debug("Executing batch call for %d services", len(prepared_calls))
            if status_results := await self.batch_call(prepared_calls):
                _LOGGER.debug("Got %d status results", len(status_results))
                for service_name, result in status_results:
                    _LOGGER.debug("Processing result for service %s: %s", service_name, result)

                    if isinstance(result, dict):
                        if service_name in result:
                            service_status = result[service_name]
                            _LOGGER.debug("Extracted service status for %s: %s", service_name, service_status)

                            # Parse service status - OpenWrt RC returns different formats
                            parsed_status = self._parse_service_status(service_status, service_name)
                            services_with_status[service_name] = parsed_status
                        else:
                            _LOGGER.debug("Service %s not found in response dict, using default", service_name)
                            services_with_status[service_name] = {"running": False, "enabled": False}
                    elif isinstance(result, Exception):
                        _LOGGER.error("Exception for service %s: %s, using default", service_name, result)
                        services_with_status[service_name] = {"running": False, "enabled": False}
                    else:
                        _LOGGER.error("Unexpected result type for service %s: %s, using default", service_name,
                                      type(result))
                        services_with_status[service_name] = {"running": False, "enabled": False}
            else:
                _LOGGER.warning("Batch call returned no results")

        _LOGGER.debug("Final services with status: %s", services_with_status)
        return services_with_status

    def _parse_service_status(self, status_data, service_name):
        """Parse service status from RC API response."""
        _LOGGER.debug("Parsing service status for %s: %s (type: %s)", service_name, status_data, type(status_data))

        if not status_data:
            _LOGGER.debug("Service %s: No status data, returning disabled", service_name)
            return {"running": False, "enabled": False}

        # OpenWrt RC list returns a dict with service properties:
        # {"start": 99, "enabled": true, "running": false}
        if isinstance(status_data, dict):
            _LOGGER.debug("Service %s: Dict status keys=%s", service_name, list(status_data.keys()))

            # Extract running and enabled status
            running = status_data.get("running", False)
            enabled = status_data.get("enabled", False)
            start_priority = status_data.get("start", 0)

            _LOGGER.debug("Service %s: running=%s, enabled=%s, start=%s",
                          service_name, running, enabled, start_priority)

            result = {
                "running": bool(running),
                "enabled": bool(enabled),
                "start_priority": start_priority,
                "raw_status": status_data
            }
            _LOGGER.debug("Service %s: Final parsed result=%s", service_name, result)
            return result

        # Fallback for string or other formats (shouldn't happen with RC list)
        if isinstance(status_data, str):
            running = status_data.lower() in ["running", "active", "started"]
            _LOGGER.debug("Service %s: String status '%s', running=%s", service_name, status_data, running)
            return {"running": running, "enabled": running, "status": status_data}

        # Fallback for unexpected formats
        _LOGGER.warning("Service %s: Unexpected status format (type %s): %s", service_name, type(status_data),
                        status_data)
        return {"running": False, "enabled": False, "raw_status": status_data}

    async def service_action(self, service_name, action):
        """Perform action on a service (start, stop, restart)."""
        return await self.api_call(
            API_RPC_CALL,
            API_SUBSYS_RC,
            API_METHOD_INIT,
            {"name": service_name, "action": action}
        )

    async def check_hostapd_available(self):
        """Check if hostapd service is available via ubus list."""
        try:
            result = await self.api_call(API_RPC_LIST, "*")
            if not result:
                return False

            # Look for any hostapd.* interfaces in the result
            for interface_name in result.keys():
                if interface_name.startswith("hostapd."):
                    _LOGGER.debug("Found hostapd interface: %s", interface_name)
                    return True

            _LOGGER.debug("No hostapd interfaces found in ubus list")
            return False

        except Exception as exc:
            _LOGGER.warning("Failed to check hostapd availability: %s", exc)
            return False

    async def kick_device(self, hostapd_interface, mac_address, ban_time=60000, reason=5):
        """Kick a device from the AP interface.

        Args:
            hostapd_interface: The hostapd interface name (e.g. "hostapd.phy0-ap0")
            mac_address: MAC address of the device to kick
            ban_time: Ban time in milliseconds (default: 60000ms = 60s)
            reason: Deauth reason code (default: 5)
        """
        return await self.api_call(
            API_RPC_CALL,
            hostapd_interface,
            API_METHOD_DEL_CLIENT,
            {
                "addr": mac_address,
                "deauth": True,
                "reason": reason,
                "ban_time": ban_time
            }
        )

    async def get_network_devices(self):
        """Get network device status."""
        return await self.api_call(API_RPC_CALL, "network.device", "status")
