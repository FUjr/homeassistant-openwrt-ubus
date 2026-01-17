"""Extended Ubus client with specific OpenWrt functionality."""

import json
import logging

from .Ubus import Ubus
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
    API_SUBSYS_LUCI_RPC,
    API_METHOD_BOARD,
    API_METHOD_GET,
    API_METHOD_GET_AP,
    API_METHOD_GET_CLIENTS,
    API_METHOD_GET_STA,
    API_METHOD_GET_QMODEM,
    API_METHOD_INFO,
    API_METHOD_READ,
    API_METHOD_REBOOT,
    API_METHOD_DEL_CLIENT,
    API_METHOD_LIST,
    API_METHOD_INIT,
    API_METHOD_GET_HOST_HINTS,
    DEFAULT_BAN_TIME_MS,
    DEFAULT_DEAUTH_REASON,
)

_LOGGER = logging.getLogger(__name__)


class ExtendedUbus(Ubus):
    """Extended Ubus client with specific OpenWrt functionality."""

    async def file_read(self, path):
        """Read file content."""
        return await self.api_call(
            API_RPC_CALL,
            API_SUBSYS_FILE,
            API_METHOD_READ,
            {API_PARAM_PATH: path},
        )

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

    async def get_hostapd_clients(self, hostapd):
        """Get hostapd clients."""
        return await self.api_call(API_RPC_CALL, hostapd, API_METHOD_GET_CLIENTS)

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

    async def system_reboot(self):
        """System reboot."""
        return await self.get_system_method(API_METHOD_REBOOT)

    # iwinfo specific methods
    async def get_ap_devices(self):
        """Get access point devices."""
        return await self.api_call(API_RPC_CALL, API_SUBSYS_IWINFO, API_METHOD_GET_AP)

    async def get_sta_devices(self, ap_device):
        """Get station devices."""
        return await self.api_call(API_RPC_CALL, API_SUBSYS_IWINFO, API_METHOD_GET_STA, {"device": ap_device})

    async def get_sta_statistics(self, ap_device):
        """Get detailed station statistics for all connected devices."""
        return await self.api_call(API_RPC_CALL, API_SUBSYS_IWINFO, API_METHOD_GET_STA, {"device": ap_device})

    async def get_ap_info(self, ap_device):
        """Get detailed access point information."""
        return await self.api_call(API_RPC_CALL, API_SUBSYS_IWINFO, API_METHOD_INFO, {"device": ap_device})

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
            # Direct list format
            sta_devices.extend(
                device["mac"] for device in result if isinstance(device, dict) and "mac" in device
            )
        elif isinstance(result, dict):
            # Dictionary format with "results" key
            sta_devices.extend(
                device["mac"] for device in result.get("results", [])
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
                mac = device["mac"]
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

    def parse_hostapd_ap_devices(self, result):
        """Parse access point devices from hostapd ubus result."""
        return result

    async def get_all_sta_data_batch(self, ap_devices, is_hostapd=False):
        """Get station data for all AP devices using batch call."""
        if not ap_devices:
            return {}

        # Build API calls for all AP devices
        rpcs = []
        for i, ap_device in enumerate(ap_devices):
            if is_hostapd:
                # For hostapd, ap_device is the hostapd interface name
                api_call = json.loads(self.build_api(
                    API_RPC_CALL,
                    ap_device,
                    API_METHOD_GET_CLIENTS
                ))
            else:
                # For iwinfo, ap_device is the wireless interface name
                api_call = json.loads(self.build_api(
                    API_RPC_CALL,
                    API_SUBSYS_IWINFO,
                    API_METHOD_GET_STA,
                    {"device": ap_device}
                ))
            api_call["id"] = i  # Use index as ID to match responses
            rpcs.append(api_call)

        # Execute batch call
        results = await self.batch_call(rpcs)
        if not results:
            return {}

        # Process results
        sta_data = {}

        # Handle both list and dict formats for ap_devices
        if isinstance(ap_devices, list):
            ap_device_list = ap_devices
        elif isinstance(ap_devices, dict):
            ap_device_list = list(ap_devices.keys())
        else:
            _LOGGER.error("Unexpected ap_devices type: %s", type(ap_devices).__name__)
            return {}

        for i, result in enumerate(results):
            # ignore if out of bounds. there has been a new connection?
            if i >= len(ap_device_list):
                continue
            ap_device = ap_device_list[i]

            try:
                # ap_device is already set from ap_device_list[i] above

                # Handle different response formats
                if "result" in result:
                    sta_result = result["result"][1] if len(result["result"]) > 1 else None
                elif "error" in result:
                    _LOGGER.debug("Error in batch call for %s: %s", ap_device, result["error"])
                    continue
                else:
                    _LOGGER.debug("Unexpected result format for %s: %s", ap_device, result)
                    continue

                if sta_result:
                    if is_hostapd:
                        sta_data[ap_device] = {
                            'devices': self.parse_hostapd_sta_devices(sta_result),
                            'statistics': self.parse_hostapd_sta_statistics(sta_result)
                        }
                    else:
                        sta_data[ap_device] = {
                            'devices': self.parse_sta_devices(sta_result),
                            'statistics': self.parse_sta_statistics(sta_result)
                        }
            except (IndexError, KeyError) as exc:
                _LOGGER.debug("Error parsing sta data index %s: %s", ap_device, exc)
        return sta_data

    async def get_all_ap_info_batch(self, ap_devices):
        """Get AP info for all AP devices using batch call."""
        if not ap_devices:
            return {}

        # Build API calls for all AP devices
        rpcs = []
        for i, ap_device in enumerate(ap_devices):
            api_call = json.loads(self.build_api(
                API_RPC_CALL,
                API_SUBSYS_IWINFO,
                API_METHOD_INFO,
                {"device": ap_device}
            ))
            api_call["id"] = i  # Use index as ID to match responses
            rpcs.append(api_call)

        # Execute batch call
        results = await self.batch_call(rpcs)
        if not results:
            return {}

        # Process results
        ap_info_data = {}
        for i, result in enumerate(results):
            if i < len(ap_devices):
                ap_device = ap_devices[i]
                try:
                    # Handle different response formats
                    if "result" in result:
                        ap_result = result["result"][1] if len(result["result"]) > 1 else None
                    elif "error" in result:
                        _LOGGER.debug("Error in batch call for AP %s: %s", ap_device, result["error"])
                        continue
                    else:
                        continue

                    if ap_result:
                        ap_info = self.parse_ap_info(ap_result, ap_device)
                        # Only add AP if it has an SSID
                        if ap_info and ap_info.get("ssid"):
                            ap_info_data[ap_device] = ap_info
                            _LOGGER.debug("AP info fetched for device %s with SSID %s", ap_device, ap_info.get("ssid"))
                        else:
                            _LOGGER.debug("Skipping AP device %s - no SSID found", ap_device)
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
        status_rpcs = []
        service_names = []

        for service_name in service_list_result:
            service_names.append(service_name)
            # Use "list" method with service name to get specific service status
            status_call = json.loads(self.build_api(
                API_RPC_CALL,
                API_SUBSYS_RC,
                API_METHOD_LIST,
                {"name": service_name}
            ))
            status_rpcs.append(status_call)

        # Execute batch call for all service statuses
        if status_rpcs:
            _LOGGER.debug("Executing batch call for %d services", len(status_rpcs))
            status_results = await self.batch_call(status_rpcs)

            if status_results:
                _LOGGER.debug("Got %d status results", len(status_results))
                for i, result in enumerate(status_results):
                    if i < len(service_names):
                        service_name = service_names[i]
                        _LOGGER.debug("Processing result %d for service %s: %s", i, service_name, result)

                        if result and "result" in result and len(result["result"]) > 1:
                            # Service status format: [session_id, services_dict]
                            services_dict = result["result"][1] if len(result["result"]) > 1 else {}
                            _LOGGER.debug("Raw services dict for %s: %s", service_name, services_dict)

                            # Extract the specific service from the services dict
                            if isinstance(services_dict, dict) and service_name in services_dict:
                                service_status = services_dict[service_name]
                                _LOGGER.debug("Extracted service status for %s: %s", service_name, service_status)

                                # Parse service status - OpenWrt RC returns different formats
                                parsed_status = self._parse_service_status(service_status, service_name)
                                services_with_status[service_name] = parsed_status
                            else:
                                _LOGGER.debug("Service %s not found in response dict, using default", service_name)
                                services_with_status[service_name] = {"running": False, "enabled": False}
                        else:
                            # Default status if no result
                            _LOGGER.debug("No valid result for service %s, using default", service_name)
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
        _LOGGER.warning("Service %s: Unexpected status format (type %s): %s",
                        service_name, type(status_data), status_data)
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

    async def kick_device(
        self,
        hostapd_interface: str,
        mac_address: str,
        ban_time: int = DEFAULT_BAN_TIME_MS,
        reason: int = DEFAULT_DEAUTH_REASON,
    ):
        """Kick a device from the AP interface.

        Args:
            hostapd_interface: The hostapd interface name (e.g. "hostapd.phy0-ap0")
            mac_address: MAC address of the device to kick
            ban_time: Ban time in milliseconds (default: 60000ms = 60s)
            reason: 802.11 deauthentication reason code (default: 5)
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

    # luci-rpc specific methods for wired device tracking
    async def get_host_hints(self):
        """Get host hints from luci-rpc for device name/IP mapping.

        Returns a dictionary with MAC addresses as keys containing:
        - ipaddrs: List of IPv4 addresses
        - ip6addrs: List of IPv6 addresses
        - name: Hostname if available
        """
        try:
            result = await self.api_call(
                API_RPC_CALL,
                API_SUBSYS_LUCI_RPC,
                API_METHOD_GET_HOST_HINTS
            )
            if result and isinstance(result, dict):
                return result
            return {}
        except Exception as exc:
            _LOGGER.debug("Error getting host hints: %s", exc)
            return {}

    async def get_arp_table(self):
        """Read and parse ARP table from /proc/net/arp.

        Returns a list of dictionaries containing:
        - ip: IP address
        - mac: MAC address (uppercase)
        - device: Network interface
        - state: ARP entry state (derived from flags)
        """
        try:
            result = await self.file_read("/proc/net/arp")
            if not result or "data" not in result:
                return []

            return self.parse_arp_table(result["data"])
        except Exception as exc:
            _LOGGER.debug("Error reading ARP table: %s", exc)
            return []

    def parse_arp_table(self, arp_data: str) -> list[dict]:
        """Parse ARP table data from /proc/net/arp.

        Format of /proc/net/arp:
        IP address       HW type     Flags       HW address            Mask     Device
        192.168.1.1      0x1         0x2         00:11:22:33:44:55     *        br-lan

        Flags:
        - 0x0: incomplete
        - 0x2: reachable/complete
        - 0x4: permanent
        - 0x6: reachable + permanent
        """
        arp_entries = []
        if not arp_data:
            return arp_entries

        lines = arp_data.strip().split("\n")
        # Skip header line
        for line in lines[1:]:
            parts = line.split()
            if len(parts) >= 6:
                ip_addr = parts[0]
                flags = parts[2]
                mac_addr = parts[3].upper()
                device = parts[5]

                # Skip incomplete entries (flags 0x0) and broadcast/multicast
                if flags == "0x0" or mac_addr == "00:00:00:00:00:00":
                    continue

                # Determine state based on flags
                try:
                    flag_int = int(flags, 16)
                    if flag_int & 0x4:
                        state = "permanent"
                    elif flag_int & 0x2:
                        state = "reachable"
                    else:
                        state = "stale"
                except ValueError:
                    state = "unknown"

                arp_entries.append({
                    "ip": ip_addr,
                    "mac": mac_addr,
                    "device": device,
                    "state": state,
                    "flags": flags
                })

        return arp_entries

    async def get_wired_devices(self, wireless_macs: set[str] | None = None) -> dict[str, dict]:
        """Get wired devices by combining ARP table with host hints.

        Args:
            wireless_macs: Set of MAC addresses that are wireless (to exclude)

        Returns:
            Dictionary with MAC addresses as keys containing device info:
            - ip_address: IPv4 address
            - hostname: Device hostname if available
            - connected: Whether device is currently connected
            - connection_type: "wired"
            - ap_device: "LAN" for wired devices
        """
        if wireless_macs is None:
            wireless_macs = set()

        # Normalize wireless MACs to uppercase for comparison
        wireless_macs_upper = {mac.upper() for mac in wireless_macs}

        # Get ARP table entries
        arp_entries = await self.get_arp_table()

        # Get host hints for name/IP mapping
        host_hints = await self.get_host_hints()

        wired_devices = {}

        for entry in arp_entries:
            mac = entry["mac"]

            # Skip wireless devices
            if mac in wireless_macs_upper:
                _LOGGER.debug("Skipping wireless device %s from wired tracking", mac)
                continue

            # Get additional info from host hints
            hint = host_hints.get(mac, {})

            # Determine hostname - prefer host hints name, fallback to MAC
            hostname = hint.get("name", "")
            if not hostname:
                # Try lowercase MAC lookup as well
                hint = host_hints.get(mac.lower(), {})
                hostname = hint.get("name", "")

            # Determine connection state
            connected = entry["state"] in ("reachable", "permanent")

            wired_devices[mac] = {
                "ip_address": entry["ip"],
                "hostname": hostname if hostname else mac,
                "connected": connected,
                "connection_type": "wired",
                "ap_device": "LAN",
                "arp_state": entry["state"],
                "interface": entry["device"]
            }

            _LOGGER.debug(
                "Found wired device %s: IP=%s, hostname=%s, connected=%s",
                mac, entry["ip"], hostname, connected
            )

        return wired_devices
