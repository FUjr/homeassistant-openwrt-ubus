"""Constants for the openwrt_ubus integration."""

from homeassistant.const import Platform

DOMAIN = "openwrt_ubus"
PLATFORMS = [Platform.DEVICE_TRACKER, Platform.SENSOR, Platform.SWITCH, Platform.BUTTON]

# Configuration constants
CONF_DHCP_SOFTWARE = "dhcp_software"
CONF_WIRELESS_SOFTWARE = "wireless_software"
CONF_USE_HTTPS = "use_https"
CONF_VERIFY_SSL = "verify_ssl"
CONF_CERT_PATH = "cert_path"
CONF_PORT = "port"
DEFAULT_DHCP_SOFTWARE = "dnsmasq"
DEFAULT_WIRELESS_SOFTWARE = "iwinfo"
DEFAULT_USE_HTTPS = False
DEFAULT_VERIFY_SSL = False  # Default to not verifying SSL for self-signed certificates
DEFAULT_HTTP_PORT = 80
DEFAULT_HTTPS_PORT = 443
DHCP_SOFTWARES = ["dnsmasq", "odhcpd", "none"]
WIRELESS_SOFTWARES = ["hostapd", "iwinfo", "none"]

# Device kick constants
DEFAULT_BAN_TIME_MS = 60000  # Default ban time in milliseconds (60 seconds)
DEFAULT_DEAUTH_REASON = 5    # 802.11 deauthentication reason code

# Sensor enable/disable configuration
CONF_ENABLE_QMODEM_SENSORS = "enable_qmodem_sensors"
CONF_ENABLE_STA_SENSORS = "enable_sta_sensors"
CONF_ENABLE_SYSTEM_SENSORS = "enable_system_sensors"
CONF_ENABLE_AP_SENSORS = "enable_ap_sensors"
CONF_ENABLE_ETH_SENSORS = "enable_eth_sensors"
CONF_ENABLE_SERVICE_CONTROLS = "enable_service_controls"

CONF_ENABLE_DEVICE_KICK_BUTTONS = "enable_device_kick_buttons"
CONF_ENABLE_WIRED_TRACKING = "enable_wired_tracking"
CONF_SELECTED_SERVICES = "selected_services"

# Timeout configuration
CONF_SYSTEM_SENSOR_TIMEOUT = "system_sensor_timeout"
CONF_QMODEM_SENSOR_TIMEOUT = "qmodem_sensor_timeout"
CONF_STA_SENSOR_TIMEOUT = "sta_sensor_timeout"
CONF_AP_SENSOR_TIMEOUT = "ap_sensor_timeout"
CONF_SERVICE_TIMEOUT = "service_timeout"

# Default values
DEFAULT_ENABLE_QMODEM_SENSORS = True
DEFAULT_ENABLE_STA_SENSORS = True
DEFAULT_ENABLE_SYSTEM_SENSORS = True
DEFAULT_ENABLE_AP_SENSORS = True
DEFAULT_ENABLE_ETH_SENSORS = True
DEFAULT_ENABLE_SERVICE_CONTROLS = False

DEFAULT_ENABLE_DEVICE_KICK_BUTTONS = False
DEFAULT_ENABLE_WIRED_TRACKING = False
DEFAULT_SELECTED_SERVICES = []
DEFAULT_SYSTEM_SENSOR_TIMEOUT = 30
DEFAULT_QMODEM_SENSOR_TIMEOUT = 120
DEFAULT_STA_SENSOR_TIMEOUT = 30
DEFAULT_AP_SENSOR_TIMEOUT = 60
DEFAULT_SERVICE_TIMEOUT = 30

# API constants - moved from Ubus/const.py
API_RPC_CALL = "call"
API_RPC_LIST = "list"

# API parameters
API_PARAM_CONFIG = "config"
API_PARAM_PATH = "path"
API_PARAM_TYPE = "type"

# API subsystems
API_SUBSYS_DHCP = "dhcp"
API_SUBSYS_FILE = "file"
API_SUBSYS_HOSTAPD = "hostapd.*"
API_SUBSYS_IWINFO = "iwinfo"
API_SUBSYS_SYSTEM = "system"
API_SUBSYS_UCI = "uci"
API_SUBSYS_QMODEM = "modem_ctrl"
API_SUBSYS_RC = "rc"
API_SUBSYS_LUCI_RPC = "luci-rpc"

# API methods
API_METHOD_BOARD = "board"
API_METHOD_GET = "get"
API_METHOD_GET_AP = "devices"
API_METHOD_GET_CLIENTS = "get_clients"
API_METHOD_GET_STA = "assoclist"
API_METHOD_GET_QMODEM = "info"
API_METHOD_INFO = "info"
API_METHOD_READ = "read"
API_METHOD_REBOOT = "reboot"
API_METHOD_DEL_CLIENT = "del_client"
API_METHOD_LIST = "list"
API_METHOD_INIT = "init"
API_METHOD_GET_HOST_HINTS = "getHostHints"


def build_ubus_url(
    host: str,
    use_https: bool = False,
    port: int | None = None,
) -> str:
    """Build the ubus API URL.

    Args:
        host: The hostname or IP address of the OpenWrt device
        use_https: Whether to use HTTPS (default: False)
        port: Optional custom port (default: 443 for HTTPS, 80 for HTTP)

    Returns:
        The complete ubus API URL
    """
    protocol = "https" if use_https else "http"
    if port is None:
        port = DEFAULT_HTTPS_PORT if use_https else DEFAULT_HTTP_PORT

    # Only include port in URL if it's non-standard
    if (use_https and port == DEFAULT_HTTPS_PORT) or (not use_https and port == DEFAULT_HTTP_PORT):
        return f"{protocol}://{host}/ubus"
    return f"{protocol}://{host}:{port}/ubus"


def get_config_value(entry, key: str, default):
    """Get configuration value with priority: options > data > default.

    Args:
        entry: The ConfigEntry object
        key: The configuration key to look up
        default: The default value if key is not found

    Returns:
        The configuration value
    """
    return entry.options.get(key, entry.data.get(key, default))
