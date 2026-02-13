"""Constants for the openwrt_ubus integration."""

from homeassistant.const import Platform

DOMAIN = "openwrt_ubus"
PLATFORMS = [Platform.DEVICE_TRACKER, Platform.SENSOR, Platform.SWITCH, Platform.BUTTON]

# Configuration constants
CONF_USE_HTTPS = "use_https"
CONF_PORT = "port"
CONF_ENDPOINT = "endpoint"
CONF_DHCP_SOFTWARE = "dhcp_software"
CONF_WIRELESS_SOFTWARE = "wireless_software"
DEFAULT_DHCP_SOFTWARE = "dnsmasq"
DEFAULT_WIRELESS_SOFTWARE = "iwinfo"
DHCP_SOFTWARES = ["dnsmasq", "odhcpd", "ethers", "none"]
WIRELESS_SOFTWARES = ["hostapd", "iwinfo", "none"]
TRACKING_METHODS = ["uniqueid", "combined"]
CONF_TRACKING_METHOD = "tracking_method"

# Sensor enable/disable configuration
CONF_ENABLE_QMODEM_SENSORS = "enable_qmodem_sensors"
CONF_ENABLE_STA_SENSORS = "enable_sta_sensors"
CONF_ENABLE_SYSTEM_SENSORS = "enable_system_sensors"
CONF_ENABLE_AP_SENSORS = "enable_ap_sensors"
CONF_ENABLE_ETH_SENSORS = "enable_eth_sensors"
CONF_ENABLE_MWAN3_SENSORS = "enable_mwan3_sensors"
CONF_ENABLE_SERVICE_CONTROLS = "enable_service_controls"

CONF_ENABLE_DEVICE_KICK_BUTTONS = "enable_device_kick_buttons"
CONF_SELECTED_SERVICES = "selected_services"

# Timeout configuration
CONF_SYSTEM_SENSOR_TIMEOUT = "system_sensor_timeout"
CONF_QMODEM_SENSOR_TIMEOUT = "qmodem_sensor_timeout"
CONF_STA_SENSOR_TIMEOUT = "sta_sensor_timeout"
CONF_AP_SENSOR_TIMEOUT = "ap_sensor_timeout"
CONF_MWAN3_SENSOR_TIMEOUT = "mwan3_sensor_timeout"
CONF_SERVICE_TIMEOUT = "service_timeout"

# Default values
DEFAULT_USE_HTTPS = False
DEFAULT_PORT_HTTP = 80
DEFAULT_PORT_HTTPS = 443
DEFAULT_ENDPOINT = "ubus"
DEFAULT_ENABLE_QMODEM_SENSORS = True
DEFAULT_ENABLE_STA_SENSORS = True
DEFAULT_ENABLE_SYSTEM_SENSORS = True
DEFAULT_ENABLE_AP_SENSORS = True
DEFAULT_ENABLE_ETH_SENSORS = True
DEFAULT_ENABLE_MWAN3_SENSORS = True
DEFAULT_ENABLE_SERVICE_CONTROLS = False
DEFAULT_TRACKING_METHOD = "combined"

DEFAULT_ENABLE_DEVICE_KICK_BUTTONS = False
DEFAULT_SELECTED_SERVICES = []
DEFAULT_SYSTEM_SENSOR_TIMEOUT = 30
DEFAULT_QMODEM_SENSOR_TIMEOUT = 120
DEFAULT_STA_SENSOR_TIMEOUT = 30
DEFAULT_AP_SENSOR_TIMEOUT = 60
DEFAULT_MWAN3_SENSOR_TIMEOUT = 60
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
API_SUBSYS_MWAN3 = "mwan3"
API_SUBSYS_RC = "rc"
API_SUBSYS_WIRELESS = "network.wireless"

# API methods
API_METHOD_BOARD = "board"
API_METHOD_GET = "get"
API_METHOD_GET_AP = "devices"
API_METHOD_GET_CLIENTS = "get_clients"
API_METHOD_GET_STA = "assoclist"
API_METHOD_GET_QMODEM = "info"
API_METHOD_GET_MWAN3 = "status"
API_METHOD_INFO = "info"
API_METHOD_READ = "read"
API_METHOD_REBOOT = "reboot"
API_METHOD_DEL_CLIENT = "del_client"
API_METHOD_LIST = "list"
API_METHOD_INIT = "init"
API_METHOD_SET = "set"
API_METHOD_COMMIT = "commit"


def _build_host_port(target: str, use_https: bool, port: int | None) -> str:
    """Build host:port string, omitting port if it's the default."""
    if port is None:
        return target
    default_port = DEFAULT_PORT_HTTPS if use_https else DEFAULT_PORT_HTTP
    if port == default_port:
        return target
    return f"{target}:{port}"


def build_ubus_url(
    host: str,
    use_https: bool = False,
    ip_address: str | None = None,
    port: int | None = None,
    endpoint: str | None = None,
) -> str:
    """Build the ubus URL based on protocol, host, port and endpoint."""
    scheme = "https" if use_https else "http"
    target = ip_address if ip_address else host
    host_port = _build_host_port(target, use_https, port)
    ep = endpoint.strip("/") if endpoint else DEFAULT_ENDPOINT
    return f"{scheme}://{host_port}/{ep}"


def build_configuration_url(host: str, use_https: bool = False, port: int | None = None) -> str:
    """Build the configuration URL for device info."""
    scheme = "https" if use_https else "http"
    host_port = _build_host_port(host, use_https, port)
    return f"{scheme}://{host_port}"
