# OpenWrt Ubus Integration for Home Assistant

[中文版本](README_zh.md) | **English Version**

A custom Home Assistant integration that connects to OpenWrt routers via the ubus interface to provide device tracking and system monitoring capabilities.

## Features

### 📱 Device Tracking
- **Wireless Device Detection**: Track connected wireless devices using iwinfo or hostapd
- **DHCP Client Monitoring**: Monitor DHCP clients using dnsmasq or odhcpd
- **Real-time Connection Status**: Get live updates on device connectivity

![Device Tracker](imgs/sta_info_devicetracker.png)
*Device tracker showing connected wireless devices*

### 📊 System Sensors
- **System Information**: Uptime, load averages, memory usage
- **QModem Support**: Monitor 4G/LTE modem status and connection details
- **Station Information**: Track wireless station associations and signal strength

![System Information](imgs/system_info_sensor.png)
*System information sensors in Home Assistant*

### 🔧 Advanced Features
- **Service Control**: Start, stop, enable, and disable OpenWrt system services
- **Batch API Optimization**: Efficient data retrieval using batch API calls
- **Configurable Polling**: Adjustable update intervals for different sensor types
- **Multiple Software Support**: Compatible with various OpenWrt software configurations
- **Device Registry Integration**: Proper device identification and management

## 📥 Installation

### Method 1: Manual Installation

1. 📂 Download or clone this repository
2. 📋 Copy the `custom_components/openwrt_ubus` folder to your Home Assistant `custom_components` directory
3. 🔄 Restart Home Assistant
4. ⚙️ Go to **Configuration** → **Integrations** → **Add Integration**
5. 🔍 Search for "OpenWrt ubus" and follow the setup wizard

### Method 2: HACS (Recommended) 🌟

> **Note**: This integration is not yet available in the default HACS repository

1. ➕ Add this repository as a custom repository in HACS
2. 📦 Install the "OpenWrt ubus" integration
3. 🔄 Restart Home Assistant
4. ⚙️ Add the integration through the UI

## ⚙️ Configuration

### Prerequisites ✅

Your OpenWrt router must have:
- 🔧 `rpcd` service running (usually enabled by default)
- 🌐 `uhttpd` with ubus JSON-RPC support
- 🔐 Valid user credentials with appropriate permissions

### Integration Setup 🛠️

1. Navigate to **Settings** → **Devices & Services** → **Add Integration**
2. Search for "OpenWrt ubus"
3. Enter your router configuration:
   - **🏠 Host**: IP address of your OpenWrt router
   - **👤 Username**: Login username (usually 'root')
   - **🔑 Password**: Login password
   - **📡 Wireless Software**: Choose between 'iwinfo' (default) or 'hostapd'
   - **🌐 DHCP Software**: Choose between 'dnsmasq' (default), 'odhcpd', or 'none'

### Configuration Options 📋

| Option | Description | Default | Options |
|--------|-------------|---------|---------|
| 🏠 Host | Router IP address | - | Any valid IP |
| 👤 Username | Login username | - | Usually 'root' |
| 🔑 Password | Login password | - | Router password |
| 📡 Wireless Software | Wireless monitoring method | iwinfo | iwinfo, hostapd |
| 🌐 DHCP Software | DHCP client detection method | dnsmasq | dnsmasq, odhcpd, none |
| ⏱️ System Sensor Timeout | System data fetch timeout | 30s | 5s-300s |
| 📊 QModem Sensor Timeout | QModem data fetch timeout | 30s | 5s-300s |
| ⚙️ Service Timeout | Service control timeout | 30s | 5s-300s |

## 📋 Entities

### Device Tracker
- **Wireless Devices**: All connected wireless clients
- **DHCP Clients**: All DHCP-assigned devices (if DHCP monitoring enabled)

### Service Control
- **🔄 Switch Entities**: Control OpenWrt system services (start/stop)
- **⚡ Button Entities**: Quick actions for service management (start, stop, enable, disable, restart)

![Connected Devices](imgs/system_info_connected_devices.png)
*Overview of connected devices and service controls in Home Assistant*

### Sensors

#### 🖥️ System Information
- `sensor.openwrt_uptime` - System uptime
- `sensor.openwrt_load_1` - 1-minute load average
- `sensor.openwrt_load_5` - 5-minute load average  
- `sensor.openwrt_load_15` - 15-minute load average
- `sensor.openwrt_memory_*` - Various memory statistics

#### 📡 QModem (4G/LTE Modem)
- `sensor.openwrt_qmodem_*` - Modem status, signal strength, connection details

![QModem Information](imgs/qmodem_info.png)
*QModem sensor showing LTE modem status and signal information*

#### 📶 Wireless Stations
- `sensor.openwrt_sta_*` - Station signal strength and connection information

![Station Information](imgs/sta_info_sensor.png)
*Wireless station sensors showing signal strength and connection details*

#### 🌐 Access Point Information
The integration provides detailed information about both AP client mode and master mode:

![AP Client Mode](imgs/ap_info_client.png)
*Access Point in client mode - showing connection to upstream AP*

![AP Master Mode](imgs/ap_info_master.png)
*Access Point in master mode - showing hosted network information*

### 🎛️ Service Control
The integration provides comprehensive service control capabilities:

#### Switch Entities
- **Service Switches**: Toggle services on/off with real-time status updates
- **Status Monitoring**: Live display of service running state
- **Batch Status Updates**: Efficient polling of multiple service states

#### Button Entities
- **Start Service**: Start a stopped service
- **Stop Service**: Stop a running service  
- **Enable Service**: Enable service to start automatically on boot
- **Disable Service**: Disable service from auto-starting
- **Restart Service**: Restart a running service (stop then start)

**Available Services Include**:
- `dnsmasq`: DNS and DHCP server
- `dropbear`: SSH server
- `firewall`: Firewall service
- `network`: Network configuration
- `uhttpd`: Web server
- `wpad`: Wireless configuration daemon
- And many more system services...

**Service Control Features**:
- ✅ Real-time status monitoring
- ⚡ Instant response to state changes
- 🔄 Automatic status refresh after operations
- 🛡️ Error handling with user-friendly messages
- 📊 Batch API optimization for performance

## 🔧 Troubleshooting

### Common Issues ⚠️

**🚫 Cannot Connect to Router**
- ✅ Verify the router IP address and credentials
- ✅ Ensure `rpcd` and `uhttpd` services are running on OpenWrt
- ✅ Check firewall settings allow HTTP access to ubus

**❌ No Devices Detected**
- ✅ Verify wireless and DHCP software settings match your OpenWrt configuration
- ✅ Check that the selected monitoring methods are properly configured on the router

**⏰ Sensors Not Updating**
- ✅ Check Home Assistant logs for connection errors
- ✅ Verify router permissions allow access to system information

**🏷️ Devices Show MAC Addresses Instead of Hostnames**
- ✅ Ensure hostname resolution ACL is properly configured (see [Hostname Resolution Configuration](#hostname-resolution-configuration-🏷️))
- ✅ Verify DHCP lease files are accessible: `/var/dhcp.leases` or `/tmp/dhcp.leases`
- ✅ Check that the rpcd service has been restarted after ACL configuration
- ✅ Confirm the user account is assigned to the correct ACL group

### Debug Logging 🐛

Add to your `configuration.yaml`:

```yaml
logger:
  logs:
    custom_components.openwrt_ubus: debug
    homeassistant.components.device_tracker: debug
```

## 🔧 OpenWrt Router Configuration

### Required Packages 📦
Ensure these packages are installed on your OpenWrt router:

```bash
opkg install rpcd uhttpd-mod-ubus
```

### Service Configuration ⚙️
Make sure required services are running:

```bash
service rpcd start
service rpcd enable
service uhttpd start  
service uhttpd enable
```

### Permissions 🔐
The user account needs appropriate permissions to access ubus methods. For the root user, this is typically not an issue.

### Hostname Resolution Configuration 🏷️

> **Important**: If you need hostname resolution for connected devices, additional ACL configuration is required.

To enable hostname resolution, you need to configure rpcd ACL (Access Control List) to allow reading system files. This is necessary for the integration to read hostname information from DHCP lease files and system configuration.

#### Step 1: Create ACL Configuration File
Create a new ACL file for the Home Assistant integration:

```bash
# SSH into your OpenWrt router
ssh root@your_router_ip

# Create the ACL configuration directory if it doesn't exist
mkdir -p /usr/share/rpcd/acl.d

# Create the ACL configuration file
cat > /usr/share/rpcd/acl.d/hass.json << 'EOF'
{
  "hass": {
    "description": "Access role for OpenWrt ubus integration",
    "read": {
      "file": {
        "/tmp/*": [ "read" ]
      }
    }
  }
}
EOF
```

#### Step 2: Restart Services
Restart the required services to apply changes:

```bash
/etc/init.d/rpcd restart && /etc/init.d/uhttpd restart
```

> **Note**: Without proper ACL configuration, device names may appear as MAC addresses instead of hostnames in Home Assistant.

## 👨‍💻 Development

### Project Structure 📁
```
custom_components/openwrt_ubus/
├── __init__.py              # Main integration setup
├── config_flow.py           # Configuration flow
├── const.py                 # Constants and configuration
├── device_tracker.py        # Device tracking platform
├── sensor.py               # Sensor platform coordinator
├── switch.py               # Service control switches
├── button.py               # Service control buttons
├── extended_ubus.py        # Enhanced ubus client with batch API
├── shared_data_manager.py  # Shared data management and optimization
├── manifest.json           # Integration manifest
├── strings.json            # UI strings
├── services.yaml           # Service definitions
├── Ubus/                   # Ubus communication library
│   ├── __init__.py
│   ├── const.py
│   └── interface.py
├── sensors/                # Individual sensor modules
│   ├── __init__.py
│   ├── system_sensor.py    # System information sensors
│   ├── qmodem_sensor.py    # QModem/LTE sensors
│   ├── sta_sensor.py       # Wireless station sensors
│   └── ap_sensor.py        # Access Point sensors
└── translations/           # Localization files
    ├── en.json
    └── zh.json
```

### Contributing 🤝
1. 🍴 Fork the repository
2. 🌿 Create a feature branch
3. ✏️ Make your changes
4. 🧪 Test thoroughly
5. 📤 Submit a pull request

## 📄 License

This project is licensed under the Mozilla Public License 2.0 (MPL-2.0) - see the LICENSE file for details.

## 🆘 Support

- **🐛 GitHub Issues**: [Report bugs or request features](https://github.com/fujr/homeassistant-openwrt-ubus/issues)
- **💬 Home Assistant Community**: [Discuss on the forum](https://community.home-assistant.io/)

## 🙏 Acknowledgments

- 🔧 OpenWrt project for the excellent router firmware
- 🏠 Home Assistant community for integration development resources
- 👥 Contributors and testers who help improve this integration
