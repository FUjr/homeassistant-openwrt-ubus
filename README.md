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
- **Device Management**: Kick connected devices from wireless network with hostapd integration
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
| 🚫 Device Kick Buttons | Enable device kick functionality | Disabled | Enabled/Disabled |

## 📋 Entities

### Device Tracker
- **Wireless Devices**: All connected wireless clients
- **DHCP Clients**: All DHCP-assigned devices (if DHCP monitoring enabled)

### Service Control
- **🔄 Switch Entities**: Control OpenWrt system services (start/stop)
- **⚡ Button Entities**: Quick actions for service management (start, stop, enable, disable, restart)

### Device Management
- **🚫 Kick Buttons**: Force disconnect connected wireless devices from access points (requires hostapd)

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

### 🚫 Device Kick Buttons
The integration provides device management capabilities through kick buttons that allow you to disconnect devices from your wireless network:

#### Features
- **🔌 Device Disconnection**: Force disconnect connected wireless devices from AP
- **⏱️ Temporary Ban**: Automatically bans devices for 60 seconds after kicking
- **🔄 Real-time Updates**: Button availability updates based on device connection status
- **🎯 Hostapd Integration**: Uses hostapd interface for reliable device management
- **📍 AP-Specific Control**: Separate buttons for devices on different access points

#### How It Works
1. **🔍 Automatic Detection**: Integration automatically detects connected wireless devices
2. **🆔 Button Creation**: Creates kick buttons for each connected device dynamically
3. **✅ Availability Check**: Buttons are only available when:
   - Hostapd service is running and accessible via ubus
   - Target device is currently connected to the wireless network
   - Device is connected to the correct access point
4. **⚡ Kick Action**: When pressed, sends deauthentication command to disconnect device
5. **🔄 Status Update**: Automatically refreshes device status after kick operation

#### Requirements
- **📡 hostapd**: Must be installed and running on OpenWrt router
- **🌐 Ubus Interface**: hostapd must be accessible via ubus (hostapd.*)
- **🔐 Permissions**: User account needs permission to access hostapd ubus methods

#### Button Entity Details
- **🏷️ Entity Name**: `button.kick_[device_name]` or `button.kick_[mac_address]`
- **📊 Attributes**: 
  - `device_mac`: MAC address of the target device
  - `device_name`: Hostname of the device (if available)
  - `ap_device`: Access point interface (e.g., `phy0-ap0`)
  - `hostapd_interface`: Full hostapd interface name (e.g., `hostapd.phy0-ap0`)
- **🔴 Availability**: Automatically becomes unavailable when:
  - Device disconnects from the network
  - Hostapd service becomes unavailable
  - Device moves to a different access point

#### Configuration
Device kick buttons are disabled by default and can be enabled in the integration options:

1. Go to **Settings** → **Devices & Services** → **OpenWrt ubus**
2. Click **Configure** on the integration
3. Enable **Device Kick Buttons**
4. Save configuration

#### Dependencies
The kick device functionality depends on several integration modules:

**Core Dependencies**:
- `extended_ubus.py`: Provides `check_hostapd_available()` and `kick_device()` methods
- `shared_data_manager.py`: Manages caching of hostapd availability status (30-minute cache)
- `buttons/device_kick_button.py`: Implements the kick button entities

**Data Requirements**:
- `hostapd_available`: Cached check of hostapd service availability
- `device_statistics`: Real-time device connection information
- `ap_info`: Access point configuration and status

**API Calls Used**:
- `ubus list "*"`: Check for available hostapd interfaces
- `ubus call hostapd.[interface] del_client`: Kick device from AP

#### Technical Implementation
```bash
# Example ubus command executed when kicking a device:
ubus call hostapd.phy0-ap0 del_client '{"addr":"aa:bb:cc:dd:ee:ff","deauth":true,"reason":5,"ban_time":60000}'
```

The integration automatically:
- 🔍 Discovers available hostapd interfaces via `ubus list`
- 📋 Caches hostapd availability for 30 minutes (configurable)
- 🎯 Creates device-specific kick buttons for connected devices
- ⚡ Updates button availability in real-time
- 🚫 Executes deauthentication with 60-second ban time
- 🔄 Refreshes device status after kick operations

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
# Basic packages (required)
opkg install rpcd uhttpd-mod-ubus

# Optional packages for enhanced functionality
opkg install hostapd    # Required for device kick functionality
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
├── button.py               # Service control buttons and device kick coordination
├── extended_ubus.py        # Enhanced ubus client with batch API and hostapd support
├── shared_data_manager.py  # Shared data management and optimization
├── manifest.json           # Integration manifest
├── strings.json            # UI strings
├── services.yaml           # Service definitions
├── Ubus/                   # Ubus communication library
│   ├── __init__.py
│   ├── const.py
│   └── interface.py
├── buttons/                # Button entity modules
│   ├── __init__.py
│   ├── service_button.py   # Service control buttons
│   └── device_kick_button.py # Device kick functionality
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
