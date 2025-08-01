# OpenWrt Ubus Integration for Home Assistant

[中文版本](README_zh.md) | **English Version**

## 🚀 Overview

The OpenWrt Ubus Integration is a comprehensive Home Assistant custom integration that transforms your OpenWrt router into a powerful smart home hub. By leveraging OpenWrt's native ubus interface, this integration provides real-time device tracking, system monitoring, and advanced network management capabilities directly within Home Assistant.

![Integration Overview](imgs/overview.png)
*Complete overview of OpenWrt Ubus integration features in Home Assistant*

### Key Capabilities

🔍 **Real-time Device Tracking** - Monitor all connected wireless and DHCP devices with live status updates  
📊 **System Monitoring** - Track router performance, uptime, memory usage, and load statistics  
🎛️ **Service Management** - Start, stop, and control OpenWrt system services remotely  
📡 **Wireless Control** - Manage access points and kick unwanted devices  
🌐 **Multi-Protocol Support** - Compatible with various OpenWrt software configurations  
⚡ **Performance Optimized** - Batch API calls and intelligent caching for minimal resource usage

## 📥 Installation & Setup

### Prerequisites ✅

Before installing the integration, ensure your OpenWrt router meets these requirements:

**Required Packages:**
```bash
# Install essential packages on your OpenWrt router
opkg install rpcd uhttpd-mod-ubus

# For device kick functionality (optional)
opkg install hostapd
```

**Required Services:**
```bash
# Enable required services
service rpcd start && service rpcd enable
service uhttpd start && service uhttpd enable
```

**Router Configuration:**
- 🔧 `rpcd` service running (handles ubus JSON-RPC)
- 🌐 `uhttpd` with ubus support (web interface backend)
- 🔐 Valid user credentials with appropriate permissions
- 🌍 Network access from Home Assistant to router

### Installation Methods

#### Method 1: Manual Installation

1. **📂 Download**: Clone or download this repository
   ```bash
   git clone https://github.com/FUjr/homeassistant-openwrt-ubus.git
   ```

2. **📋 Copy Files**: Copy the integration to your Home Assistant
   ```bash
   cp -r homeassistant-openwrt-ubus/custom_components/openwrt_ubus /config/custom_components/
   ```

3. **🔄 Restart**: Restart Home Assistant

4. **⚙️ Configure**: Go to **Settings** → **Devices & Services** → **Add Integration**

5. **🔍 Search**: Look for "OpenWrt ubus" and follow the setup wizard

#### Method 2: HACS Installation (Recommended) 🌟

> **Note**: This integration is available as a custom HACS repository

1. **➕ Add Repository**: In HACS, go to **Integrations** → **⋮** → **Custom repositories**
   
2. **📦 Install**: Add `https://github.com/FUjr/homeassistant-openwrt-ubus` as Integration

3. **⬇️ Download**: Search for "OpenWrt ubus" and install

4. **🔄 Restart**: Restart Home Assistant

5. **⚙️ Setup**: Add the integration through **Settings** → **Devices & Services**

### Router Permissions Setup 🔐

For enhanced functionality (hostname resolution), configure ACL permissions:

#### Create ACL Configuration
```bash
# SSH into your OpenWrt router
ssh root@your_router_ip

# Create ACL directory
mkdir -p /usr/share/rpcd/acl.d

# Create ACL file for Home Assistant
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

# Restart services to apply changes
/etc/init.d/rpcd restart && /etc/init.d/uhttpd restart
```

> **Important**: Without ACL configuration, device names may appear as MAC addresses instead of hostnames.

## 🎛️ Features & Configuration

### Initial Setup 🛠️

1. **Navigate to Integration**: Go to **Settings** → **Devices & Services** → **Add Integration**
2. **Search and Add**: Search for "OpenWrt ubus" and click to add
3. **Configure Connection**: Enter your router details

### Configuration Options 📋

| Option | Description | Default | Available Options |
|--------|-------------|---------|------------------|
| 🏠 **Host** | Router IP address | - | Any valid IP address |
| 👤 **Username** | Login username | - | Usually 'root' |
| 🔑 **Password** | Login password | - | Router admin password |
| 📡 **Wireless Software** | Wireless monitoring method | iwinfo | iwinfo, hostapd |
| 🌐 **DHCP Software** | DHCP client detection | dnsmasq | dnsmasq, odhcpd, none |
| ⏱️ **System Timeout** | System data fetch timeout | 30s | 5s-300s |
| 📊 **QModem Timeout** | QModem data fetch timeout | 30s | 5s-300s |
| ⚙️ **Service Timeout** | Service control timeout | 30s | 5s-300s |
| 🚫 **Device Kick Buttons** | Enable device kick functionality | Disabled | Enabled/Disabled |

---

### 📱 Device Tracking

The integration provides comprehensive device tracking for all connected devices to your OpenWrt router.

![Device Tracking](imgs/sta_info_devicetracker.png)
*Device tracker entities showing connected wireless devices with real-time status*

#### Wireless Device Detection
- **iwinfo Method**: Uses OpenWrt's iwinfo to detect wireless clients
- **hostapd Method**: Connects directly to hostapd daemon for real-time updates
- **Real-time Status**: Live updates when devices connect/disconnect
- **Device Attributes**: MAC address, hostname, signal strength, connection time

#### DHCP Client Monitoring
- **dnsmasq Integration**: Monitors DHCP leases from dnsmasq server
- **odhcpd Support**: Compatible with odhcpd DHCP server
- **Lease Information**: IP addresses, hostnames, lease expiration
- **Automatic Discovery**: Automatically detects new DHCP clients

**Features:**
- ✅ Real-time connection status updates
- 🏷️ Hostname resolution (with proper ACL configuration)
- 📍 Device location tracking (which AP they're connected to)
- ⏰ Connection duration tracking
- 🔄 Automatic entity creation for new devices

---

### 📊 System Monitoring

Comprehensive system health and performance monitoring for your OpenWrt router.

![System Information](imgs/system_info_sensor.png)
*System sensors displaying uptime, memory usage, and load averages*

#### System Information Sensors
- `sensor.openwrt_uptime` - System uptime and boot time
- `sensor.openwrt_load_1` - 1-minute load average
- `sensor.openwrt_load_5` - 5-minute load average
- `sensor.openwrt_load_15` - 15-minute load average
- `sensor.openwrt_memory_*` - Memory statistics (total, free, available, buffers, cached)

#### QModem LTE/4G Support
Monitor cellular modem status for routers with LTE/4G capabilities.

![QModem Information](imgs/qmodem_info.png)
*QModem sensors showing LTE signal strength, connection status, and data usage*

**QModem Sensors Include:**
- Signal strength and quality
- Connection status and uptime
- Data usage statistics
- Network operator information
- Modem temperature and status

#### Wireless Station Information
Track detailed wireless connection information for each connected device.

![Station Information](imgs/sta_info_sensor.png)
*Wireless station sensors showing signal strength and connection quality*

**Station Sensors:**
- Signal strength (RSSI)
- Connection quality
- Data rates (TX/RX)
- Connection duration
- Authentication status

---

### 🌐 Access Point Management

Monitor and manage wireless access points with detailed status information.

#### AP Client Mode
![AP Client Mode](imgs/ap_info_client.png)
*Access Point in client mode - connected to upstream wireless network*

**Client Mode Features:**
- Upstream AP connection status
- Signal strength to parent AP
- Data rate and quality metrics
- Connection stability monitoring

#### AP Master Mode
![AP Master Mode](imgs/ap_info_master.png)
*Access Point in master mode - hosting wireless network for clients*

**Master Mode Features:**
- Connected client count
- Channel information
- Encryption status
- Bandwidth utilization
- Network configuration details

---

### 🎛️ Service Control

Comprehensive service management for OpenWrt system services with real-time status monitoring.

![Service Control](imgs/service_control.png)
*Service control switches and buttons for managing OpenWrt system services*

#### Switch Entities
- **Service Switches**: Toggle services on/off with real-time status
- **Live Status**: Shows current running state of each service
- **Batch Updates**: Efficient monitoring of multiple services simultaneously

#### Button Entities
- **🟢 Start Service**: Start a stopped service
- **🔴 Stop Service**: Stop a running service
- **✅ Enable Service**: Enable service to start on boot
- **❌ Disable Service**: Disable auto-start on boot
- **🔄 Restart Service**: Restart a running service

**Managed Services Include:**
- `dnsmasq` - DNS and DHCP server
- `dropbear` - SSH server daemon
- `firewall` - Netfilter firewall
- `network` - Network configuration
- `uhttpd` - Web server
- `wpad` - Wireless daemon
- And many more system services...

**Features:**
- ⚡ Instant response to state changes
- 🔄 Automatic status refresh after operations
- 🛡️ Error handling with detailed feedback
- 📊 Optimized batch API calls for performance

---

### 🚫 Device Management & Control

Advanced device management capabilities including the ability to disconnect unwanted devices.

![Device Kick Control](imgs/ap_control_kick_sta.png)
*Device kick buttons for disconnecting specific wireless clients*

#### Device Kick Functionality
Force disconnect connected wireless devices from your network with temporary bans.

**How It Works:**
1. **🔍 Auto Detection**: Automatically detects connected wireless devices
2. **🆔 Dynamic Buttons**: Creates kick buttons for each connected device
3. **✅ Availability Check**: Buttons only appear when:
   - Device is currently connected
   - hostapd service is running
   - Device is on a supported access point
4. **⚡ Kick Action**: Sends deauthentication command
5. **🕐 Temporary Ban**: Automatically bans device for 60 seconds
6. **🔄 Status Update**: Refreshes device status after action

#### Connected Devices Overview
![Connected Devices](imgs/system_info_connected_devices.png)
*Overview of all connected devices with management controls*

**Requirements:**
- **📡 hostapd**: Must be installed and running
- **🌐 Ubus Access**: hostapd accessible via ubus interface
- **🔐 Permissions**: Appropriate user permissions for device management

**Button Entity Details:**
- **Entity Names**: `button.kick_[device_name]` or `button.kick_[mac_address]`
- **Attributes**: Device MAC, hostname, AP interface, signal strength
- **Auto-Hide**: Buttons disappear when devices disconnect
- **Multi-AP Support**: Separate controls for different access points

**Configuration:**
Device kick buttons are disabled by default. Enable in integration options:
1. Go to **Settings** → **Devices & Services** → **OpenWrt ubus**
2. Click **Configure**
3. Enable **Device Kick Buttons**
4. Save configuration

---

### 🔧 Advanced Configuration

#### Timeout Settings
- **System Sensor Timeout**: How long to wait for system data (5-300 seconds)
- **QModem Timeout**: Timeout for LTE/4G modem queries (5-300 seconds)  
- **Service Timeout**: Timeout for service control operations (5-300 seconds)

#### Performance Optimization
- **Batch API Calls**: Multiple ubus calls combined for efficiency
- **Intelligent Caching**: Reduces redundant API calls
- **Configurable Polling**: Adjust update frequencies per sensor type
- **Background Processing**: Non-blocking operations for better performance

#### Software Compatibility
- **Wireless Options**: Choose between `iwinfo` and `hostapd` based on your setup
- **DHCP Options**: Support for `dnsmasq`, `odhcpd`, or disable DHCP monitoring
- **Flexible Configuration**: Adapts to different OpenWrt configurations

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
- ✅ Ensure hostname resolution ACL is properly configured (see [Router Permissions Setup](#router-permissions-setup-🔐))
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
