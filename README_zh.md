# OpenWrt Ubus Home Assistant 集成

**中文版本** | [English Version](README.md)

这是一个 Home Assistant 自定义集成，通过 ubus 接口连接到 OpenWrt 路由器，提供设备跟踪和系统监控功能。

## 功能特性

### 📱 设备跟踪
- **无线设备检测**：使用 iwinfo 或 hostapd 跟踪连接的无线设备
- **DHCP 客户端监控**：使用 dnsmasq 或 odhcpd 监控 DHCP 客户端
- **实时连接状态**：获取设备连接状态的实时更新

![设备跟踪器](imgs/sta_info_devicetracker.png)
*设备跟踪器显示已连接的无线设备*

### 📊 系统传感器
- **系统信息**：运行时间、负载平均值、内存使用情况
- **QModem 支持**：监控 4G/LTE 调制解调器状态和连接详情
- **工作站信息**：跟踪无线工作站关联和信号强度

![系统信息](imgs/system_info_sensor.png)
*Home Assistant 中的系统信息传感器*

### 🔧 高级功能
- **服务控制**：启动、停止、启用和禁用 OpenWrt 系统服务
- **批量 API 优化**：使用批量 API 调用进行高效数据检索
- **可配置轮询**：为不同传感器类型调整更新间隔
- **多软件支持**：兼容各种 OpenWrt 软件配置
- **设备注册表集成**：正确的设备识别和管理

## 📥 安装

### 方法一：手动安装

1. 📂 下载或克隆此仓库
2. 📋 将 `custom_components/openwrt_ubus` 文件夹复制到您的 Home Assistant `custom_components` 目录
3. 🔄 重启 Home Assistant
4. ⚙️ 转到 **配置** → **集成** → **添加集成**
5. 🔍 搜索 "OpenWrt ubus" 并按照设置向导进行配置

### 方法二：HACS（推荐）🌟

> **注意**：此集成尚未在默认 HACS 仓库中提供

1. ➕ 在 HACS 中添加此仓库作为自定义仓库
2. 📦 安装 "OpenWrt ubus" 集成
3. 🔄 重启 Home Assistant
4. ⚙️ 通过 UI 添加集成

## ⚙️ 配置

### 前提条件 ✅

您的 OpenWrt 路由器必须具备：
- 🔧 `rpcd` 服务正在运行（通常默认启用）
- 🌐 支持 ubus JSON-RPC 的 `uhttpd`
- 🔐 具有适当权限的有效用户凭据

### 集成设置 🛠️

1. 导航到 **设置** → **设备与服务** → **添加集成**
2. 搜索 "OpenWrt ubus"
3. 输入您的路由器配置：
   - **🏠 主机**：您的 OpenWrt 路由器的 IP 地址
   - **👤 用户名**：登录用户名（通常是 'root'）
   - **🔑 密码**：登录密码
   - **📡 无线软件**：在 'iwinfo'（默认）或 'hostapd' 之间选择
   - **🌐 DHCP 软件**：在 'dnsmasq'（默认）、'odhcpd' 或 'none' 之间选择

### 配置选项 📋

| 选项 | 描述 | 默认值 | 选项 |
|------|------|--------|------|
| 🏠 主机 | 路由器 IP 地址 | - | 任何有效的 IP |
| 👤 用户名 | 登录用户名 | - | 通常是 'root' |
| 🔑 密码 | 登录密码 | - | 路由器密码 |
| 📡 无线软件 | 无线监控方法 | iwinfo | iwinfo, hostapd |
| 🌐 DHCP 软件 | DHCP 客户端检测方法 | dnsmasq | dnsmasq, odhcpd, none |
| ⏱️ 系统传感器超时 | 系统数据获取超时 | 30秒 | 5-300秒 |
| 📊 QModem 传感器超时 | QModem 数据获取超时 | 30秒 | 5-300秒 |
| ⚙️ 服务超时 | 服务控制超时 | 30秒 | 5-300秒 |

## 📋 实体

### 设备跟踪器
- **无线设备**：所有连接的无线客户端
- **DHCP 客户端**：所有 DHCP 分配的设备（如果启用了 DHCP 监控）

### 服务控制
- **🔄 开关实体**：控制 OpenWrt 系统服务（启动/停止）
- **⚡ 按钮实体**：服务管理的快速操作（启动、停止、启用、禁用、重启）

![已连接设备](imgs/system_info_connected_devices.png)
*Home Assistant 中已连接设备和服务控制的概览*

### 传感器

#### 🖥️ 系统信息
- `sensor.openwrt_uptime` - 系统运行时间
- `sensor.openwrt_load_1` - 1分钟负载平均值
- `sensor.openwrt_load_5` - 5分钟负载平均值
- `sensor.openwrt_load_15` - 15分钟负载平均值
- `sensor.openwrt_memory_*` - 各种内存统计信息

#### 📡 QModem（4G/LTE 调制解调器）
- `sensor.openwrt_qmodem_*` - 调制解调器状态、信号强度、连接详情

![QModem 信息](imgs/qmodem_info.png)
*QModem 传感器显示 LTE 调制解调器状态和信号信息*

#### 📶 无线工作站
- `sensor.openwrt_sta_*` - 工作站信号强度和连接信息

![工作站信息](imgs/sta_info_sensor.png)
*无线工作站传感器显示信号强度和连接详情*

#### 🌐 接入点信息
集成提供了 AP 客户端模式和主模式的详细信息：

![AP 客户端模式](imgs/ap_info_client.png)
*客户端模式下的接入点 - 显示与上游 AP 的连接*

![AP 主模式](imgs/ap_info_master.png)
*主模式下的接入点 - 显示托管网络信息*

### 🎛️ 服务控制
集成提供全面的服务控制功能：

#### 开关实体
- **服务开关**：实时状态更新的服务开/关切换
- **状态监控**：服务运行状态的实时显示
- **批量状态更新**：多个服务状态的高效轮询

#### 按钮实体
- **启动服务**：启动已停止的服务
- **停止服务**：停止正在运行的服务
- **启用服务**：启用服务在启动时自动启动
- **禁用服务**：禁用服务自动启动
- **重启服务**：重启正在运行的服务（先停止再启动）

**可用服务包括**：
- `dnsmasq`：DNS 和 DHCP 服务器
- `dropbear`：SSH 服务器
- `firewall`：防火墙服务
- `network`：网络配置
- `uhttpd`：Web 服务器
- `wpad`：无线配置守护程序
- 以及许多其他系统服务...

**服务控制功能**：
- ✅ 实时状态监控
- ⚡ 状态变化的即时响应
- 🔄 操作后自动状态刷新
- 🛡️ 用户友好的错误处理消息
- 📊 性能优化的批量 API

## 🔧 故障排除

### 常见问题 ⚠️

**🚫 无法连接到路由器**
- ✅ 验证路由器 IP 地址和凭据
- ✅ 确保 OpenWrt 上的 `rpcd` 和 `uhttpd` 服务正在运行
- ✅ 检查防火墙设置是否允许 HTTP 访问 ubus

**❌ 未检测到设备**
- ✅ 验证无线和 DHCP 软件设置与您的 OpenWrt 配置匹配
- ✅ 检查所选的监控方法是否在路由器上正确配置

**⏰ 传感器未更新**
- ✅ 检查 Home Assistant 日志中的连接错误
- ✅ 验证路由器权限是否允许访问系统信息

**🏷️ 设备显示 MAC 地址而不是主机名**
- ✅ 确保主机名解析 ACL 已正确配置（参见[主机名解析配置](#主机名解析配置-🏷️)）
- ✅ 验证 DHCP 租约文件是否可访问：`/var/dhcp.leases` 或 `/tmp/dhcp.leases`
- ✅ 检查在 ACL 配置后是否已重启 rpcd 服务
- ✅ 确认用户账户已分配到正确的 ACL 组

### 调试日志 🐛

在您的 `configuration.yaml` 中添加：

```yaml
logger:
  logs:
    custom_components.openwrt_ubus: debug
    homeassistant.components.device_tracker: debug
```

## 🔧 OpenWrt 路由器配置

### 所需软件包 📦
确保您的 OpenWrt 路由器上安装了这些软件包：

```bash
opkg install rpcd uhttpd-mod-ubus
```

### 服务配置 ⚙️
确保所需服务正在运行：

```bash
service rpcd start
service rpcd enable
service uhttpd start  
service uhttpd enable
```

### 权限 🔐
用户账户需要适当的权限来访问 ubus 方法。对于 root 用户，这通常不是问题。

### 主机名解析配置 🏷️

> **重要提示**：如果需要解析已连接设备的主机名，需要额外的 ACL 配置。

要启用主机名解析，您需要配置 rpcd ACL（访问控制列表）以允许读取系统文件。这对于集成从 DHCP 租约文件和系统配置中读取主机名信息是必需的。

#### 步骤 1：创建 ACL 配置文件
为 Home Assistant 集成创建新的 ACL 文件：

```bash
# SSH 连接到您的 OpenWrt 路由器
ssh root@your_router_ip

# 如果不存在，创建 ACL 配置目录
mkdir -p /usr/share/rpcd/acl.d

# 创建 ACL 配置文件
cat > /usr/share/rpcd/acl.d/hass.json << 'EOF'
{
  "hass": {
    "description": "OpenWrt ubus 集成的访问角色",
    "read": {
      "file": {
        "/tmp/*": [ "read" ]
      }
    }
  }
}
EOF
```

#### 步骤 2：重启服务
重启所需服务以应用更改：

```bash
/etc/init.d/rpcd restart && /etc/init.d/uhttpd restart
```

> **注意**：如果没有正确的 ACL 配置，设备名称在 Home Assistant 中可能显示为 MAC 地址而不是主机名。

## 👨‍💻 开发

### 项目结构 📁
```
custom_components/openwrt_ubus/
├── __init__.py              # 主集成设置
├── config_flow.py           # 配置流程
├── const.py                 # 常量和配置
├── device_tracker.py        # 设备跟踪平台
├── sensor.py               # 传感器平台协调器
├── switch.py               # 服务控制开关
├── button.py               # 服务控制按钮
├── extended_ubus.py        # 增强的 ubus 客户端与批量 API
├── shared_data_manager.py  # 共享数据管理和优化
├── manifest.json           # 集成清单
├── strings.json            # UI 字符串
├── services.yaml           # 服务定义
├── Ubus/                   # Ubus 通信库
│   ├── __init__.py
│   ├── const.py
│   └── interface.py
├── sensors/                # 各个传感器模块
│   ├── __init__.py
│   ├── system_sensor.py    # 系统信息传感器
│   ├── qmodem_sensor.py    # QModem/LTE 传感器
│   ├── sta_sensor.py       # 无线工作站传感器
│   └── ap_sensor.py        # 接入点传感器
└── translations/           # 本地化文件
    ├── en.json
    └── zh.json
```

### 贡献 🤝
1. 🍴 Fork 仓库
2. 🌿 创建功能分支
3. ✏️ 进行更改
4. 🧪 彻底测试
5. 📤 提交拉取请求

## 📄 许可证

此项目采用 Mozilla Public License 2.0 (MPL-2.0) 许可证 - 有关详细信息，请参阅 LICENSE 文件。

## 🆘 支持

- **🐛 GitHub Issues**：[报告错误或请求功能](https://github.com/fujr/homeassistant-openwrt-ubus/issues)
- **💬 Home Assistant 社区**：[在论坛上讨论](https://community.home-assistant.io/)

## 🙏 致谢

- 🔧 OpenWrt 项目提供了优秀的路由器固件
- 🏠 Home Assistant 社区提供了集成开发资源
- 👥 帮助改进此集成的贡献者和测试人员
