# OpenWrt Ubus API优化说明

## 问题描述

原始实现中存在以下问题：
1. 每个传感器模块（system_sensor、qmodem_sensor、sta_sensor）都有独立的数据协调器
2. 每个协调器都单独进行API调用，造成对路由器的重复请求
3. 相同的API端点被多次调用，增加了路由器的负载压力

## 优化方案

### 1. 共享数据管理器 (SharedUbusDataManager)

创建了一个中心化的数据管理器来：
- 统一管理所有ubus API调用
- 实现数据缓存机制，避免重复调用
- 根据不同数据类型设置合理的更新间隔
- 支持批量数据获取，减少API调用次数

#### 主要特性：
- **缓存机制**: 每种数据类型都有独立的缓存和更新时间
- **更新间隔控制**: 不同类型数据有不同的更新频率
- **批量获取**: 支持一次性获取多种数据类型
- **连接管理**: 统一管理aiohttp会话和ubus连接
- **异常处理**: 优雅的错误处理和降级机制

### 2. 共享数据协调器 (SharedDataUpdateCoordinator)

继承自Home Assistant的DataUpdateCoordinator，专门用于：
- 与共享数据管理器交互
- 支持多种数据类型的组合获取
- 为多个传感器实体提供统一的数据更新

### 3. 数据类型和更新频率

```python
_update_intervals = {
    "system_info": timedelta(minutes=2),     # 系统信息
    "system_board": timedelta(minutes=5),    # 硬件信息
    "qmodem_info": timedelta(minutes=1),     # QModem信息
    "device_statistics": timedelta(seconds=30), # 设备统计
    "dhcp_leases": timedelta(seconds=30),    # DHCP租约
    "hostapd_clients": timedelta(seconds=30), # Hostapd客户端
    "iwinfo_stations": timedelta(seconds=30), # Iwinfo站点
}
```

## 实现细节

### 文件结构

- `shared_data_manager.py`: 核心共享数据管理器
- `sensors/system_sensor.py`: 系统传感器（✅ 已优化）
- `sensors/qmodem_sensor.py`: QModem传感器（✅ 已优化）
- `sensors/sta_sensor.py`: 设备统计传感器（✅ 已优化）
- `device_tracker.py`: 设备追踪器（⏳ 待优化）

### 关键改进

1. **减少API调用**：
   - 原来：每个协调器独立调用API
   - 现在：共享数据管理器统一调用，数据共享

2. **智能缓存**：
   - 根据数据变化频率设置不同的缓存时间
   - 避免在缓存期内的重复API调用

3. **批量获取**：
   - `get_combined_data()` 方法支持一次获取多种数据
   - 系统相关的数据可以在一次API调用中获取

4. **连接复用**：
   - 所有模块共享同一个aiohttp会话
   - 减少连接建立和断开的开销

## 使用示例

### 在传感器模块中使用

```python
# 获取共享数据管理器
data_manager = hass.data[DOMAIN][f"data_manager_{entry.entry_id}"]

# 创建协调器
coordinator = SharedDataUpdateCoordinator(
    hass,
    data_manager,
    ["system_info", "system_board"],  # 需要的数据类型
    "coordinator_name",
    update_interval,
)
```

### 获取数据

```python
# 获取单一类型数据
system_data = await data_manager.get_data("system_info")

# 获取多种类型数据
combined_data = await data_manager.get_combined_data([
    "system_info", 
    "system_board", 
    "qmodem_info"
])
```

## 性能提升

1. **减少API调用频率**：从原来的每个协调器独立调用，变为共享调用
2. **智能缓存**：避免不必要的重复请求
3. **连接复用**：减少网络连接开销
4. **批量处理**：提高数据获取效率

## 后续计划

1. ✅ 优化 `system_sensor.py` - 已完成
2. ✅ 优化 `qmodem_sensor.py` - 已完成  
3. ✅ 优化 `sta_sensor.py` - 已完成
4. ⏳ 继续优化 `device_tracker.py`
5. 🔄 添加更多的数据类型支持
6. 🔄 实现更智能的缓存策略
7. 📊 添加监控和统计功能

### 最新改进 (sta_sensor.py)

- **动态设备检测**: 自动为新连接的设备创建传感器实体
- **智能实体管理**: 避免重复创建已存在的实体
- **数据结构适配**: 适配共享数据管理器的数据格式
- **异步监听器**: 使用协调器监听器处理新设备发现

### 技术亮点

- **零重复API调用**: 所有传感器共享同一套API数据
- **动态实体创建**: 新设备自动获得完整的传感器套件
- **内存优化**: 智能缓存避免数据重复存储
- **错误恢复**: 优雅的错误处理和降级机制

这个优化方案大大减少了对OpenWrt路由器的API调用压力，同时提高了数据获取的效率和可靠性。
