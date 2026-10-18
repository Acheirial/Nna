# 运营维护与故障排查

本指南涵盖 **mita** 服务器和 **mieru** 客户端的日常运维：查看运行状态、查看日志、排查常见故障，以及说明配置文件的存放位置、可用环境变量和修改设置后的生效方式。

- [查看运行状态](#查看运行状态)
- [查看日志](#查看日志)
- [打开和关闭调试日志](#打开和关闭调试日志)
- [密码套件协商](#密码套件协商)
- [常见问题速查](#常见问题速查)
  - [应用配置时提示 unknown field](#症状应用配置时提示-unknown-field)
  - [完全无法连接](#症状完全无法连接)
  - [连接一段时间后断开](#症状连接一段时间后断开)
  - [速度非常慢](#症状速度非常慢)
  - [客户端无法启动](#症状客户端无法启动)
- [配置文件存放位置](#配置文件存放位置)
- [环境变量](#环境变量)
- [修改设置后如何生效](#修改设置后如何生效)

> **说明**：本版本已删除连接列表、流量统计、配额与指标查询等命令。因此排查问题只依赖两样东西：**运行状态**和**日志**。

---

## 查看运行状态

### 服务器

```sh
mita status
```

如果输出 `mita server status is "RUNNING"`，说明代理服务正在运行。如果输出 `"STOPPED"`，说明守护进程没有在运行，可以用 `mita start` 启动。`mita start`（以及 `mieru start`）会先校验配置，配置非法时立即报错且不会启动守护进程，因此如果 `start` 立即失败，请先检查配置。

### 客户端

```sh
mieru status
```

如果输出 `mieru client status is "RUNNING"`，说明客户端正在运行；输出 `"STOPPED"` 说明客户端没有在运行。客户端监听的 socks5 地址记录在客户端日志中。

---

## 查看日志

### 服务器 (mita)

服务器日志输出到守护进程的标准输出。由 systemd 托管时，可以用 journalctl 查看：

```sh
sudo journalctl -u mita -xe --no-pager
```

只看最后若干行可以加上 `-n`，例如：

```sh
sudo journalctl -u mita -xe --no-pager -n 200
```

如果是用 `mita start` 直接启动后台守护进程，可以按需把 `mita start` 的标准输出重定向到文件。调试时更简单的方式是用 `mita run` 在前台运行，日志直接打印到终端。

### 客户端 (mieru)

| 操作系统 | 日志目录 | 示例 |
|----------|----------|------|
| Linux | `$HOME/.cache/mieru/` 或 `$XDG_CACHE_HOME/mieru/` | `/home/enfein/.cache/mieru/` |
| macOS | `$HOME/Library/Caches/mieru/` | `/Users/enfein/Library/Caches/mieru/` |
| Windows | `%USERPROFILE%\AppData\Local\mieru\` | `C:\Users\enfein\AppData\Local\mieru\` |

日志文件命名格式：`yyyyMMdd_HHmm_PID.log`。每次重启 mieru 会生成新文件。日志数量过多时，旧文件会被自动清理。

客户端以 `mieru start` 后台运行时，日志写入上表中的日志目录；直接用 `mieru run` 在前台运行时，日志打印到当前终端。

---

## 打开和关闭调试日志

默认情况下，mieru / mita 打印的日志非常少，且不包含 IP 地址、端口号等敏感信息。如需诊断单个网络连接，可以打开调试日志。

仓库在 `configs/templates/` 目录下提供了模板文件。

**服务器：**

```sh
# 启用
mita apply config server_enable_debug_logging.json
mita stop
mita start

# 关闭
mita apply config server_disable_debug_logging.json
mita stop
mita start
```

**客户端：**

```sh
# 启用
mieru apply config client_enable_debug_logging.json
mieru stop
mieru start

# 关闭
mieru apply config client_disable_debug_logging.json
mieru stop
mieru start
```

日志等级由 `loggingLevel` 字段控制，可选值为 `FATAL`、`ERROR`、`WARN`、`INFO`、`DEBUG`、`TRACE`。改动 `loggingLevel` 也需要重启对应的程序才能生效。

---

## 密码套件协商

客户端与服务端在握手时协商密码套件。可选套件为 `CIPHER_SUITE_XCHACHA20_POLY1305`、`CIPHER_SUITE_AES_256_GCM` 和 `CIPHER_SUITE_AES_128_GCM`，配置字段的含义与协商规则见[密码套件](./protocol.md#密码套件)与[版本与套件协商](./protocol.md#版本与套件协商)。日常运维需要注意下面几点。

1. **协议版本与兼容性。** 本版本使用协议版本 2 与 3 的握手。协议版本 1 的旧客户端发出的握手请求会被服务端判为「无共同版本」，服务端返回 `status` = 1 并关闭会话。协议版本 3 与版本 2 之间也不是双向兼容：v3 服务端同时兼容 v2 与 v3 客户端，但 v2 服务端只兼容 v2 客户端，v3 客户端无法与 v2 服务端建立会话（v3 客户端用 4096 次派生的静态密钥并携带 keyed 用户提示，v2 服务端只尝试 64 次派生、只识别旧提示）。因此升级**必须两端同步**：只升级一端会让所有会话在握手阶段被拒绝，现象与「完全无法连接」相同。套件协商发生在握手的内部，所以它不能用来兼容旧客户端。
2. **查看生效的套件。** 服务端用 `mita describe config`，客户端用 `mieru describe config`，查看输出里的 `cipherSuites` 字段。如果没有该字段或者列表为空，说明仍在使用默认行为：客户端只使用 `CIPHER_SUITE_XCHACHA20_POLY1305`，服务端接受全部套件。实际使用的套件由两端在握手时协商：先取两个列表的交集，再在交集中按服务端偏好顺序选出最终成员。**只有协商出协议版本 2 时**，才会额外要求该成员的长度不超过客户端列表首项（信封套件）的密钥长度，因此当对端是 v2 服务端时，把 `CIPHER_SUITE_AES_128_GCM` 放在客户端首位会排除两种 32 字节密钥的套件；交集为空、或（v2 下）交集中没有满足密钥长度限制的成员时，握手失败（服务端返回 `status` = 2 并记录日志）。协议版本 3 不受这条密钥长度限制，交集中的任何套件都可能被选中。
3. **建议优先使用 XChaCha20-Poly1305。** 也就是保持默认，或者把 `CIPHER_SUITE_XCHACHA20_POLY1305` 写在客户端与服务端列表的第一项。它的性能不依赖 CPU 的硬件特性；而在没有 AES 硬件指令的 CPU 上，Go 标准库中 AES-GCM 的软件实现必须使用常数时间的实现，速度会明显下降。
4. **两端 CPU 差异较大、并且都支持 AES-NI 时，可以改用 AES-256-GCM。** 如果服务器与客户端的 CPU 都支持 AES 硬件指令（x86 的 AES-NI、ARM 的 Crypto Extension），可以把两端的 `cipherSuites` 都设置为以 `CIPHER_SUITE_AES_256_GCM` 开头的列表。只有在确认两端都有硬件加速时才建议这样做，其余情况请保留 XChaCha20-Poly1305。

---

## 常见问题速查

### 症状：应用配置时提示 unknown field

错误示例：

```text
common.UnmarshalJSON() failed: proto: (line 2:2): unknown field "profiles"
```

```text
common.UnmarshalJSON() failed: proto: (line 2:2): unknown field "portBindings"
```

这通常表示配置文件被应用到了错误的程序。如果 `mita` 报告 `profiles` 等未知字段，很可能是它正在读取客户端配置；如果 `mieru` 报告 `portBindings` 或 `users` 等未知字段，很可能是它正在读取服务器配置。

请使用匹配的命令：

```sh
mita apply config <server_config.json>
mieru apply config <client_config.json>
```

另外，如果配置是从旧版本沿用而来，其中可能含有本版本已删除的字段：客户端配置里的 `httpProxyPort`、`httpProxyListenLAN`、`noCheckUpdate`、`rpcPort` 与 `advancedSettings`，以及服务器配置里 `users` 下的 `quotas`。请先从配置文件中删除这些字段，再重新应用。

### 症状：完全无法连接

| 步骤 | 命令/操作 | 检查内容 |
|------|-----------|----------|
| 1 | `ping <server_ip>` | 确认基础网络可达性。 |
| 2 | `mita status`（服务器端） | 确认代理服务处于 `RUNNING` 状态。 |
| 3 | `mieru status`（客户端） | 确认客户端已启动。 |
| 4 | `mieru describe config` 与 `mita describe config` | 对比**端口**、**协议**、**用户名**和**密码**，必须完全一致；同时确认两端的 `cipherSuites` 有交集，且两端都能运行本次握手所需的协议版本（v1 客户端不再被支持；v3 客户端需要 v3 服务端，只有 v2 服务端时无法建连，见[密码套件协商](#密码套件协商)）。如果对端是 v2 服务端，还要确认交集中有密钥长度不超过客户端列表首项（信封套件）的套件。 |
| 5 | `date`（两端均执行） | 确认两端时钟偏差不超过 1 分钟；偏差超过 1 分钟会握手失败。 |
| 6 | 在两端启用调试日志并重启 | 在日志中查找 `handshake`、`cipher` 或 `underlay` 相关错误；服务器的解密失败通常表现为无法识别用户或密钥不匹配。 |
| 7 | 检查服务器防火墙 | 确认配置文件里 `portBindings` 声明的 TCP / UDP 端口对公网开放。 |
| 8 | `mita describe config`（服务器端） | 服务端默认要求首包携带匹配的用户提示，配置项 `advancedSettings` -> `userHintIsMandatory` 的默认值是 `true`；未命中提示的源还会在 10 秒内被负缓存直接拒绝。使用不带提示的旧客户端、或两端用户名/密码不一致时，首包会被丢弃。只有该字段被显式设置为 `false` 才会关闭这一要求。 |

### 症状：连接一段时间后断开

| 可能原因 | 如何检查 | 解决方法 |
|----------|----------|----------|
| 服务器防火墙关闭了空闲端口 | 调试日志显示连接被重置，且断开前一段时间没有流量 | 使用更大的端口范围，或在应用层启用 keepalive。 |
| 客户端或服务器重启 | 检查日志时间戳与断开时间是否吻合 | 服务器端确保守护进程随系统启动（例如配置 systemd 服务）。 |
| 网络链路限速 / QoS | 仅在高峰时段降速 | 改用 UDP 协议或启用流量混淆。 |
| 服务器侧的端口映射（NAT）超时 | 空闲一段时间后必断 | 缩短客户端的空闲时间或改用流量混淆，避免长时间无数据。 |

### 症状：速度非常慢

| 可能原因 | 如何检查 | 解决方法 |
|----------|----------|----------|
| TCP 拥塞控制未使用 BBR | `sysctl net.ipv4.tcp_congestion_control` | 参见 [BBR 拥塞控制算法](./server-install.md#bbr-拥塞控制算法)。 |
| MTU 不匹配导致分片 | `ping -M do -s 1372 <server>`（Linux） | 在两端将 `mtu` 设为相同的值（取值范围 1280 到 1500，例如 1280）后再次测试。 |
| 多路复用过于激进 | 调试日志显示短时间内建立大量连接 | 将 `multiplexing` 的 `level` 降为 `MULTIPLEXING_LOW` 或 `MULTIPLEXING_MIDDLE`。 |
| 服务器负载过高 | `top` / `uptime` 查看 CPU 与负载 | 减少单机用户数量，或增加服务器数量分摊流量。 |
| 加密与填充开销 | 启用了低熵模式或较大的填充长度 | 参见[流量模式](./traffic-pattern.md)，适当降低填充与低熵模式的强度。 |

### 症状：客户端无法启动

| 可能原因 | 如何检查 | 解决方法 |
|----------|----------|----------|
| 端口已被占用 | `lsof -i :1080`（macOS/Linux）或 `netstat -ano \| findstr 1080`（Windows） | 更换 `socks5Port` 为未占用的端口。 |
| 配置文件 JSON 语法错误 | `mieru apply config` 打印错误 | 修正 JSON 语法后重新应用。 |
| 权限不足（Linux） | 客户端二进制文件无执行权限 | `chmod +x mieru` 或通过软件包安装。 |
| 日志目录不可写 | 启动日志提示无法创建日志文件 | 检查上表中的日志目录权限。 |

---

## 配置文件存放位置

### 服务器

| 文件 | 路径 | 格式 |
|------|------|------|
| 配置 | `/etc/mita/server.conf.pb` | Protocol buffer（二进制） |

服务器**不**存储密码明文，仅保存校验码。

### 客户端

| 操作系统 | 配置路径 | 示例 |
|----------|----------|------|
| Linux | `$HOME/.config/mieru/client.conf.pb` | `/home/enfein/.config/mieru/client.conf.pb` |
| macOS | `$HOME/Library/Application Support/mieru/client.conf.pb` | `/Users/enfein/Library/Application Support/mieru/client.conf.pb` |
| Windows | `%USERPROFILE%\AppData\Roaming\mieru\client.conf.pb` | `C:\Users\enfein\AppData\Roaming\mieru\client.conf.pb` |

`apply config`、`replace config`、`describe config`、`import config` 等命令读写的都是上表中的文件。

---

## 环境变量

| 变量 | 用途 |
|------|------|
| `MITA_CONFIG_JSON_FILE` | 从该路径加载 JSON 格式服务器配置文件。 |
| `MITA_CONFIG_FILE` | 从该路径加载 protobuf 格式服务器配置文件。 |
| `MIERU_CONFIG_JSON_FILE` | 从该路径加载 JSON 格式客户端配置文件。 |
| `MIERU_CONFIG_FILE` | 从该路径加载 protobuf 格式客户端配置文件。 |
| `MITA_LOG_NO_TIMESTAMP` | 非空时，服务器日志不打印时间戳（配合 journald 使用）。 |

**示例：使用自定义配置文件在前台运行客户端**

```sh
MIERU_CONFIG_JSON_FILE=/etc/mieru_client_config.json mieru run
```

日志直接输出到终端。按 `Ctrl+C` 退出。

---

## 修改设置后如何生效

修改设置分两步：先用命令把 JSON 文件写入本地配置，再重启对应的程序。

```sh
# 服务器
mita apply config <FILE>       # 合并写入；要整体替换则用 mita replace config <FILE>
mita stop
mita start

# 客户端
mieru apply config <FILE>      # 合并写入；要整体替换则用 mieru replace config <FILE>
mieru stop
mieru start
```

需要重启的原因：守护进程在启动代理服务时读取一次配置，之后配置文件的改动不会自动作用于已经运行的代理服务。因此**本版本不再提供局部重载配置的能力**，任何改动（包括 `loggingLevel`、监听端口、用户列表）都要通过 `stop` + `start` 生效。

如果只想确认当前生效的设置，用 `mita describe config` 或 `mieru describe config` 查看。
