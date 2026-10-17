# 客户端安装与配置

## 下载 mieru 客户端

mieru 客户端软件支持 Windows，Mac OS 和 Linux 系统。你可以从源码编译，也可以直接使用已经编译好的 `mieru` 可执行文件。

### 从源码编译

按照[编译](./compile.md)文档准备好编译环境，然后在项目根目录运行：

```sh
make build
```

编译结果位于 `bin/` 目录。把 `bin/mieru` 复制到系统路径 `PATH` 即可。

### 使用已编译的二进制

如果你已经获得编译好的 `mieru` 可执行文件，解压缩后将其复制到系统路径 `PATH` 中即可。

## 修改客户端的设置

用户可以通过

```sh
mieru apply config <FILE>
```

指令来修改客户端的设置，这里的 `<FILE>` 是一个 JSON 格式的配置文件。该配置文件不需要指定完整的客户端设置。运行指令 `mieru apply config <FILE>` 时，文件内容会合并到任何已有的客户端设置。

要替换整个已保存的配置，请提供含有完整客户端设置的 JSON 文件：

```sh
mieru replace config <FILE>
```

客户端配置的一个示例如下。

```js
{
    "profiles": [
        {
            "profileName": "default",
            "user": {
                "name": "user1",
                "password": "password1"
            },
            "servers": [
                {
                    "ipAddress": "12.34.56.78",
                    "domainName": "",
                    "portBindings": [
                        {
                            "portRange": "2012-2022",
                            "protocol": "TCP"
                        },
                        {
                            "port": 2027,
                            "protocol": "TCP"
                        }
                    ]
                }
            ],
            "mtu": 1400,
            "multiplexing": {
                "level": "MULTIPLEXING_HIGH"
            },
            "handshakeMode": "HANDSHAKE_STANDARD",
            "cipherSuites": [
                "CIPHER_SUITE_XCHACHA20_POLY1305",
                "CIPHER_SUITE_AES_256_GCM"
            ]
        }
    ],
    "activeProfile": "default",
    "socks5Port": 1080,
    "loggingLevel": "INFO",
    "socks5ListenLAN": false
}
```

请用文本编辑器修改如下的内容：

1. 在 `profiles` -> `user` -> `name` 属性中，填写用户名。此处必须与代理服务器中的设置相同。
2. 在 `profiles` -> `user` -> `password` 属性中，填写密码。此处必须与代理服务器中的设置相同。
3. 在 `profiles` -> `servers` -> `ipAddress` 属性中，填写代理服务器的公网地址。支持 IPv4 和 IPv6 地址。
4. 【可选】如果你为代理服务器注册了域名，请在 `profiles` -> `servers` -> `domainName` 中填写域名。否则，请勿修改这个属性。
5. 在 `profiles` -> `servers` -> `portBindings` -> `port` 中填写 mita 监听的 TCP 或 UDP 端口号。这个端口号必须与代理服务器中的设置相同。如果想要监听连续的端口号，也可以改为使用 `portRange` 属性。
6. 【可选】请为 `profiles` -> `mtu` 属性指定一个从 1280 到 1500 之间的值，默认值为 1400。该值是 L3 MTU，即网络路径能够通过的最大 IP 报文长度；UDP 代理协议的有效载荷预算会在此基础上另外扣除 IP 报文头与 UDP 报文头（IPv6 下最多 48 字节）。这个值必须与代理服务器相同；只有两端取值一致，才能避免因分片导致的性能下降。
7. 【可选】如果想要调整多路复用的频率，是更多地创建新连接，还是更多地重用旧连接，可以为 `profiles` -> `multiplexing` -> `level` 属性设定一个值。这里可以使用的值包括 `MULTIPLEXING_OFF`, `MULTIPLEXING_LOW`, `MULTIPLEXING_MIDDLE`, `MULTIPLEXING_HIGH`。其中 `MULTIPLEXING_OFF` 会关闭多路复用功能。默认值为 `MULTIPLEXING_LOW`。
8. 【可选】如果想开启 0-RTT 握手，请将 `profiles` -> `handshakeMode` 属性的值设置为 `HANDSHAKE_NO_WAIT`，否则请设置为 `HANDSHAKE_STANDARD`。默认值为 `HANDSHAKE_STANDARD`。
9. 【可选】`profiles` -> `cipherSuites` 属性是客户端愿意使用的密码套件列表，**第一个元素最优先**。可以使用的值包括 `CIPHER_SUITE_XCHACHA20_POLY1305`，`CIPHER_SUITE_AES_256_GCM` 和 `CIPHER_SUITE_AES_128_GCM`。**未设置或者设置为空列表时，客户端只使用 `CIPHER_SUITE_XCHACHA20_POLY1305`**，与旧版本配置的行为一致。会话最终使用的套件由客户端与服务端在握手时协商决定，规则和适用场景见[密码套件](./protocol.md#密码套件)。列表的第 0 项还会决定握手信封的密钥长度：**当协商出协议版本 2 时**，服务端只会从交集中挑选密钥长度不超过它的套件，因此把 `CIPHER_SUITE_AES_128_GCM` 排在首位会排除另外两种套件；协议版本 3 不受这一限制（详见[版本与套件协商](./protocol.md#版本与套件协商)）。
10. 请为 `socks5Port` 属性指定一个从 1025 到 65535 之间的数值。
11. 【可选】如果客户端需要为局域网中的其他设备提供代理服务，请将 `socks5ListenLAN` 属性设置为 `true`。

用户与端口设置的取值需通过校验，否则 `mieru apply config` 会报错：

- `profiles` -> `user` -> `name` 不能为空，且不超过 64 字节。
- `user` 必须设置 `password` 或 `hashedPassword` 之一。`password` 是明文口令，长度必须在 8 到 64 字节之间，不能全部由数字组成，也不能是同一个字符的重复。`hashedPassword` 是口令 SHA-256 摘要的十六进制表示，必须恰好为 64 个十六进制字符（32 字节）。如果同时设置 `password` 和 `hashedPassword`，两者必须一致。
- 同一份配置中不允许存在同名的 profile。
- 每条 `portBindings` 不能同时设置 `port` 和 `portRange`。
- `multiplexing` -> `level` 只接受 `MULTIPLEXING_OFF`、`MULTIPLEXING_LOW`、`MULTIPLEXING_MIDDLE`、`MULTIPLEXING_HIGH` 等合法的枚举值，非法取值会报错。
- `profiles` -> `cipherSuites` 只接受 `CIPHER_SUITE_XCHACHA20_POLY1305`、`CIPHER_SUITE_AES_256_GCM`、`CIPHER_SUITE_AES_128_GCM` 等合法的枚举值，不能包含 `CIPHER_SUITE_UNSPECIFIED`，非法取值或拼写错误会报错；列表中的重复项会被忽略，只保留第一次出现的那个，因此相对偏好顺序保持不变。

> **注意**：本版本已移除 HTTP / HTTPS 代理功能、客户端自动更新检查功能与本地控制接口，配置中不再支持 `httpProxyPort`、`httpProxyListenLAN`、`noCheckUpdate`、`rpcPort` 和客户端 `advancedSettings` 字段。如果你从旧版本升级，请先从配置文件中删除这些字段，否则 `mieru apply config`、`mieru import config` 或 `mieru run` 会报未知字段（unknown field）错误。

如果你安装了多台代理服务器，或者一台服务器监听多个端口，可以把它们都添加到客户端设置中。每次发起新的连接时，mieru 会随机选取其中的一台服务器和一个端口。**如果使用了多台服务器，请确保每一台服务器都启动了 mita 代理服务。**

假设这个配置文件的文件名是 `client_config.json`，在修改完成之后，调用指令 `mieru apply config client_config.json` 写入该配置。

如果配置有误，mieru 会打印出现的问题。请根据提示修改配置文件，重新运行 `mieru apply config <FILE>` 指令写入修正后的配置。

写入后，可以用

```sh
mieru describe config
```

指令查看当前设置。

## 启动客户端

```sh
mieru start
```

`mieru start` 会在后台启动客户端守护进程：守护进程会脱离当前终端，命令执行完即可返回，关闭终端不会影响客户端运行。启动是否成功、监听的 socks5 地址，都可以在日志中确认（见[运营维护与故障排查](./operation.md)）。

调试时可以在前台运行客户端，日志直接输出到当前终端，按 `Ctrl+C` 退出：

```sh
mieru run
```

mieru 客户端不会与系统一同启动。在重新启动计算机后，需要手动使用 `mieru start` 指令启动客户端。`mieru start` 会先加载并校验客户端配置，配置非法时立即报错、不会启动守护进程。客户端守护进程的 pid 记录在客户端配置目录下的 `mieru.pid` 文件中。该文件在 Linux 上记录进程号与进程的启动时刻（格式为 `<pid> <starttime>`），`mieru stop` 在发送信号前会核对进程身份，避免误伤恰好复用了同一 PID 的其他进程；在无法获取启动时刻的平台上，该文件退化为只记录进程号。文件路径保持不变，仍为客户端配置目录下的 `mieru.pid`。

如果需要停止 mieru 客户端，请输入指令

```sh
mieru stop
```

`mieru stop` 会读取 pid 文件，向客户端守护进程发送终止信号并等待其退出。

使用指令

```sh
mieru status
```

可以查询客户端当前的运行状态。

注意，每次使用 `mieru apply config <FILE>` 或 `mieru replace config <FILE>` 修改设置后，需要用 `mieru stop` 和 `mieru start` 重启客户端，才能使新设置生效。

## 测试客户端与服务器的连接

本版本不再提供内置的连接测试命令。可以借助任意支持 socks5 的工具验证链路：把客户端 `socks5Port` 指向的地址当作代理来访问一个网站。例如使用 curl：

```sh
curl -x socks5://127.0.0.1:1080 https://example.com
```

如果正常返回网页内容，说明客户端到代理服务器的链路可用。浏览器中配置 socks5 代理的方法见下一节。

## 配置浏览器

Chrome / Firefox 等浏览器可以通过安装插件，使用 socks5 代理访问网站。关于 socks5 代理的地址，请填写 `127.0.0.1:xxxx`，其中 `xxxx` 是客户端设置中 `socks5Port` 的值。

默认情况下，mieru 不要求应用程序提供 socks5 用户名和密码；如需开启验证，请参见下文 [socks5 用户名和密码验证](#socks5-用户名和密码验证)。

客户端内置的 socks5 服务端只接受版本号为 `5` 的请求，其他版本字节会被拒绝。对于 socks5 UDP ASSOCIATE，客户端会按请求中声明的客户端地址校验数据报来源，来源不符的数据报会被丢弃。

## Clash 设置

如果使用 Clash.Meta / mihomo 客户端，请参考下面的配置。

```yaml
proxies:
  - name: server1
    type: mieru
    server: 12.34.56.78
    port-range: 2012-2022
    transport: TCP
    udp: true
    username: user1
    password: password1
    multiplexing: MULTIPLEXING_HIGH
  - name: server2
    type: mieru
    server: 12.34.56.78
    port: 2027
    transport: TCP
    udp: true
    username: user1
    password: password1
    multiplexing: MULTIPLEXING_HIGH
```

使用 `udp: true` 允许 socks5 UDP associate 请求。你不能在一条配置内同时使用 `port` 和 `port-range` 属性。

## 高级设置

### 通过 socks5 代理连接 mita 服务器

如果 mieru 客户端必须通过已有的 socks5 代理连接 mita 服务器，可以在客户端 profile 中添加 `dialer` 对象。没有 `dialer` 的已有 profile 会继续直接连接 mita。

```js
{
    "profiles": [
        {
            "profileName": "default",
            "user": {
                ...
            },
            "servers": [
                ...
            ],
            "dialer": {
                "protocol": "SOCKS5_PROXY_PROTOCOL",
                "host": "127.0.0.1",
                "port": 1081,
                "socks5UDPAssociate": true,
                "socks5Authentication": {
                    "user": "proxy-user",
                    "password": "proxy-password"
                }
            }
        }
    ]
}
```

当前只支持 `SOCKS5_PROXY_PROTOCOL`。`host` 和 `port` 必须填写。`socks5Authentication` 是可选的；如果填写，则 `user` 和 `password` 都必须设置。

将 `socks5UDPAssociate` 设置为 `true`，可以通过 socks5 UDP ASSOCIATE 连接 mita 代理服务器。如果它为 `false` 或未填写，UDP 流量不会通过 socks5 代理。

### socks5 用户名和密码验证

如果你想要让应用程序必须通过用户名和密码验证才能访问 socks5 代理，可以在客户端设置中添加 `socks5Authentication` 属性。一个示例如下：

```js
{
    "socks5Authentication": [
        {
            "user": "user1",
            "password": "password1"
        },
        {
            "user": "user2",
            "password": "password2"
        }
    ]
}
```

应用程序可以选择 `socks5Authentication` 列表中的任意一组用户名和密码访问 socks5 代理。

如果想要关闭 socks5 用户名和密码验证，请先用 `mieru replace config <FILE>` 写入一份不再包含 `socks5Authentication` 属性的完整配置，然后重启客户端。

### 密码套件

如果客户端要使用默认套件之外的密码套件，可以在 profile 中设置 `cipherSuites`。它是一个**有序的偏好列表，第一个元素最优先**：

```js
{
    "profiles": [
        {
            "profileName": "default",
            "user": {
                ...
            },
            "servers": [
                ...
            ],
            "cipherSuites": [
                "CIPHER_SUITE_XCHACHA20_POLY1305",
                "CIPHER_SUITE_AES_256_GCM"
            ]
        }
    ]
}
```

请连同该 profile 的其它必要字段一起填写：应用配置补丁时，补丁中出现的 profile 会整体替换同名的已有 profile，因此只写 `profileName` 和 `cipherSuites` 会丢失原来的 `user`、`servers` 等设置。也可以直接修改[上文](#修改客户端的设置)的完整配置示例，再使用 `mieru replace config <FILE>` 写入。

可以使用的值包括 `CIPHER_SUITE_XCHACHA20_POLY1305`，`CIPHER_SUITE_AES_256_GCM` 和 `CIPHER_SUITE_AES_128_GCM`。未设置 `cipherSuites` 或者设置为空列表时，客户端只使用 `CIPHER_SUITE_XCHACHA20_POLY1305`，因此不含有该字段的旧版本配置文件可以继续使用，行为保持不变。

会话实际使用的套件由两端在握手时协商：先取「客户端列表」与「服务端允许集合」的交集，再在交集中按**服务端偏好顺序**选出最终成员，因此最终套件可能不是客户端列表的第一项。**只有协商出协议版本 2 时**，才会额外要求该成员的长度不超过客户端列表第 0 项（信封套件）的密钥长度：对端是 v2 服务端时，把 `CIPHER_SUITE_AES_128_GCM`（16 字节密钥）排在首位，`CIPHER_SUITE_XCHACHA20_POLY1305` 与 `CIPHER_SUITE_AES_256_GCM`（都是 32 字节密钥）都不会被选中；只要服务端的允许集合中包含 `CIPHER_SUITE_AES_128_GCM`，双方就会协商出它并正常建立会话。反之，如果交集为空，或者（在 v2 下）交集中没有任何密钥长度不超过信封套件的成员，握手就会失败，服务端返回 `status` = 2。协议版本 3 用协商出的套件派生会话密钥，不受密钥长度限制，交集中的任何套件都可能被选中，因此 v3 下把密钥更短的套件放在首位不会再排除密钥更长的套件。无论如何，两端至少要有一个共同的套件。

一般建议保留默认的 `CIPHER_SUITE_XCHACHA20_POLY1305`：它的性能不依赖 CPU 的硬件特性。`CIPHER_SUITE_AES_256_GCM` 与 `CIPHER_SUITE_AES_128_GCM` 只有在 CPU 支持 AES 硬件指令时才有优势，详见[密码套件](./protocol.md#密码套件)；运维和排查注意事项见[密码套件协商](./operation.md#密码套件协商)。

## 分享客户端的设置

用户可以使用 `mieru export config` 或者 `mieru export config simple` 指令生成 URL 链接，来分享客户端的配置。这些 URL 链接可以使用 `mieru import config <URL>` 指令导入至其他客户端。

### 标准分享链接

使用指令 `mieru export config` 生成一个标准分享链接。例如：

```
mieru://<base64 编码的客户端配置>
```

标准分享链接以 `mieru://` 开始，使用 base64 编码完整的客户端配置。用户可以使用标准分享链接在一台全新的设备上复刻客户端配置。

### 简单分享链接

使用指令 `mieru export config simple` 生成人类可读的简单分享链接。例如：

```
mierus://user1:password1@1.2.3.4?handshake-mode=HANDSHAKE_NO_WAIT&mtu=1400&multiplexing=MULTIPLEXING_HIGH&port=6666&port=10000-10001&port=10002&port=10003&profile=default&protocol=TCP&protocol=TCP&protocol=UDP&protocol=UDP&traffic-pattern=CCoQARoECAEQCiIYCAMQASoIMDAwMTAyMDMqCDA0MDUwNjA3
```

简单分享链接的格式如下：

`mierus://用户名:密码@服务器地址?参数列表`

简单分享链接以 `mierus://` 开始，其中 `s` 表示 `simple`。

简单分享链接中只有一个服务器地址。如果客户端的设置含有多台服务器，则会生成多个链接。

链接中支持的参数列表如下：

- `profile`
- `mtu`
- `multiplexing`
- `handshake-mode`
- `cipher-suites`
- `traffic-pattern`
- `port`
- `protocol`

其中 `profile` 必须出现一次，`mtu`，`multiplexing`，`handshake-mode`，`cipher-suites` 以及 `traffic-pattern` 最多出现一次，`port` 和 `protocol` 可以出现多次，且他们出现的次数必须相同，以便将同一位置上的 `port` 和 `protocol` 联系起来。另外 `port` 也可以用来指定一段连续的端口。`traffic-pattern` 的值使用 base64 编码的 protobuf 格式，与[流量模式](./traffic-pattern.md)文档中描述的字段一一对应。

`cipher-suites` 的值是用逗号分隔的套件枚举名列表，顺序即客户端的偏好顺序，例如 `cipher-suites=CIPHER_SUITE_XCHACHA20_POLY1305,CIPHER_SUITE_AES_256_GCM`。如果 profile 设置了 `cipherSuites`，`mieru export config simple` 生成的链接中就会包含该参数；链接中省略该参数等同于未设置 `cipherSuites`，即客户端只使用 `CIPHER_SUITE_XCHACHA20_POLY1305`。如果列表中含有无法识别的套件名，或者其中含有 `CIPHER_SUITE_UNSPECIFIED`，`mieru import config <URL>` 会报错。

上面的简单分享链接等同于如下的客户端配置片段：

```js
{
    "profileName":  "default",
    "user":  {
        "name":  "user1",
        "password":  "password1"
    },
    "servers":  [
        {
            "ipAddress":  "1.2.3.4",
            "portBindings":  [
                {
                    "port":  6666,
                    "protocol":  "TCP"
                },
                {
                    "protocol":  "TCP",
                    "portRange":  "10000-10001"
                },
                {
                    "port":  10002,
                    "protocol":  "UDP"
                },
                {
                    "port":  10003,
                    "protocol":  "UDP"
                }
            ]
        }
    ],
    "mtu":  1400,
    "multiplexing":  {
        "level":  "MULTIPLEXING_HIGH"
    },
    "handshakeMode":  "HANDSHAKE_NO_WAIT",
    "trafficPattern":  {
        "seed":  42,
        "unlockAll":  true,
        "tcpFragment":  {
            "enable":  true,
            "maxSleepMs":  10
        },
        "nonce":  {
            "type":  "NONCE_TYPE_FIXED",
            "applyToAllUDPPacket":  true,
            "customHexStrings":  [
                "00010203",
                "04050607"
            ]
        }
    }
}
```

简单分享链接只包含服务器、用户与流量模式等最少的必要信息，不含有 `socks5Port` 等本机配置。因此，在全新的设备上导入简单分享链接会失败；如需完整复制配置，请使用标准分享链接。
