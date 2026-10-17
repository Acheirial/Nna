# 服务器安装与配置

代理服务器软件 mita 需要运行在 Linux 系统中。

## 安装 mita

你可以从源码编译，也可以直接使用已经编译好的 `mita` 可执行文件。

### 从源码编译

按照[编译](./compile.md)文档准备好编译环境，然后在项目根目录运行：

```sh
make build
```

编译结果位于 `bin/` 目录。把 `mita` 复制到系统路径 `PATH` 即可，例如：

```sh
sudo install -m 755 bin/mita /usr/local/bin/mita
```

### 使用已编译的二进制

如果你已经获得编译好的 `mita` 可执行文件，直接将其复制到系统路径 `PATH` 中即可，例如 `/usr/local/bin/`。

## 修改代理服务器设置

mieru 代理支持 TCP 和 UDP 两种不同的传输协议。要了解协议之间的差别，请阅读 [mieru 代理协议](./protocol.md)。

用户可以通过

```sh
mita apply config <FILE>
```

指令来修改代理服务器的设置，这里的 `<FILE>` 是一个 JSON 格式的配置文件。该配置文件不需要指定完整的代理服务器设置。运行指令 `mita apply config <FILE>` 时，文件内容会合并到任何已有的代理服务器设置。

要替换整个已保存的配置，请提供含有完整代理服务器设置的 JSON 文件：

```sh
mita replace config <FILE>
```

下面是服务器配置文件的一个例子。

```js
{
    "portBindings": [
        {
            "portRange": "2012-2022",
            "protocol": "TCP"
        },
        {
            "port": 2027,
            "protocol": "TCP"
        }
    ],
    "users": [
        {
            "name": "user1",
            "password": "password1"
        },
        {
            "name": "user2",
            "password": "password2"
        }
    ],
    "loggingLevel": "INFO",
    "mtu": 1400,
    "dns": {
        "dualStack": "PREFER_IPv4"
    },
    "cipherSuites": [
        "CIPHER_SUITE_XCHACHA20_POLY1305",
        "CIPHER_SUITE_AES_256_GCM",
        "CIPHER_SUITE_AES_128_GCM"
    ]
}
```

1. `portBindings` -> `port` 属性是 mita 监听的 TCP 或 UDP 端口号，请指定一个从 1025 到 65535 之间的值。如果想要监听连续的端口号，也可以改为使用 `portRange` 属性。**请确保防火墙允许使用这些端口进行通信。**
2. `portBindings` -> `protocol` 属性可以使用 `TCP` 或者 `UDP`。
3. 在 `users` -> `name` 属性中填写用户名。
4. 在 `users` -> `password` 属性中填写该用户的密码。
5. 【可选】`mtu` 属性是使用 UDP 代理协议时网络路径的 L3 MTU，即能够通过的最大 IP 报文长度，取值范围是 1280 到 1500，默认值是 1400。UDP 的有效载荷预算会在此基础上另外扣除 IP 报文头与 UDP 报文头（IPv6 下最多 48 字节，即 40 字节 IPv6 头加 8 字节 UDP 头）。服务器与客户端必须使用相同的值。
6. 【可选】建议将 `dns` -> `dualStack` 设置为 `PREFER_IPv4`，尤其是在服务器不支持 IPv6 时。其他选项和静态主机映射请参见 [DNS 策略](#dns-策略)。
7. 【可选】`cipherSuites` 属性是服务端允许使用的密码套件列表，**列表顺序就是服务端的偏好顺序**。可以使用的值包括 `CIPHER_SUITE_XCHACHA20_POLY1305`，`CIPHER_SUITE_AES_256_GCM` 和 `CIPHER_SUITE_AES_128_GCM`。**未设置或者设置为空列表时，服务端接受全部三种套件**，与旧版本配置的行为一致。会话最终使用的套件由客户端与服务端在握手时协商决定，规则和适用场景见[密码套件](#密码套件)。只有协商出协议版本 2 时，才会按客户端首选套件（信封套件）的密钥长度过滤候选，细节见该节。

用户与端口设置的取值需通过校验，否则 `mita apply config` 会报错：

- `users` -> `name` 不能为空，且不超过 64 字节。
- 每个用户必须设置 `password` 或 `hashedPassword` 之一。`password` 是明文口令，长度必须在 8 到 64 字节之间，不能全部由数字组成，也不能是同一个字符的重复。`hashedPassword` 是口令 SHA-256 摘要的十六进制表示，必须恰好为 64 个十六进制字符（32 字节）。如果同时设置 `password` 和 `hashedPassword`，两者必须一致。
- 同一份配置中不允许存在同名的用户。
- 每条 `portBindings` 不能同时设置 `port` 和 `portRange`。
- `cipherSuites` 只接受 `CIPHER_SUITE_XCHACHA20_POLY1305`、`CIPHER_SUITE_AES_256_GCM`、`CIPHER_SUITE_AES_128_GCM` 等合法的枚举值，不能包含 `CIPHER_SUITE_UNSPECIFIED`，非法取值或拼写错误会报错；列表中的重复项会被忽略，只保留第一次出现的那个，因此相对偏好顺序保持不变。

除此之外，mita 可以监听多个不同的端口。我们建议在服务器和客户端配置中使用多个端口。

如果你想把代理线路分享给别人使用，也可以创建多个不同的用户。

假设在服务器上，这个配置文件的文件名是 `server_config.json`，在文件修改完成之后，请调用指令 `mita apply config server_config.json` 写入该配置。

如果配置有误，mita 会打印出现的问题。请根据提示修改配置文件，重新运行 `mita apply config <FILE>` 指令写入修正后的配置。

写入后，可以用

```sh
mita describe config
```

指令查看当前设置。

## 启动代理服务

mita 采用「守护进程 + 命令行」的结构：命令行工具通过 pid 文件与操作系统信号控制后台守护进程，两者之间没有额外的网络接口或本地 socket 通信。守护进程负责监听端口并处理客户端请求。

调试时可以在前台运行守护进程，日志直接输出到当前终端，按 `Ctrl+C` 退出：

```sh
sudo mita run
```

正式使用时，直接运行

```sh
mita start
```

`mita start` 会先加载并校验服务器配置，配置非法时立即报错、不会派生守护进程（因此无需等到启动超时）。校验通过后，它会让守护进程脱离当前终端在后台运行，并在 `/var/run/mita/mita.pid` 中记录进程号，随后 mita 开始监听设置中指定的端口号。因为守护进程已经脱离终端，关闭终端不会影响服务。

接下来，调用指令

```sh
mita status
```

查询工作状态。如果返回 `mita server status is "RUNNING"`，说明代理服务正在运行，可以开始响应客户端的请求了；如果返回 `"STOPPED"`，说明守护进程没有在运行。

UDP 监听端的事件循环如果因为监听套接字出错而异常退出，守护进程会自动重新创建该监听端，两次尝试之间的等待时间从 1 秒起按失败次数翻倍，最长 30 秒，并带有随机抖动；监听端成功运行满 30 秒后，退避会被清零。因此 UDP 端口短暂不可用是正常的自愈过程，**不必**为此重启 mita。唯一的例外是首次监听失败（例如端口被其它进程占用）：这时 `mita start` 会直接报错，需要先解决端口冲突。

如果想要停止服务，请使用指令

```sh
mita stop
```

`mita stop` 会读取 pid 文件，向守护进程发送终止信号并等待它退出；如果它没有及时退出，会强制结束进程。pid 文件在 Linux 上记录进程号与该进程的启动时刻（格式为 `<pid> <starttime>`），`mita stop` 在发送信号前会核对进程身份，避免误伤恰好复用了同一 PID 的其他进程；在无法获取启动时刻的平台上，pid 文件退化为只记录进程号。文件路径保持不变，仍为 `/var/run/mita/mita.pid`。

### 使用 systemd 托管（可选）

也可以用 systemd 等进程管理器托管守护进程，此时需要以 `mita run` 作为 `ExecStart`，让 systemd 负责进程的启动、停止与重启。仓库在 `configs/examples/mita.service` 提供了一个这样的服务单元示例（以 `mita` 用户运行 `/usr/bin/mita run`）。

本仓库不再提供 deb / rpm 安装包，因此 `mita` 用户与相关目录需要手动创建，否则服务无法启动：

```sh
sudo useradd -r -s /usr/sbin/nologin mita
sudo mkdir -p /etc/mita /var/run/mita
sudo chown -R mita:mita /etc/mita /var/run/mita
```

其中 `/etc/mita` 存放服务器配置，`/var/run/mita` 存放守护进程的 pid 文件。

然后把服务单元复制到 `/etc/systemd/system/mita.service`，再执行 `sudo systemctl enable --now mita` 启动。使用 systemd 时用 `systemctl` 而不是 `mita start` / `mita stop` 控制服务，以免两套机制互相干扰。

注意，每次使用 `mita apply config <FILE>` 或 `mita replace config <FILE>` 修改设置后，都需要重启服务（`mita stop` + `mita start`，或 `systemctl restart mita`），才能使新设置生效。本版本不再提供不中断连接的局部重载能力，任何设置改动（包括 `loggingLevel` 与 `users`）都必须通过重启生效。

启动代理服务后，请继续进行[客户端安装与配置](./client-install.md)。

## 高级设置

### 监听 IP 地址

默认情况下，mita 监听所有网络接口。将 `listenIPAddress` 属性设置为一个 IPv4 或 IPv6 地址，即可只监听该地址上的端口。例如，监听 `1.2.3.4`：

```js
{
    "listenIPAddress": "1.2.3.4"
}
```

将 `listenIPAddress` 设置为空字符串 `""`，即可重新监听所有网络接口。

修改 `listenIPAddress` 后，必须依次运行 `mita stop` 和 `mita start`，新的监听地址才会生效。本版本的配置变更一律通过重启生效，运行中不会替换或关闭已有的监听器。如果新的监听地址无法绑定（例如端口已被占用），代理服务会启动失败，具体错误记录在日志中。

### BBR 拥塞控制算法

[BBR](https://en.wikipedia.org/wiki/TCP_congestion_control#TCP_BBR) 是一种不依赖于丢包的拥塞控制算法。在恶劣的网络情况下，使用 BBR 的网络传输速度比传统算法更快。

编辑 `/etc/sysctl.conf`，加入以下内容，然后执行 `sudo sysctl -p` 生效。

```ini
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
```

上述设置可以在服务器和客户端中使用。

### 配置出站代理

出站代理功能允许 mieru 与其他代理工具结合构成链式代理。链式代理的网络拓扑结构的一个例子如下图所示：

```
mieru 客户端 -> 互联网 -> mita 服务器 -> cloudflare 代理客户端 -> cloudflare CDN -> 目标网站
```

通过链式代理，目标网站看到的 IP 地址是 cloudflare CDN 的地址，而不是 mita 服务器的地址。

下面是配置链式代理的一个例子。

```js
{
    "egress": {
        "proxies": [
            {
                "name": "cloudflare",
                "protocol": "SOCKS5_PROXY_PROTOCOL",
                "host": "127.0.0.1",
                "port": 4000,
                "socks5Authentication": {
                    "user": "proxy-user",
                    "password": "proxy-password"
                }
            }
        ],
        "rules": [
            {
                "ipRanges": ["8.8.4.4/32", "8.8.8.8/32"],
                "action": "REJECT"
            },
            {
                "domainNames": ["example.com"],
                "action": "PROXY",
                "proxyNames": ["cloudflare"]
            },
            {
                "ipRanges": ["*"],
                "domainNames": ["*"],
                "action": "DIRECT"
            }
        ]
    }
}
```

1. 在 `egress` -> `proxies` 属性中列举出站代理服务器的信息。当前版本只支持 socks5 出站，因此 `protocol` 的值必须设定为 `SOCKS5_PROXY_PROTOCOL`。如果出站代理服务器需要 socks5 用户名和密码验证，请填写 `socks5Authentication` 属性。否则，请删除 `socks5Authentication` 属性。
2. 在 `egress` -> `rules` 属性中列举出站规则。从上到下，第一条匹配 IP 地址段或 DNS 后缀的规则会被执行。使用通配符 `"*"` 匹配所有 IP 地址或域名。出站行为包括 `DIRECT`，`PROXY` 和 `REJECT`。其中 `PROXY` 行为必须指定 `proxyNames`。`proxyNames` 需要指向 `egress` -> `proxies` 属性中存在的代理。默认的出站行为是 `DIRECT`。规则只作用于有效的目标地址：请求声明域名（`ATYP` = 3）但地址长度为 0 时，请求会在匹配任何规则之前被直接拒绝，因此它不会匹配到 `"*"` 这样的通配规则，也不会被当作 `DIRECT`。

如果想要关闭出站代理功能，将 `egress` 属性设置为空 `{}` 即可。

### DNS 策略

当代理客户端请求域名时，代理服务器会先解析域名，然后再建立连接。可以按如下方式配置 DNS 策略和静态主机映射：

```js
{
    "dns": {
        "dualStack": "PREFER_IPv4",
        "hosts": {
            "example.com": "93.184.216.34",
            "ipv6.example.com": "2606:2800:220:1:248:1893:25c8:1946"
        }
    }
}
```

`dns` -> `dualStack` 属性支持以下值：

1. `USE_FIRST_IP`：使用 DNS 服务器返回的第一个 IP 地址。这是默认策略。
2. `PREFER_IPv4`：优先使用 IPv4，然后回退到 IPv6。
3. `PREFER_IPv6`：优先使用 IPv6，然后回退到 IPv4。
4. `ONLY_IPv4`：仅使用 IPv4。如果没有可用的 IPv4 地址，则连接失败。
5. `ONLY_IPv6`：仅使用 IPv6。如果没有可用的 IPv6 地址，则连接失败。

可选的 `dns` -> `hosts` 属性用于定义静态的域名到 IP 地址映射。每个键必须是域名，每个值必须是有效的 IPv4 或 IPv6 地址。域名采用精确匹配且不区分大小写；不支持通配符和 DNS 后缀匹配。域名不能以点号开头或结尾。

### 允许用户访问内网

默认情况下，代理服务器只允许用户向互联网发起代理请求。

如果需要允许用户通过代理服务器访问私有 IP 地址，例如 `192.168.1.100`，请设置 `users` -> `allowPrivateIP` 属性。

如果需要允许用户通过代理服务器访问服务器本机，例如 `127.0.0.1`，请设置 `users` -> `allowLoopbackIP` 属性。

上述限制对 TCP 连接和 UDP 数据报同时生效：未开启对应权限的用户，无论使用哪种传输协议，都无法访问受限地址。TCP 连接在解析域名之后，会按解析出的 IP 地址**再复查一次**同一套策略（与 UDP 数据报对每个目标地址的检查一致），因此借助指向受限地址的域名（例如 `127-0-0-1.nip.io`）无法绕过限制。此外，socks5 请求声明的地址类型为域名（`ATYP` = 3）而地址长度为 0 时，请求会被直接拒绝：它既不会被当作 `DIRECT`，也不参与出站规则的匹配。被拒绝的目标包括回环地址、私有地址（RFC 1918 / RFC 4193）、链路本地地址（RFC 3927 / RFC 4291，其中包含云服务商的元数据地址 `169.254.169.254`）、CGNAT 地址（`100.64.0.0/10`）以及未指定地址（`0.0.0.0` / `::`）。

```js
{
    "users": [
        {
            "name": "user1",
            "password": "password1",
            "allowPrivateIP": true,
            "allowLoopbackIP": true
        },
        {
            "name": "user2",
            "password": "password2"
        }
    ]
}
```

### 用户提示

从 v3.31.0 版本开始，mieru 客户端会在每个报文 nonce 的末尾附带 4 字节的用户提示（user hint），mita 服务器可以据此跳过明显不匹配的用户，减少对未认证首包的解密尝试次数。代理用户数量较多时，这尤其有帮助。当前客户端发送的是协议版本 3 的 keyed 提示：它由用户名与密码共同派生，旁观者只要不掌握凭据就无法算出，也无法用候选用户名去验证服务端注册了哪些用户。服务端同时接受 keyed 提示与协议版本 2 的 legacy 提示（后者任何人只要知道用户名就能算出），因此不带 keyed 提示的旧客户端仍然可用。

`advancedSettings` -> `userHintIsMandatory` 属性决定服务端是否强制要求首包携带匹配的用户名提示，**它的默认值是 `true`**：没有携带提示、或者提示与任何已注册用户都不匹配的报文会被直接丢弃，不会进入逐用户的试解密。这样一来，未认证首包的试解代价从 Θ(用户数 × 套件数) 降到只对提示匹配的少数用户尝试，显著降低了未认证流量放大服务端 CPU 消耗的风险。在提示为必需的前提下，某个源地址用同一提示试解失败后，其后续报文在 10 秒内会被负缓存直接拒绝，连试解密循环都不会进入；认证成功后该记录会被清除。这条负缓存只在要求提示时才生效，因为提示可选时「提示不匹配」可能只是报文没带提示。

只有在仍需兼容 v3.31.0 之前的旧客户端时才应该关闭它：

```js
{
    "advancedSettings": {
        "userHintIsMandatory": false
    }
}
```

把 `userHintIsMandatory` 显式设置为 `false` 之后，服务端必须对每一个候选用户、每一种套件、每一个时间槽分别尝试解密，未认证首包的试解代价回到 Θ(用户数 × 套件数) 次 AEAD 解封；用户数量较多时，很小的带宽就能把服务器的 CPU 打满，因此在没有兼容旧客户端的需要时不要关闭它。用户提示本身不是认证信息——keyed 提示需要用户名与密码才能算出，legacy 提示则任何人只要知道用户名就能算出——它只影响查找代价，报文能否被接受始终取决于 AEAD 认证标签。

### 密码套件

如果要在服务端限定或者排列密码套件，可以设置顶层的 `cipherSuites` 属性。它是一个**有序的列表，顺序就是服务端的偏好顺序**：

```js
{
    "cipherSuites": [
        "CIPHER_SUITE_AES_256_GCM",
        "CIPHER_SUITE_XCHACHA20_POLY1305"
    ]
}
```

可以使用的值包括 `CIPHER_SUITE_XCHACHA20_POLY1305`，`CIPHER_SUITE_AES_256_GCM` 和 `CIPHER_SUITE_AES_128_GCM`。未设置 `cipherSuites` 或者设置为空列表时，服务端接受全部三种套件，因此不含有该字段的旧版本配置文件可以继续使用，行为保持不变。

会话实际使用的套件由两端在握手时协商：先取「客户端偏好列表」与「服务端允许集合」的交集，再在交集中按**服务端偏好顺序**选出最终成员，因此最终套件可能不是客户端列表的第一项。**只有协商出协议版本 2 时**，才会额外要求该成员的长度不超过客户端首选套件（信封套件，即客户端列表第 0 项）的密钥长度：此时客户端把 `CIPHER_SUITE_AES_128_GCM`（16 字节密钥）排在首位，服务端就不会选择 `CIPHER_SUITE_XCHACHA20_POLY1305` 或 `CIPHER_SUITE_AES_256_GCM`（都是 32 字节密钥）。交集为空，或者（在 v2 下）交集中没有任何密钥长度不超过信封套件的成员时，握手失败，服务端返回 `status` = 2、关闭会话并记录日志，因此两端必须至少有一个共同的套件；如果对端是 v2 客户端且其列表首项是密钥较短的套件，服务端的允许集合里也必须包含密钥长度不超过它的套件。协议版本 3 用协商出的套件派生会话密钥，不按信封套件的密钥长度过滤，交集中的任何套件都可能被选中。

一般建议保留默认行为：不在服务端限制套件，或者把 `CIPHER_SUITE_XCHACHA20_POLY1305` 写在列表的第一项，因为它的性能不依赖 CPU 的硬件特性。只有当服务器与客户端的 CPU 都支持 AES 硬件指令（x86 的 AES-NI、ARM 的 Crypto Extension）时，才建议把 `CIPHER_SUITE_AES_256_GCM` 排在前面；即使两端的 CPU 差异较大，只要双方都支持 AES-NI，也可以统一改用 AES-256-GCM。原理与适用场景见[密码套件](./protocol.md#密码套件)，运维和排查注意事项见[密码套件协商](./operation.md#密码套件协商)。

## 【可选】安装 NTP 网络时间同步服务

客户端和代理服务器软件会根据用户名、密码和系统时间，分别计算密钥。只有当客户端和服务器的密钥相同时，服务器才能解密和响应客户端的请求。密钥派生使用 2 分钟粒度的时间槽，服务器会对当前时间槽以及向前、向后各一个时间槽（共 3 组时间盐）分别尝试解密，因此密钥层面可以容忍客户端时间槽 ±1 个时间槽（2 分钟）的偏差；但连接元数据中携带的时间戳以分钟为单位，只容忍 ±1 分钟的偏差。两者取更严格的一个，**实际生效的容忍区间是 ±1 分钟：客户端与服务器的时钟偏差一旦超过 1 分钟，握手就会失败**。请确保两端系统时间正确。

为了保证服务器系统时间是精确的，我们建议用户启动或安装 NTP 网络时间服务。

在 Linux 中，如果系统时间同步由 `systemd-timesyncd` 服务管理，你可以将 `/etc/systemd/timesyncd.conf` 配置文件更改为如下内容。

```ini
[Time]
NTP=time.google.com
```

否则，使用下面的指令安装 NTP。

```sh
# Debian / Ubuntu
sudo apt-get install ntp

# RedHat / CentOS / Rocky Linux
sudo dnf install ntp
```
