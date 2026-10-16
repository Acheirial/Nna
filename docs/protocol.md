# mieru 代理协议

为了满足不同场景的需要，mieru 提供了 TCP 和 UDP 两种不同的代理协议。由于 UDP 协议需要尝试更多次数的解密，TCP 协议比 UDP 协议更快。在大多数情况下，我们推荐使用 TCP 协议。

下面是 mieru 代理协议的具体讲解。如果没有特殊说明，所有数据以 big endian 的方式存储。

## 密钥与密码套件

TCP 和 UDP 协议共用同一套密钥生成方法、同一组密码套件，以及同一套握手流程。

每一个 mieru 用户都需要提供用户名 `username` 和密码 `password`。从用户名和密码生成加密和解密使用的密钥，需要经历如下几步。

第一步，生成一个哈希密码 `hashedPassword`，其值等于 `password` 附加一个 `0x00` 字节再附加 `username` 得到的字符串的 SHA-256 校验码。

第二步，获取系统当前的时间 `unixTime`，其值等于 1970 年 1 月 1 日到现在经历的秒数。将 `unixTime` 的时刻四舍五入到最接近的 2 分钟，以 uint64 存储为一个 8 字节的字符串，取得该字符串的 SHA-256 校验码，记为 `timeSalt`。

第三步，使用 [pbkdf2](https://en.wikipedia.org/wiki/PBKDF2) 算法生成密钥。其中，使用 `hashedPassword` 作为密码，使用 `timeSalt` 作为盐，迭代次数为 64，密钥长度为 32 字节，哈希算法为 SHA-256。

第四步，按照当前会话协商出的密码套件截取密钥。上面得到的 32 字节输出记为 `pbkdf2Output`，则静态密钥 `staticKey` 等于 `pbkdf2Output` 的前 `suite.KeyLen()` 个字节。截取前缀在密码学上等价于一次独立的派生：PBKDF2 的输出块可以被视为随机的，任何前缀都不会泄露其后的字节。

静态密钥的生命周期只有一次握手。它只用来加密和认证握手的两个数据包（请求与响应），握手完成后传输的数据全部改用一次性会话密钥保护，详见「握手」。

由于密钥依赖于系统时间，客户端和服务器之间的时间差不能超过 2 分钟。对任意参考时刻，服务器最多需要尝试 3 组不同的时间盐（当前时刻，以及向前、向后各偏移一个密钥刷新周期，即 2 分钟）才能顺利解密。此外，元数据中的 `timestamp` 字段（单位为分钟）只容忍 ±1 分钟的偏差，超出该范围的数据段会被直接丢弃，因此建议两端的时钟偏差远小于 1 分钟。

### 密码套件

mieru 协议使用 [AEAD](https://en.wikipedia.org/wiki/Authenticated_encryption) 算法加密数据。目前定义了下面三种密码套件。

| 套件 | 配置枚举名 | 套件编号 `suite` | 密钥长度 | AEAD nonce 长度 | 适用场景 |
| :----: | :----: | :----: | :----: | :----: | :---- |
| XChaCha20-Poly1305 | `CIPHER_SUITE_XCHACHA20_POLY1305` | 0 | 32 字节 | 24 字节 | 默认套件。纯软件实现即高速，且所有 CPU 上的运行时间都只与数据长度有关 |
| AES-256-GCM | `CIPHER_SUITE_AES_256_GCM` | 1 | 32 字节 | 12 字节 | 支持 AES 硬件指令（x86 的 AES-NI、ARM 的 Crypto Extension）的 CPU |
| AES-128-GCM | `CIPHER_SUITE_AES_128_GCM` | 2 | 16 字节 | 12 字节 | 同上，且偏好更短的密钥 |

上面表中的「密钥长度」同时决定两件事：静态密钥的截取长度（见「密钥与密码套件」第四步），以及会话密钥的派生长度（见「会话密钥的派生」）。

客户端的首选套件列表由客户端配置的 `cipherSuites` 字段给出，顺序即偏好顺序；服务端接受的套件集合由服务端配置的 `cipherSuites` 字段给出，顺序即服务端偏好顺序。客户端列表为空时只使用 XChaCha20-Poly1305；服务端列表为空时接受全部三种套件。双方通过握手把两个列表协商成唯一的一个套件，详见「版本与套件协商」。

无论协商出哪个套件，**线路上的 nonce 长度恒为 24 字节**。AEAD 算法本身要求的 nonce 长度不同，实际参与运算的 nonce 由线路 nonce 派生，规则见下。同样地，AEAD 认证标签的长度恒为 16 字节。

### AEAD nonce 的派生规则

记数据段开头的 24 字节线路 nonce 为 `wireNonce`，套件所用 AEAD 算法的 nonce 长度为 `N`，则实际传给 AEAD 的 nonce 为 `wireNonce` 的**末 `N` 字节**：

```
aeadNonce = wireNonce[len(wireNonce)-N:]
```

- XChaCha20-Poly1305：`N` = 24，`aeadNonce` 就是完整的 24 字节线路 nonce，行为与早期版本完全一致。
- AES-256-GCM 与 AES-128-GCM：`N` = 12，`aeadNonce` = `wireNonce[12:24]`。

之所以对 AES-GCM 取末 12 字节而不是前 12 字节，原因有两个。第一，`wireNonce[0:12]` 可能被 traffic pattern 的 `noncePattern` 重写为**用户配置的确定性字节**，同一把密钥下重复的 GCM nonce 会直接摧毁 GCM 的机密性与认证能力，因此这一段绝不能充当 GCM nonce；而 `wireNonce[12:24]` 包含随机区 `[12:20]` 与用户名提示区 `[20:24]`，同一把密钥下出现重复 nonce 的概率可以忽略。第二，UDP 协议通过翻转下标 16 的字节派生载荷 nonce（见「UDP 数据段的规则」），下标 16 落在 `[12:20]` 区间内，所以即使套件换成 AES-GCM，「元数据和载荷不共用同一个 `(key, nonce)` 对」这条不变量依然成立。

为了加快用户查找，nonce 的最后 4 个字节被替换为 SHA-256 输出的前 4 个字节，其中 SHA-256 的输入是用户名再接上 nonce 的前 16 个字节。

### 默认套件

默认套件是 XChaCha20-Poly1305，配置中省略 `cipherSuites` 字段即使用它。选择它作为默认值的原因是它的性能与安全性都不依赖硬件特性：CPU 支持 AES 硬件指令时 AES-GCM 会更快，但在**没有** AES 硬件指令的 CPU 上，AES-GCM 的软件实现必须使用常数时间的查表或位切片实现，速度显著下降；而 XChaCha20-Poly1305 在纯软件实现下依然很快，其 24 字节 nonce 也足够长，随机采样的 nonce 碰撞风险可以忽略。因此 AES 套件更适合明确知道自己 CPU 支持硬件加速、且已完成实测的场景。

## 握手

mieru 的每一个会话（每一个 TCP 连接，以及 UDP 的每一个会话）在传输应用数据之前，都要先完成一次握手。客户端发送握手请求，服务端回复握手响应，双方据此协商协议版本、确定密码套件，并派生出一组一次性会话密钥。握手使用的密钥是静态密钥，握手完成后的全部数据使用会话密钥。

握手请求是 `openSessionRequest` 数据段（`protocol type` = 2）载荷的前缀，握手响应是 `openSessionResponse` 数据段（`protocol type` = 3）载荷的全部内容。两个数据包的元数据与载荷格式、字段偏移遵循「元数据的格式」与「数据段的格式」两节的规定，只有密钥与 nonce 的来源不同。

### 握手请求

握手请求的载荷前缀中的字段及其长度如下表所示。

| versionMin | versionMax | suiteCount | suite list | ephPubClient | clientSalt |
| :----: | :----: | :----: | :----: | :----: | :----: |
| 1 | 1 | 1 | `suiteCount` | 32 | 16 |

- `versionMin` 与 `versionMax` 是客户端支持的协议版本区间。当前实现两者都是 2，即只支持协议版本 2。
- `suiteCount` 是客户端首选套件的数量，取值范围为 1 至 4。
- `suite list` 是客户端首选套件列表，每个套件占 1 个字节，字节值等于「密码套件」表中的套件编号，顺序即客户端偏好顺序。
- `ephPubClient` 是一次性的 X25519 公钥，用于派生会话密钥。
- `clientSalt` 是客户端生成的 16 字节随机盐。

因此握手请求载荷的总长度为 `51 + suiteCount` 字节，当 `suiteCount` 为 1 时为 52 字节。

握手请求使用**客户端首选列表中的第一个套件**（`suite list` 的第 0 项）对应的静态密钥加密，且使用与元数据相同的当前时间槽。服务端在解密之前无法知道客户端选择了哪个套件，因此它必须对每一个允许的套件、每一个时间槽分别尝试解密；AEAD 认证标签校验通过的那个套件就是客户端首选套件。合法性的唯一证明始终是认证标签校验通过，其它一切信息（包括 `source IP`、nonce 中的用户名提示、以及 `suite list` 的内容）都只是加速查表的提示，不构成认证。

### 握手响应

握手响应的载荷中的字段及其长度如下表所示。

| status | version | suite | ephPubServer | serverSalt |
| :----: | :----: | :----: | :----: | :----: |
| 1 | 1 | 1 | 32 | 16 |

- `status` 是协商结果：0 表示成功，1 表示双方没有共同的协议版本，2 表示双方没有共同的密码套件。
- `version` 是最终使用的协议版本。
- `suite` 是最终使用的套件编号。
- `ephPubServer` 是一次性的 X25519 公钥，用于派生会话密钥。
- `serverSalt` 是服务端生成的 16 字节随机盐。

握手响应载荷的总长度恒为 51 字节。当 `status` 不为 0 时，会话失败，`version` 与 `suite` 为 0，`ephPubServer` 与 `serverSalt` 为全 0。

握手响应**恒定使用「解出请求时所用的套件」与「同一个时间槽的静态密钥」加密**，`status` 为 0 时也一样。这里不能使用会话密钥，原因是密钥派生本身依赖响应包中的 `ephPubServer` 与 `serverSalt`：只要响应还用会话密钥加密，客户端就无法解密它，双方会陷入循环依赖。因此静态密钥保护握手请求与握手响应这两个包，会话密钥只保护握手之后传输的数据。

客户端收到响应后，需要对自己首选列表中的每一个套件、每一个时间槽，用对应的静态密钥尝试解密；第一个认证标签校验通过的组合胜出，客户端使用胜出的套件和它当时使用的那把静态密钥继续派生会话密钥。如果所有组合都无法解密，客户端不能把这次失败当作「服务端无响应」，而应超时报错并关闭会话，并在日志中提示两端可能存在时钟偏差或配置不一致。

### 会话密钥的派生

协商出最终的 `version` 与 `suite` 之后，双方各自按下式派生会话密钥。所有步骤都使用协商结果和握手两包中已经交换的值，因此两端得到的结果必然相同。

```
shared    = X25519(ephPriv_local, ephPub_peer)                  // 32 字节
salt      = SHA256(staticKey ‖ clientSalt ‖ serverSalt)          // 32 字节
info_c2s  = "mieru-v2 c2s" ‖ byte(version) ‖ byte(suite)
info_s2c  = "mieru-v2 s2c" ‖ byte(version) ‖ byte(suite)
c2sKey    = HKDF-SHA256(secret=shared, salt=salt, info=info_c2s, L=suite.KeyLen())
s2cKey    = HKDF-SHA256(secret=shared, salt=salt, info=info_s2c, L=suite.KeyLen())
```

其中 `staticKey` 是解出握手包时使用的那把静态密钥，`ephPriv_local` 是本端的一次性私钥，`ephPub_peer` 是对端的一次性公钥。如果 X25519 的结果为全零，或者对端公钥非法，双方都必须拒绝本次会话。`c2s` 表示客户端到服务端方向，`s2c` 表示服务端到客户端方向：客户端发送数据使用 `c2sKey`、接收数据使用 `s2cKey`，服务端正好相反。

两个方向使用不同的 `info` 字符串，因此 `c2sKey` 与 `s2cKey` 在密码学上互相独立，跨方向复用 `(key, nonce)` 对的情况不会发生。会话密钥与静态密钥也互相独立，即使同一个用户、同一个时间槽上建立多个会话，每个会话的密钥都不相同。

握手结束后，元数据与数据载荷这两条加密路径都必须替换为会话密钥；线路 nonce 的生成方式不变，AEAD nonce 仍按「AEAD nonce 的派生规则」从 24 字节线路 nonce 中截取。

### 版本与套件协商

握手使用的协商规则如下。

1. 版本：最终版本 `version` 等于 `min(服务端 versionMax, 客户端 versionMax)`。如果 `version` 小于 `max(服务端 versionMin, 客户端 versionMin)`，即两个区间没有交集，服务端返回 `status` = 1，会话失败。
2. 套件：在「客户端首选列表」与「服务端允许集合」的交集中，按**服务端偏好顺序**取第一个条目作为最终套件。交集为空时服务端返回 `status` = 2，会话失败。最终套件可以不同于客户端首选列表的第一项。
3. 服务端解密请求时命中的那个套件，被记录为客户端首选套件，用于加速查找，但**不**参与上一条规则的取舍。
4. 服务端仍然必须容忍 ±2 分钟的时钟偏差，即对当前时刻以及向前、向后各偏移 2 分钟的时间槽分别尝试。
5. 会话失败时，服务端必须关闭会话并记录日志，不得静默丢弃一个已经通过认证的请求，更不得因此终止进程。

握手请求（信封）由客户端用**自己首选列表的第一项**套件保护，因为客户端在握手之前并不知道服务端的允许集合。相应地，服务端在发现阶段必须用全部受支持套件（XChaCha20-Poly1305 / AES-256-GCM / AES-128-GCM）依次尝试解密，因此即使客户端的首选套件不在服务端允许集合内，服务端也能解出请求、识别出这是一次套件不兼容的握手，并按上一条返回 `status` = 2，而不是静默丢弃。服务端允许集合只约束最终套件的选择（即上一条的取舍），不影响发现阶段的解密范围；source-IP 缓存里记录的「上次认证成功的套件」只作为试解顺序提示，试解失败必须回退到全集，合法性仍然只由 AEAD 认证标签决定。

版本区间和套件列表都在握手请求的载荷内部，即处于 AEAD 加密与认证之下。网络上的观察者既不能读取它们，也不能篡改它们而不破坏认证标签。

### 前向安全

数据面的全部密钥都来自一次性的 X25519 交换（`shared`），再加上两端各自生成的随机盐。握手的静态密钥只用于保护请求与响应两个包，不参与任何数据段的加密。

因此，即使某个用户的用户名与密码在会话结束之后泄露（或者攻击者事后获得了攻击时刻的静态密钥），攻击者也无法解密已经记录下来的历史会话：要还原历史会话密钥，攻击者除了静态密钥之外，还必须持有当时那次握手的两包密文，以及握手中使用过的一次性私钥；而一次性私钥在会话结束后随即被丢弃。会话结束后，两端都应尽力清零自己的一次性私钥；受 Go 语言 `crypto/ecdh` 接口所限，这只是尽力而为的措辞，进程内存中的残留仍然取决于运行时。

## 数据段的格式

mieru 收到用户的网络访问请求后，会将原始数据流量切分成小段（fragment），经过加密封装发送到互联网上。每个数据段（segment）中的数据项（field）及其长度如下表所示。

| padding 0 | nonce | encrypted metadata | auth tag of encrypted metadata | padding 1 | encrypted or low entropy encoded payload body | auth tag of encrypted payload | padding 2 |
| :----: | :----: | :----: | :----: | :----: | :----: | :----: | :----: |
| ? | 0 or 24 | 32 | 16 | ? | original or encoded body size | 16 | ? |

这其中，`encrypted metadata` 和 `auth tag of encrypted metadata` 会出现在每一个数据段中，其它的数据项则不是必须的。`padding 0`, `padding 1` 和 `padding 2` 是随机生成的非加密内容，mieru 使用这些填充数据调节数据段的信息熵，以及连续可打印字符的长度等信息。

`encrypted metadata` 和 `auth tag of encrypted metadata` 使用数据段开头的 `nonce` 加密。同一个数据段中的载荷（`encrypted or low entropy encoded payload body` 与 `auth tag of encrypted payload`）必须使用不同的 nonce，以免在同一把密钥下复用 `(key, nonce)` 对：TCP 协议使用隐式递增后的 nonce，UDP 协议使用由报文 `nonce` 派生的域分离 nonce，派生规则见「UDP 数据段的规则」。载荷的密钥、线格式与所有字段偏移都与元数据相同。

握手完成之前，上面用到的密钥是静态密钥；握手完成之后，上面用到的密钥换成会话密钥（发送方向一把，接收方向一把）。传给 AEAD 的 nonce 由 24 字节线路 nonce 按「AEAD nonce 的派生规则」派生，因此无论协商出哪个套件，线路上的 nonce 长度恒为 24 字节。

### TCP 数据段的规则

使用 TCP 协议时，nonce 在 TCP 连接的每个方向（客户端到服务器、服务器到客户端）只会在第一个数据段出现一次。每传输一个数据段，会进行一次或者两次加密操作，得到加密的元数据，以及（如果有）加密的原始数据载荷。每进行一次加密，nonce 的值会增加 1，变更后的 nonce 将会参与下一组加密的计算。

把原始数据切分成小段时，单个小段的最大长度是 32768 字节。低熵模式 `LOW_ENTROPY_MODE_32` 是例外，其上限为 32764 字节，以确保编码后的长度能装入 16 位的 `payload length` 字段。该模式下，32768 字节的应用写入会被拆分到多个数据段中。

### UDP 数据段的规则

使用 UDP 协议时，每一个数据段都会包含 nonce，用来解密当前的数据段。

同一个数据段中的载荷不能复用该 nonce 加密。发送端先复制一份报文 nonce，把副本中下标为 `16`（从 0 开始计数，即第 17 个字节）的字节与 `0x01` 异或，得到载荷 nonce `payloadNonce`，再用 `payloadNonce` 加密载荷；接收端对收到的报文 nonce 做完全相同的变换，再用 `payloadNonce` 解密载荷。选择下标 16 是因为 nonce 的前 12 个字节可能被 traffic pattern 重写、后 4 个字节（下标 20 至 23）是用户名提示位，下标 16 不属于这两段。由于异或的是非零值，`payloadNonce` 恒不等于报文 nonce，因此元数据与载荷不会共用同一个 `(key, nonce)` 对；载荷使用的密钥、线格式与所有字段偏移都与元数据相同，只有 nonce 不同。

该派生规则改变了 UDP 载荷的密文语义，详见「兼容性说明」。

使用 UDP 协议时，每一个会话都要独立完成一次握手，会话密钥不跨会话复用。

加密后的数据段必须能装入单个 UDP 数据包中。数据段在传输时的大小，不能超过当前网络的 MTU 值。网络的 MTU 值会决定把原始数据切分成小段时，单个小段的最大长度。

## 元数据的格式

每个数据段必定包含一个元数据。元数据的长度固定为 32 字节。当前 mieru 版本定义的元数据类型包含下面三种。

### 会话元数据

会话元数据（session metadata）中的数据项及其长度如下表所示。

| protocol type | unused | timestamp | session ID | sequence number | status code | payload length | suffix length | unused |
| :----: | :----: | :----: | :----: | :----: | :----: | :----: | :----: | :----: |
| 1 | 1 | 4 | 4 | 4 | 1 | 2 | 1 | 14 |

会话元数据用于下面四种 `protocol type`:

- `openSessionRequest` = 2
- `openSessionResponse` = 3
- `closeSessionRequest` = 4
- `closeSessionResponse` = 5

`timestamp` 的值设定为 1970 年 1 月 1 日到现在经历的分钟数。

如果一个数据段采用了会话元数据，该数据段可以用来传输最多 1024 字节的原始数据载荷。这个载荷的长度记录在 `payload length` 中。

`suffix length` 决定了 `padding 2` 的长度。

### 数据元数据

数据元数据（data metadata）中的数据项及其长度如下表所示。

| protocol type | unused | timestamp | session ID | sequence number | unack sequence number | window size | fragment number | prefix length | payload length | suffix length | unused |
| :----: | :----: | :----: | :----: | :----: | :----: | :----: | :----: | :----: | :----: | :----: | :----: |
| 1 | 1 | 4 | 4 | 4 | 4 | 2 | 1 | 1 | 2 | 1 | 7 |

数据元数据用于下面四种 `protocol type`:

- `dataClientToServer` = 6
- `dataServerToClient` = 7
- `ackClientToServer` = 8
- `ackServerToClient` = 9

`timestamp`, `session ID` 和 `sequence number` 的定义和用法，与会话元数据相同。

`sequence number`, `unack sequence number` 以及 `window size` 用于流量控制。

`prefix length` 决定了 `padding 1` 的长度，而 `suffix length` 决定了 `padding 2` 的长度。

### 数据元数据（低熵扩展）

低熵扩展采用与数据元数据相同的结构，并使用以下字段替换原先未使用的字节。

| protocol type | low entropy mode | timestamp | session ID | sequence number | unack sequence number | window size | fragment number | prefix length | payload length | suffix length | low entropy mask | extracted payload length | low entropy mask rotation |
| :----: | :----: | :----: | :----: | :----: | :----: | :----: | :----: | :----: | :----: | :----: | :----: | :----: | :----: |
| 1 | 1 | 4 | 4 | 4 | 4 | 2 | 1 | 1 | 2 | 1 | 4 | 2 | 1 |

此扩展用于下面两种 `protocol type` 值：

- `dataClientToServerLowEntropy` = 10
- `dataServerToClientLowEntropy` = 11

当每个 64 位低熵数据块分别包含 32、40、48 或 56 位载荷数据时，`low entropy mode` 的值依次为 1、2、3 或 4，其余位为填充。值为 0 时禁用低熵编码。

将 4 字节的 `low entropy mask` 重复一次，组成 8 字节的掩码，其中值为 1 的位用于标识每个数据块中的载荷位置，值为 0 的位用于标识填充位置。`payload length` 包含低熵填充，而 `extracted payload length` 记录移除填充后的载荷长度。

`low entropy mask rotation` 控制相邻 64 位数据块之间 8 字节掩码的旋转方式。值为 1 至 15 时（低 4 位），掩码向右旋转相应的位数；值为 1 至 15 中某个数的 16 倍时（高 4 位），掩码向左旋转该数对应的位数。值为 0 时掩码保持不变。

#### 低熵载荷编码

低熵编码仅用于协议类型 10 和 11。发送端首先进行普通的载荷 AEAD 加密，然后将结果拆分为密文正文和 16 字节认证标签。只有密文正文参与低熵编码。保持不变的认证标签紧跟在编码后的正文之后，既不计入 `payload length`，也不参与低熵变换。`extracted payload length` 是扩展前的密文正文长度；由于 AEAD 加密保持明文长度不变，它也等于应用分片长度。

模式决定每个 8 字节编码块的源数据容量 `C`：

| 模式 | 配置值 | 源数据字节数 `C` | 32 位半掩码中的 1 位数 | 完整块扩展倍数 |
| :----: | :---- | :----: | :----: | :----: |
| 1 | `LOW_ENTROPY_MODE_32` | 4 | 16 | 2.0 倍 |
| 2 | `LOW_ENTROPY_MODE_40` | 5 | 20 | 1.6 倍 |
| 3 | `LOW_ENTROPY_MODE_48` | 6 | 24 | 约 1.34 倍 |
| 4 | `LOW_ENTROPY_MODE_56` | 7 | 28 | 约 1.15 倍 |

对于长度为 `N` 字节的待提取正文，`payload length` 等于 `ceil(N / C) * 8`。最后一个不完整的源数据块仍占用 8 字节。

每次发送时，发送端生成一个 32 位半掩码，其中 1 的数量由模式决定，再将其重复一次组成初始 64 位掩码。第 0 个数据块直接使用该掩码。第 `i` 个数据块按照 `low entropy mask rotation` 编码的方向，将初始掩码旋转 `i * R` 位；每次旋转都从初始掩码计算。

每个源数据块按大端字节序解释，并放入源数值的低位。发送端把这些位存入当前掩码值为 1 的位置。其余所有位置都使用同一个填充值。该值可以是 0 或 1，并且对于给定的发送主机和 mieru 版本保持稳定。最后一个不完整数据块中，掩码选中但未被实际数据使用的位置也属于填充。

接收端从第一个数据块推断填充值，并要求所有数据块中的每个非数据位置都使用该值。混合填充、无效模式或旋转、掩码中的 1 位数错误，以及编码长度与提取长度不一致，都会使数据段无效。对掩码选中的密文位或保持不变的认证标签所做的修改，则会被 AEAD 认证拒绝。

所有多字节元数据字段及编码后的 64 位数据块在线路上均使用大端字节序。下面是 `LOW_ENTROPY_MODE_32` 模式的完整示例：

```text
半掩码：                 0x0f0f0f0f
64 位掩码：              0x0f0f0f0f0f0f0f0f
旋转：                   0
源数据：                 12 34 56 78
填充值为 0 的编码结果：  01 02 03 04 05 06 07 08
填充值为 1 的编码结果：  f1 f2 f3 f4 f5 f6 f7 f8
```

## UDP Associate 的封装

mieru 支持使用 TCP 和 UDP 代理协议传输 socks5 UDP associate 请求。为了保留 socks5 UDP 数据包的边界，mieru 会对原始 UDP associate 数据包进行如下的封装：

| marker 1 | data length | data | marker 2 |
| :----: | :----: | :----: | :----: |
| 1 | 2 | X | 1 |

其中 `marker 1` 的值恒定为 `0x00`，`data length` 的值为 `X`，`marker 2` 的值恒定为 `0xff`。封装后的结果将作为原始数据交给 TCP 和 UDP 代理协议进行加密和传输。

## 兼容性说明

### UDP 载荷的域分离 nonce

UDP 数据段的载荷使用由报文 nonce 派生的域分离 nonce 加密：取报文 nonce 的副本，把下标 16 的字节与 `0x01` 异或，得到 `payloadNonce`，再用它完成载荷的 AEAD 加密和解密。早期的 mieru 版本直接使用报文 nonce 加密载荷，因此这一改动改变了 UDP 载荷的密文语义：新客户端发出的数据报无法被旧服务端解密，旧客户端发出的数据报也无法被新服务端解密。当前协议没有版本协商字段，两端无法自动协商或降级，所以升级时必须同时升级客户端与服务端，否则 UDP 代理（含 UDP associate）会持续解密失败。

TCP 协议不受该改动影响：TCP 的载荷使用隐式递增 nonce，本来就不与元数据共用 nonce。数据段的线格式也没有任何变化：nonce 的位置与长度（0 或 24 字节）、元数据长度（32 字节）以及所有字段偏移都与之前一致。

### 握手协议版本 2

本次变更为握手引入了协议版本协商。当前的实现固定使用协议版本 2，握手请求的载荷首字节 `versionMin` 恒为 2。

旧客户端（协议版本 1）发出的握手请求中没有 `versionMin` 字段：它的载荷首字节是其它内容，因此服务端解析出的 `versionMin` 要么小于 2，要么请求载荷长度不足。这两种情况一律被服务端判为「无共同版本」，服务端返回 `status` = 1 并关闭会话。**协议版本 1 的客户端不再被兼容**：升级时必须同时升级客户端与服务端，否则所有会话都会在握手阶段失败。这是有意为之的破坏性变更，因为版本 1 的握手不携带 X25519 公钥，无法派生前向安全的会话密钥。

套件协商不能用来兼容旧客户端：协商发生在协议版本 2 的握手内部，而旧客户端连第一个字节都无法通过。

### 密码套件协商

密码套件由两端在握手时协商决定，而不是由某一端单独规定，因此套件配置可以两端各自独立调整：客户端不设置 `cipherSuites` 时只使用默认套件，它依然能与允许集包含默认套件的服务端建立会话；服务端的允许集与客户端偏好只要有交集，会话就能建立。

但套件协商发生在协议版本 2 的握手内部，因此上一节的破坏性升级要求不受影响：两端都必须运行协议版本 2 的实现，否则连版本协商都无法通过。
