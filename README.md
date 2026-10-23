# 見える / mieru

mieru【見える】是一款基于 TCP 或 UDP 协议的 socks5 网络代理软件，在客户端与代理服务器之间建立加密通道。

mieru 代理软件只有一个程序 `shadowlemon`，它同时包含客户端与代理服务器两个角色：`shadowlemon client <命令>` 以客户端角色运行，`shadowlemon server <命令>` 以代理服务器角色运行；编译产物是唯一的二进制 `bin/shadowlemon`，不再有单独的客户端程序与服务端程序。

## 特性

1. 提供 socks5 代理接口。
2. 不使用 TLS 协议，无需注册域名和架设伪装站点。
3. 握手协议名 ShadowLemon（版本 V0.1），线路握手版本字节为 3，不提供向后兼容（旧版对等端会被直接丢弃）；两端在握手时协商密码套件：XChaCha20-Poly1305（默认）、AES-256-GCM、AES-128-GCM。
4. 使用 X25519 临时密钥交换，并通过 HKDF 派生每会话、每方向的会话密钥（前向安全）。
5. 使用随机填充与重放攻击检测对抗流量识别。
6. 支持多个用户共享代理服务器。
7. 支持 IPv4 和 IPv6。

## 使用教程

1. [服务器安装与配置](./docs/server-install.md)
2. [客户端安装与配置](./docs/client-install.md)
3. [客户端安装与配置 - OpenWrt](./docs/client-install-openwrt.md)
4. [流量模式](./docs/traffic-pattern.md)
5. [运营维护与故障排查](./docs/operation.md)
6. [编译](./docs/compile.md)

## 原理和协议

mieru 的代理原理与 shadowsocks / v2ray 等软件类似，在客户端和代理服务器之间建立一个加密的通道。中间网络设备无法解密传输内容，也无法判定最终访问的目标地址。

从流量特征上看：线路上没有明文的魔数、协议版本或长度字段，协议版本与密码套件协商、以及全部控制信息都位于 AEAD 加密与认证之下；默认（未配置 `trafficPattern`）不改写 nonce 前缀，因此每个数据段开头的 24 字节线路 nonce 保持均匀随机，密文整体也呈均匀随机分布。需要说明的是，本协议并不模拟某种具体协议（例如 TLS 或 HTTP）的字节分布，也不承诺流量在任何统计意义上与某个既有协议不可区分。

有关代理协议的讲解，请参阅 [ShadowLemon 代理协议](./docs/protocol.md)。

## 许可证

使用本软件需遵从 GPL-3 协议。
