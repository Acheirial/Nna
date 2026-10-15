# 見える / mieru

mieru【見える】是一款安全的、无流量特征、难以主动探测的，基于 TCP 或 UDP 协议的 socks5 网络代理软件。

mieru 代理软件由称为 mieru【見える】的客户端软件和称为 mita【見た】的代理服务器软件这两部分组成。

## 特性

1. 提供 socks5 代理接口。
2. 不使用 TLS 协议，无需注册域名和架设伪装站点。
3. 使用高强度的 XChaCha20-Poly1305 加密算法，基于用户名、密码和系统时间生成密钥。
4. 使用随机填充与重放攻击检测对抗流量识别。
5. 支持多个用户共享代理服务器。
6. 支持 IPv4 和 IPv6。

## 使用教程

1. [服务器安装与配置](./docs/server-install.md)
2. [客户端安装与配置](./docs/client-install.md)
3. [客户端安装与配置 - OpenWrt](./docs/client-install-openwrt.md)
4. [流量模式](./docs/traffic-pattern.md)
5. [运营维护与故障排查](./docs/operation.md)
6. [编译](./docs/compile.md)

## 原理和协议

mieru 的代理原理与 shadowsocks / v2ray 等软件类似，在客户端和代理服务器之间建立一个加密的通道。中间网络设备无法解密传输内容，也无法判定最终访问的目标地址。

有关 mieru 协议的讲解，请参阅 [mieru 代理协议](./docs/protocol.md)。

## 许可证

使用本软件需遵从 GPL-3 协议。
