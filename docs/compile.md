# 编译

编译 shadowlemon 客户端和服务器软件，建议在 Linux 系统中进行。编译过程需要从互联网下载依赖的软件包。

编译所需的软件包括：

- git
- go (version >= 1.26)
- make
- curl（仅在重新生成 protobuf 代码时需要）

项目的 Go 版本由 `go.mod` 决定：`go` 指令声明语言版本（当前为 `go 1.26`），`toolchain` 指令声明构建所需的工具链版本（当前为 `toolchain go1.26.9`）。如果本机安装的 Go 版本低于该工具链版本，`go` 命令会自动下载并使用对应的工具链（`GOTOOLCHAIN=auto`）；在无法访问互联网的环境中，请预先安装 Go 1.26.9 或更新版本。构建时不要再使用 Go 1.25 及更早的版本。

CI（GitHub Actions）通过 `actions/setup-go@v6` 并设置 `go-version-file: go.mod` 安装 Go，因此 CI 使用的版本始终与 `go.mod` 保持一致，无需在工作流中重复维护版本号。

编译时，进入项目根目录，运行指令 `make` 即可。`make` 默认构建 `bin` 目标，编译结果会存放在项目根目录下的 `bin` 文件夹，即单一可执行文件 `bin/shadowlemon`；它同时承担客户端与服务器两种角色，分别通过 `shadowlemon client` 与 `shadowlemon server` 调用。

编译完成后，可以把可执行文件复制到系统路径 `PATH` 中，例如：

```sh
sudo install -m 755 bin/shadowlemon /usr/local/bin/shadowlemon
```

如果需要编译特定 CPU 指令集架构或操作系统的可执行文件，直接设置 `GOOS` / `GOARCH` 环境变量调用 `go build` 即可。参考下面的几个指令：

```sh
# 编译可以在龙芯处理器 Linux 系统上运行的 shadowlemon 服务端
env GOOS=linux GOARCH=loong64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o shadowlemon ./cmd/shadowlemon

# 编译可以在 x86_64 处理器 FreeBSD 系统上运行的 shadowlemon 客户端
env GOOS=freebsd GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o shadowlemon ./cmd/shadowlemon

# 编译可以在 MIPS 处理器 OpenWrt 系统上运行的 shadowlemon 客户端
env GOOS=linux GOARCH=mips CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o shadowlemon ./cmd/shadowlemon
```

**注意，shadowlemon 的服务端角色可能无法在 Linux 之外的操作系统中运行。**
