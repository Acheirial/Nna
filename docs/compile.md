# 编译

编译 mieru 客户端和 mita 服务器软件，建议在 Linux 系统中进行。编译过程需要从互联网下载依赖的软件包。

编译所需的软件包括：

- git
- go (version >= 1.20)
- make
- curl（仅在重新生成 protobuf 代码时需要）

编译时，进入项目根目录，运行指令 `make` 即可。`make` 默认构建 `bin` 目标，编译结果会存放在项目根目录下的 `bin` 文件夹，包含客户端 `bin/mieru` 和服务器 `bin/mita`。

编译完成后，可以把可执行文件复制到系统路径 `PATH` 中，例如：

```sh
sudo install -m 755 bin/mieru /usr/local/bin/mieru
sudo install -m 755 bin/mita /usr/local/bin/mita
```

如果需要编译特定 CPU 指令集架构或操作系统的可执行文件，直接设置 `GOOS` / `GOARCH` 环境变量调用 `go build` 即可。参考下面的几个指令：

```sh
# 编译可以在龙芯处理器 Linux 系统上运行的 mita 服务器软件
env GOOS=linux GOARCH=loong64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o mita cmd/mita/mita.go

# 编译可以在 x86_64 处理器 FreeBSD 系统上运行的 mieru 客户端软件
env GOOS=freebsd GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o mieru cmd/mieru/mieru.go

# 编译可以在 MIPS 处理器 OpenWrt 系统上运行的 mieru 客户端软件
env GOOS=linux GOARCH=mips CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o mieru cmd/mieru/mieru.go
```

**注意，`mita` 服务器软件可能无法在 Linux 之外的操作系统中运行。**
