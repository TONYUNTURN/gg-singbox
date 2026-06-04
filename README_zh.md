# gg-singbox

[English](README.md) | [中文](README_zh.md)

## gg-singbox 是什么？

`gg` 是一个 Linux 命令行透明代理工具。在任何命令前面加 `gg`，该命令的流量就会自动走代理——无需安装 v2ray、clash 等重型程序。

```bash
gg curl ip.sb
gg git clone https://github.com/torvalds/linux.git
gg python -m pip install torch
```

## 为什么是 gg-singbox？

本项目是 [mzz2017/gg](https://github.com/mzz2017/gg)（go-graft）的**现代化 fork**。原版 `gg` 是一个优雅的基于 ptrace 的透明代理，支持多种协议。但它依赖的 `softwind` 协议库已停止维护，不支持 Shadowsocks 2022、Hysteria2、VLESS+REALITY 等现代协议。

**gg-singbox** 将协议层替换为 [sing-box](https://github.com/SagerNet/sing-box)，在保留原版轻量 ptrace 架构的同时，获得最新协议支持。

> 🙏 感谢 [mzz2017](https://github.com/mzz2017) 创造了原版 `gg`——创新的 ptrace 透明代理设计和优雅的 CLI 架构。

## 新特性

| 特性 | 原版 gg | gg-singbox |
|---|---|---|
| 协议引擎 | softwind（已停止维护） | sing-box v1.13 |
| SS2022 | ❌ | ✅ |
| VLESS + REALITY | ❌ | ✅ |
| Hysteria2 | ❌ | ✅ |
| TUIC | ❌ | ✅ |
| Trojan / Trojan-go | ✅ | ✅ |
| VMess (AEAD) | ✅ | ✅ |
| Shadowsocks | ✅（仅旧版） | ✅（旧版 + 2022） |
| 一键配置持久化 | ❌ | ✅ `-s` 后自动保存 |
| `--select` 切换节点 | ❌ | ✅ |
| `--no-cache` 一次性模式 | ❌ | ✅ |

## 快速开始

### 安装

```bash
# 从源码编译（需要 Go 1.24+）
CGO_ENABLED=0 go build -tags "with_quic,with_utls" -ldflags="-s -w" -o gg .
sudo setcap cap_net_raw,cap_sys_ptrace+ep ./gg
sudo mv ./gg /usr/local/bin/gg
```

### 使用方法

```bash
# 首次配置
gg -s https://你的订阅地址           # 拉订阅 → 交互式选择 → 自动保存

# 日常使用（无需任何 flag！）
gg curl ip.sb
gg git clone https://github.com/...

# 切换节点
gg --select                          # 重新拉订阅并选择不同节点

# 直接指定节点（默认自动保存）
gg -n hysteria2://密码@服务器:端口 curl ip.sb

# 一次性使用（不保存）
gg -n ss://... --no-cache curl ip.sb

# 代理整个 shell 会话
gg bash
```

## 支持的协议

| 协议 | URL Scheme | 备注 |
|---|---|---|
| Shadowsocks 2022 | `ss://` | method 以 `2022-` 开头 |
| VLESS + REALITY | `vless://` | 支持 Vision flow、uTLS 指纹 |
| VMess (AEAD) | `vmess://` | |
| Trojan / Trojan-go | `trojan://` | |
| Hysteria2 | `hysteria2://` `hy2://` | |
| TUIC | `tuic://` | |
| SOCKS5 | `socks5://` | |
| HTTP | `http://` `https://` | |

## 工作原理

`gg` 使用 Linux `ptrace` 拦截目标进程的网络系统调用（connect、sendto），将其重定向到本地透明代理。代理由 sing-box 驱动，对流量加密后通过选定的出站节点转发。

```
gg curl google.com
  → ptrace 拦截 curl 的 connect()
  → 重定向到本地代理（loopback）
  → 本地代理通过 sing-box 出站拨号
  → sing-box 加密并隧道传输至远程服务器
```

## 系统要求

- Linux（amd64、arm64、arm）
- `ptrace_scope` ≤ 1（或 `CAP_SYS_PTRACE` 权限）
- Root 或 `sudo setcap cap_net_raw,cap_sys_ptrace+ep ./gg`

## 致谢

- [mzz2017/gg](https://github.com/mzz2017/gg) — 原版项目，ptrace 架构、CLI 设计
- [SagerNet/sing-box](https://github.com/SagerNet/sing-box) — 通用代理平台
- [hmgle/graftcp](https://github.com/hmgle/graftcp) — 灵感来源

## 许可证

AGPLv3 — 与原版项目一致。
