# gg-singbox

[中文](README.md)

## What is gg-singbox?

`gg` is a command-line transparent proxy tool for Linux. Just prefix any command with `gg` to redirect its traffic through a modern proxy — no heavy installations needed.

```bash
gg curl ip.sb
gg git clone https://github.com/torvalds/linux.git
gg python -m pip install torch
```

## Why gg-singbox?

This project is a **modernized fork** of [mzz2017/gg](https://github.com/mzz2017/gg) (go-graft). The original `gg` was an elegant ptrace-based transparent proxy supporting multiple protocols. However, it relied on the outdated `softwind` protocol library and lacked support for modern protocols like Shadowsocks 2022, Hysteria2, and VLESS+REALITY.

**gg-singbox** replaces the protocol layer with [sing-box](https://github.com/SagerNet/sing-box), bringing support for the latest proxy protocols while keeping the original lightweight ptrace-based architecture intact.

> 🙏 All credit to [mzz2017](https://github.com/mzz2017) for the original `gg` project — the innovative ptrace-based transparent proxy design and the elegant CLI architecture.

## What's New

| Feature | Original gg | gg-singbox |
|---|---|---|
| Protocol engine | softwind (unmaintained) | sing-box v1.13 |
| SS2022 | ❌ | ✅ |
| VLESS + REALITY | ❌ | ✅ |
| Hysteria2 | ❌ | ✅ |
| TUIC | ❌ | ✅ |
| Trojan / Trojan-go | ✅ | ✅ |
| VMess (AEAD) | ✅ | ✅ |
| Shadowsocks | ✅ (legacy only) | ✅ (legacy + 2022) |
| Simple one-line setup | ❌ | ✅ auto-save after `-s` |
| `--select` to switch nodes | ❌ | ✅ |
| `--no-cache` one-shot mode | ❌ | ✅ |

## Quick Start

### Install

**One-line install (recommended):**

```bash
# International
sudo sh -c "$(curl -fsSL https://raw.githubusercontent.com/TONYUNTURN/gg-singbox/main/release/go.sh)"

# China
curl -fsSL https://ghscript.drumsticktony.online/https://raw.githubusercontent.com/TONYUNTURN/gg-singbox/main/release/go.sh | sudo env GG_MIRROR=1 sh
```

The script auto-detects your architecture, downloads a pre-built binary (~10MB after UPX compression), installs to `/usr/local/bin/gg`, and sets the required Linux capabilities. Use `GG_MIRROR=1` in China to skip the direct GitHub attempt.

**Manual download:**

Download the latest binary from [Releases](https://github.com/TONYUNTURN/gg-singbox/releases/latest), then:

```bash
chmod +x gg-linux-*
sudo mv gg-linux-* /usr/local/bin/gg
sudo setcap cap_net_raw,cap_sys_ptrace+ep /usr/local/bin/gg
```

**Build from source (Go 1.24+):**

```bash
CGO_ENABLED=0 go build -tags "with_quic,with_utls" -ldflags="-s -w" -o gg .
sudo setcap cap_net_raw,cap_sys_ptrace+ep ./gg
sudo mv ./gg /usr/local/bin/gg
```

> 💡 The pre-built binaries are compressed with [UPX](https://upx.github.io/), reducing size from ~31MB to ~10MB.

### Usage

```bash
# First time setup
gg -s https://your-subscription-url     # pull subscription, interactive select, auto-save

# Daily use (no flags needed!)
gg curl ip.sb
gg git clone https://github.com/...

# Switch node
gg --select                              # re-pull subscription and pick a different node

# Quick one-shot (auto-saves by default)
gg -n hysteria2://password@server:port curl ip.sb

# One-shot without saving
gg -n ss://... --no-cache curl ip.sb

# Proxy entire shell session
gg bash
```

## Supported Protocols

| Protocol | URL Scheme | Notes |
|---|---|---|
| Shadowsocks 2022 | `ss://` | Method starting with `2022-` |
| VLESS + REALITY | `vless://` | Vision flow, uTLS fingerprint |
| VMess (AEAD) | `vmess://` | |
| Trojan / Trojan-go | `trojan://` | |
| Hysteria2 | `hysteria2://` `hy2://` | |
| TUIC | `tuic://` | |
| SOCKS5 | `socks5://` | |
| HTTP | `http://` `https://` | |

## How It Works

`gg` uses Linux `ptrace` to intercept network syscalls (connect, sendto) of the target process, redirecting them to a local transparent proxy. The proxy, backed by sing-box, encrypts and forwards traffic through the selected outbound node.

```
gg curl google.com
  → ptrace intercepts curl's connect()
  → redirects to local proxy (loopback)
  → local proxy dials through sing-box outbound
  → sing-box encrypts & tunnels to remote server
```

## Requirements

- Linux (amd64, arm64, arm)
- `ptrace_scope` ≤ 1 (or `CAP_SYS_PTRACE` capability)
- Root or `sudo setcap cap_net_raw,cap_sys_ptrace+ep ./gg`

## Credits

- [mzz2017/gg](https://github.com/mzz2017/gg) — original project, ptrace architecture, CLI design
- [SagerNet/sing-box](https://github.com/SagerNet/sing-box) — universal proxy platform
- [hmgle/graftcp](https://github.com/hmgle/graftcp) — original inspiration

## License

AGPLv3 — same as the original project.
