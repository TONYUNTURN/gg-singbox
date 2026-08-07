package singbox

import "github.com/mzz2017/gg/dialer"

// RegisterAll registers all sing-box based protocol handlers with gg's dialer registry.
// Call this once from main() instead of the old side-effect imports.
func RegisterAll() {
	// Shadowsocks
	dialer.FromLinkRegister("ss", NewShadowsocks)
	dialer.FromLinkRegister("shadowsocks", NewShadowsocks)
	dialer.FromClashRegister("ss", NewShadowsocksFromClash)

	// VMess / VLESS
	dialer.FromLinkRegister("vmess", NewV2Ray)
	dialer.FromLinkRegister("vless", NewV2Ray)

	// Trojan
	dialer.FromLinkRegister("trojan", NewTrojan)
	dialer.FromLinkRegister("trojan-go", NewTrojan)

	// SOCKS
	dialer.FromLinkRegister("socks", NewSocks)
	dialer.FromLinkRegister("socks5", NewSocks)
	dialer.FromLinkRegister("socks4", NewSocks)
	dialer.FromLinkRegister("socks4a", NewSocks)

	// HTTP(S)
	dialer.FromLinkRegister("http", NewHTTPProxy)
	dialer.FromLinkRegister("https", NewHTTPProxy)

	// Hysteria2
	dialer.FromLinkRegister("hysteria2", NewHysteria2)
	dialer.FromLinkRegister("hy2", NewHysteria2)

	// TUIC
	dialer.FromLinkRegister("tuic", NewTUIC)
}
