package singbox

import (
	"fmt"
	"net/url"
	"strconv"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/mzz2017/gg/dialer"
)

// NewTrojan creates a *dialer.Dialer from a trojan:// URL using sing-box.
func NewTrojan(link string, opt *dialer.GlobalOption) (*dialer.Dialer, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("%w: parse trojan URL: %v", dialer.InvalidParameterErr, err)
	}
	if (u.Scheme != "trojan" && u.Scheme != "trojan-go") || u.User == nil || u.User.Username() == "" || u.Hostname() == "" {
		return nil, fmt.Errorf("%w: trojan requires user, host, and port", dialer.InvalidParameterErr)
	}

	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("%w: invalid trojan port", dialer.InvalidParameterErr)
	}

	password := u.User.Username()
	name := u.Fragment
	sni := u.Query().Get("sni")
	if sni == "" {
		sni = u.Hostname()
	}
	allowInsecure := u.Query().Get("allowInsecure") == "1" || u.Query().Get("allowInsecure") == "true"
	if opt != nil && opt.AllowInsecure {
		allowInsecure = true
	}

	tag := "trojan-" + name
	if tag == "trojan-" {
		tag = "trojan-outbound"
	}

	tlsOpt := &option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: sni,
		Insecure:   allowInsecure,
	}
	if alpn := u.Query().Get("alpn"); alpn != "" {
		tlsOpt.ALPN = badoption.Listable[string]{alpn}
	}

	opts := &option.TrojanOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     u.Hostname(),
			ServerPort: uint16(port),
		},
		Password: password,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: tlsOpt,
		},
	}

	// Handle WebSocket transport (trojan-go style)
	if netType := u.Query().Get("type"); netType == "ws" {
		host := u.Query().Get("host")
		path := u.Query().Get("path")
		opts.Transport = &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeWebsocket,
			WebsocketOptions: option.V2RayWebsocketOptions{
				Path: path,
			},
		}
		if host != "" {
			opts.Transport.WebsocketOptions.Headers = map[string]badoption.Listable[string]{
				"Host": {host},
			}
		}
	}

	obOpt := option.Outbound{
		Type:    C.TypeTrojan,
		Tag:     tag,
		Options: opts,
	}

	box, outbound, err := CreateBox(obOpt)
	if err != nil {
		return nil, fmt.Errorf("create sing-box for trojan: %w", err)
	}

	return NewSingBoxDialer(outbound, box, name, "trojan", link), nil
}
