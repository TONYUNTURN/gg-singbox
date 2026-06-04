package singbox

import (
	"fmt"
	"net/url"
	"strconv"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"

	"github.com/mzz2017/gg/dialer"
)

// NewTUIC creates a *dialer.Dialer from a tuic:// URL using sing-box.
func NewTUIC(link string, opt *dialer.GlobalOption) (*dialer.Dialer, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("parse tuic url: %w", err)
	}

	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
	}

	// TUIC v5 format: tuic://UUID:password@server:port
	uuid := u.User.Username()
	password, _ := u.User.Password()
	name := u.Fragment
	sni := u.Query().Get("sni")
	if sni == "" {
		sni = u.Hostname()
	}
	allowInsecure := u.Query().Get("insecure") == "1" || u.Query().Get("insecure") == "true"

	tag := "tuic-" + name
	if tag == "tuic-" {
		tag = "tuic-outbound"
	}

	opts := &option.TUICOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     u.Hostname(),
			ServerPort: uint16(port),
		},
		UUID:     uuid,
		Password: password,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{
				Enabled:    true,
				ServerName: sni,
				Insecure:   allowInsecure,
			},
		},
	}

	if cc := u.Query().Get("congestion_control"); cc != "" {
		opts.CongestionControl = cc
	}
	if u.Query().Get("zero_rtt") == "1" || u.Query().Get("zero_rtt") == "true" {
		opts.ZeroRTTHandshake = true
	}

	obOpt := option.Outbound{
		Type:    C.TypeTUIC,
		Tag:     tag,
		Options: opts,
	}

	box, outbound, err := CreateBox(obOpt)
	if err != nil {
		return nil, fmt.Errorf("create sing-box for tuic: %w", err)
	}

	return NewSingBoxDialer(outbound, box, name, "tuic", link), nil
}
