package singbox

import (
	"fmt"
	"net/url"
	"strconv"

	uuid2 "github.com/gofrs/uuid/v5"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"

	"github.com/mzz2017/gg/dialer"
)

// NewTUIC creates a *dialer.Dialer from a tuic:// URL using sing-box.
func NewTUIC(link string, opt *dialer.GlobalOption) (*dialer.Dialer, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("%w: parse tuic URL: %v", dialer.InvalidParameterErr, err)
	}
	if u.Scheme != "tuic" || u.User == nil || u.User.Username() == "" || u.Hostname() == "" {
		return nil, fmt.Errorf("%w: tuic requires user, password, host, and port", dialer.InvalidParameterErr)
	}

	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("%w: invalid tuic port", dialer.InvalidParameterErr)
	}

	// TUIC v5 format: tuic://UUID:password@server:port
	uuid := u.User.Username()
	password, hasPassword := u.User.Password()
	if _, err := uuid2.FromString(uuid); err != nil || !hasPassword || password == "" {
		return nil, fmt.Errorf("%w: invalid tuic credentials", dialer.InvalidParameterErr)
	}
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
