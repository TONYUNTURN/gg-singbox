package singbox

import (
	"fmt"
	"net/url"
	"strconv"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"

	"github.com/mzz2017/gg/dialer"
)

// NewHysteria2 creates a *dialer.Dialer from a hysteria2:// URL using sing-box.
func NewHysteria2(link string, opt *dialer.GlobalOption) (*dialer.Dialer, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("parse hysteria2 url: %w", err)
	}

	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
	}

	password := u.User.String()
	name := u.Fragment
	sni := u.Query().Get("sni")
	if sni == "" {
		sni = u.Hostname()
	}
	allowInsecure := u.Query().Get("insecure") == "1" || u.Query().Get("insecure") == "true"

	tag := "hy2-" + name
	if tag == "hy2-" {
		tag = "hy2-outbound"
	}

	opts := &option.Hysteria2OutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     u.Hostname(),
			ServerPort: uint16(port),
		},
		Password: password,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{
				Enabled:    true,
				ServerName: sni,
				Insecure:   allowInsecure,
			},
		},
	}

	// Optional bandwidth settings
	if upMbps := u.Query().Get("up"); upMbps != "" {
		if v, err := strconv.Atoi(upMbps); err == nil {
			opts.UpMbps = v
		}
	}
	if downMbps := u.Query().Get("down"); downMbps != "" {
		if v, err := strconv.Atoi(downMbps); err == nil {
			opts.DownMbps = v
		}
	}

	// Optional obfs
	if obfsPassword := u.Query().Get("obfs-password"); obfsPassword != "" {
		opts.Obfs = &option.Hysteria2Obfs{
			Type:     "salamander",
			Password: obfsPassword,
		}
	}

	obOpt := option.Outbound{
		Type:    C.TypeHysteria2,
		Tag:     tag,
		Options: opts,
	}

	box, outbound, err := CreateBox(obOpt)
	if err != nil {
		return nil, fmt.Errorf("create sing-box for hysteria2: %w", err)
	}

	return NewSingBoxDialer(outbound, box, name, "hysteria2", link), nil
}
