package singbox

import (
	"fmt"
	"net/url"
	"strconv"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"

	"github.com/mzz2017/gg/dialer"
)

// NewSocks creates a *dialer.Dialer from a socks:// URL using sing-box.
func NewSocks(link string, opt *dialer.GlobalOption) (*dialer.Dialer, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("parse socks url: %w", err)
	}

	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
	}

	version := "5"
	switch u.Scheme {
	case "socks4":
		version = "4"
	case "socks4a":
		version = "4a"
	}

	username := ""
	password := ""
	if u.User != nil {
		username = u.User.Username()
		password, _ = u.User.Password()
	}

	tag := "socks-" + u.Fragment
	if tag == "socks-" {
		tag = "socks-outbound"
	}

	opts := &option.SOCKSOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     u.Hostname(),
			ServerPort: uint16(port),
		},
		Version:  version,
		Username: username,
		Password: password,
	}

	obOpt := option.Outbound{
		Type:    C.TypeSOCKS,
		Tag:     tag,
		Options: opts,
	}

	box, outbound, err := CreateBox(obOpt)
	if err != nil {
		return nil, fmt.Errorf("create sing-box for socks: %w", err)
	}

	return NewSingBoxDialer(outbound, box, u.Fragment, "socks", link), nil
}

// NewHTTPProxy creates a *dialer.Dialer from an http:// or https:// proxy URL using sing-box.
func NewHTTPProxy(link string, opt *dialer.GlobalOption) (*dialer.Dialer, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("parse http proxy url: %w", err)
	}

	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
	}

	username := ""
	password := ""
	if u.User != nil {
		username = u.User.Username()
		password, _ = u.User.Password()
	}

	tag := "http-" + u.Fragment
	if tag == "http-" {
		tag = "http-outbound"
	}

	opts := &option.HTTPOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     u.Hostname(),
			ServerPort: uint16(port),
		},
		Username: username,
		Password: password,
	}

	// Handle TLS for HTTPS proxies
	if u.Scheme == "https" {
		opts.OutboundTLSOptionsContainer.TLS = &option.OutboundTLSOptions{
			Enabled:  true,
			Insecure: opt != nil && opt.AllowInsecure,
		}
	}

	obOpt := option.Outbound{
		Type:    C.TypeHTTP,
		Tag:     tag,
		Options: opts,
	}

	box, outbound, err := CreateBox(obOpt)
	if err != nil {
		return nil, fmt.Errorf("create sing-box for http proxy: %w", err)
	}

	return NewSingBoxDialer(outbound, box, u.Fragment, "http", link), nil
}
