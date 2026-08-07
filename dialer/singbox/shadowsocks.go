package singbox

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
	"gopkg.in/yaml.v3"

	"github.com/mzz2017/gg/common"
	"github.com/mzz2017/gg/dialer"
)

var createShadowsocksBox = func(outbound option.Outbound) (interface{ Close() error }, singBoxOutbound, error) {
	box, created, err := CreateBox(outbound)
	return box, created, err
}

// NewShadowsocks creates a *dialer.Dialer from an ss:// URL using sing-box.
func NewShadowsocks(link string, opt *dialer.GlobalOption) (*dialer.Dialer, error) {
	s, err := ParseSSURL(link)
	if err != nil {
		return nil, err
	}
	return s.Dialer(opt, link)
}

type Shadowsocks struct {
	Name     string
	Server   string
	Port     int
	Password string
	Cipher   string
	Plugin   string
	UDP      bool
}

func (s *Shadowsocks) Dialer(opt *dialer.GlobalOption, link string) (*dialer.Dialer, error) {
	tag := "ss-" + s.Name
	if tag == "ss-" {
		tag = "ss-outbound"
	}

	options := &option.ShadowsocksOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     s.Server,
			ServerPort: uint16(s.Port),
		},
		Method:   s.Cipher,
		Password: s.Password,
	}
	if !s.UDP {
		options.Network = option.NetworkList(N.NetworkTCP)
	}
	obOpt := option.Outbound{
		Type:    C.TypeShadowsocks,
		Tag:     tag,
		Options: options,
	}

	if s.Plugin != "" {
		obOpt.Options.(*option.ShadowsocksOutboundOptions).Plugin = "obfs-local"
		obOpt.Options.(*option.ShadowsocksOutboundOptions).PluginOptions = s.Plugin
	}

	box, outbound, err := createShadowsocksBox(obOpt)
	if err != nil {
		return nil, fmt.Errorf("create sing-box for ss: %w", err)
	}

	return newSingBoxDialer(outbound, box, s.Name, "shadowsocks", link), nil
}

// NewShadowsocksFromClash maps the common Clash Shadowsocks fields to the
// existing Shadowsocks implementation. Unsupported plugin variants are
// rejected instead of being silently reinterpreted.
func NewShadowsocksFromClash(clashObj *yaml.Node, opt *dialer.GlobalOption) (*dialer.Dialer, error) {
	var node struct {
		Name     string `yaml:"name"`
		Server   string `yaml:"server"`
		Port     int    `yaml:"port"`
		Cipher   string `yaml:"cipher"`
		Password string `yaml:"password"`
		Plugin   string `yaml:"plugin"`
		UDP      bool   `yaml:"udp"`
	}
	if err := clashObj.Decode(&node); err != nil {
		return nil, fmt.Errorf("%w: decode Clash Shadowsocks node: %v", dialer.InvalidParameterErr, err)
	}
	if node.Server == "" || node.Port < 1 || node.Port > 65535 || node.Cipher == "" || node.Password == "" {
		return nil, fmt.Errorf("%w: Clash Shadowsocks node requires server, port, cipher, and password", dialer.InvalidParameterErr)
	}
	if node.Plugin != "" {
		return nil, fmt.Errorf("%w: unsupported Clash Shadowsocks plugin %q", dialer.InvalidParameterErr, node.Plugin)
	}
	s := &Shadowsocks{
		Name:     node.Name,
		Server:   node.Server,
		Port:     node.Port,
		Password: node.Password,
		Cipher:   strings.ToLower(node.Cipher),
		UDP:      node.UDP,
	}
	return s.Dialer(opt, s.ExportToURL())
}

// ParseSSURL parses a Shadowsocks SIP002 URL (ss://).
// Reuses the parsing logic from the original gg codebase.
func ParseSSURL(u string) (data *Shadowsocks, err error) {
	if !strings.HasPrefix(u, "ss://") {
		return nil, fmt.Errorf("unrecognized ss address: %w", dialer.InvalidParameterErr)
	}
	parse := func(content string) (v *Shadowsocks, ok bool) {
		u, err := url.Parse(content)
		if err != nil || u.Scheme != "ss" || u.User == nil || u.Hostname() == "" {
			return nil, false
		}
		credentials := u.User.Username()
		if password, ok := u.User.Password(); ok {
			credentials += ":" + password
		} else if decoded, decodeErr := common.Base64URLDecode(credentials); decodeErr == nil {
			credentials = decoded
		}
		arr := strings.SplitN(credentials, ":", 2)
		if len(arr) != 2 {
			return nil, false
		}
		cipher := arr[0]
		password := arr[1]
		var plugin string
		pluginRaw := u.Query().Get("plugin")
		if len(pluginRaw) > 0 {
			plugin = pluginRaw
		}
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 || cipher == "" || password == "" {
			return nil, false
		}
		return &Shadowsocks{
			Cipher:   strings.ToLower(cipher),
			Password: password,
			Server:   u.Hostname(),
			Port:     port,
			Name:     u.Fragment,
			Plugin:   plugin,
			UDP:      pluginRaw == "",
		}, true
	}

	var v *Shadowsocks
	content := u
	if v, _ = parse(content); v == nil {
		if len(content) <= len("ss://") {
			return nil, fmt.Errorf("unrecognized ss address: %w", dialer.InvalidParameterErr)
		}
		t := content[5:]
		var l, r string
		if ind := strings.Index(t, "#"); ind > -1 {
			l = t[:ind]
			r = t[ind+1:]
		} else {
			l = t
		}
		l, err = common.Base64StdDecode(l)
		if err != nil {
			l, err = common.Base64URLDecode(l)
			if err != nil {
				return nil, fmt.Errorf("unrecognized ss address: %w", dialer.InvalidParameterErr)
			}
		}
		t = "ss://" + l
		if len(r) > 0 {
			t += "#" + r
		}
		v, _ = parse(t)
	}
	if v == nil {
		return nil, fmt.Errorf("unrecognized ss address: %w", dialer.InvalidParameterErr)
	}
	return v, nil
}

// ExportToURL exports a Shadowsocks config back to a SIP002 URL.
func (s *Shadowsocks) ExportToURL() string {
	userPass := base64.URLEncoding.EncodeToString([]byte(s.Cipher + ":" + s.Password))
	userPass = strings.TrimSuffix(userPass, "=")
	u := &url.URL{
		Scheme:   "ss",
		User:     url.User(userPass),
		Host:     net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
		Fragment: s.Name,
	}
	return u.String()
}
