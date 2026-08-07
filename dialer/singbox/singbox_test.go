package singbox

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/mzz2017/gg/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"gopkg.in/yaml.v3"
)

type fakeOutbound struct {
	networks []string
}

func (f *fakeOutbound) Tag() string { return "local-outbound" }

func (f *fakeOutbound) Network() []string { return f.networks }

func (f *fakeOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("unexpected dial")
}

func (f *fakeOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unexpected packet listen")
}

type fakeBox struct {
	closeCalls atomic.Int32
}

func (b *fakeBox) Close() error {
	b.closeCalls.Add(1)
	return nil
}

func TestParseSSURLValidSIP002(t *testing.T) {
	link := "ss://YWVzLTEyOC1nY206dGVzdC1wYXNzd29yZA@127.0.0.1:8388#local-ss"
	parsed, err := ParseSSURL(link)
	if err != nil {
		t.Fatalf("ParseSSURL() error = %v", err)
	}
	if parsed.Cipher != "aes-128-gcm" {
		t.Errorf("Cipher = %q, want %q", parsed.Cipher, "aes-128-gcm")
	}
	if parsed.Password != "test-password" {
		t.Errorf("Password = %q, want %q", parsed.Password, "test-password")
	}
	if parsed.Server != "127.0.0.1" || parsed.Port != 8388 {
		t.Errorf("server = %s:%d, want 127.0.0.1:8388", parsed.Server, parsed.Port)
	}
	if parsed.Name != "local-ss" {
		t.Errorf("Name = %q, want %q", parsed.Name, "local-ss")
	}
}

func TestParseSSURLPlainCredentialsWithEscaping(t *testing.T) {
	parsed, err := ParseSSURL("ss://aes-128-gcm:p%40ss@127.0.0.1:8388#encoded-ss")
	if err != nil {
		t.Fatalf("ParseSSURL() error = %v", err)
	}
	if parsed.Cipher != "aes-128-gcm" || parsed.Password != "p@ss" {
		t.Fatalf("cipher/password = %q/%q, want aes-128-gcm/p@ss", parsed.Cipher, parsed.Password)
	}
}

func TestParseVmessURLValid(t *testing.T) {
	raw := []byte(`{"v":"2","ps":"local-vmess","add":"127.0.0.1","port":"443","id":"00000000-0000-4000-8000-000000000001","aid":"0","net":"tcp","type":"none"}`)
	parsed, err := ParseVmessURL("vmess://" + base64.RawStdEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatalf("ParseVmessURL() error = %v", err)
	}
	if parsed.Protocol != "vmess" || parsed.Add != "127.0.0.1" || parsed.Port != "443" || parsed.ID != "00000000-0000-4000-8000-000000000001" {
		t.Fatalf("parsed VMess = %#v", parsed)
	}
}

func TestParseVlessURLValid(t *testing.T) {
	link := "vless://00000000-0000-4000-8000-000000000001@127.0.0.1:443?type=ws&path=%2Flocal#local-vless"
	parsed, err := ParseVlessURL(link)
	if err != nil {
		t.Fatalf("ParseVlessURL() error = %v", err)
	}
	if parsed.Protocol != "vless" || parsed.Net != "ws" {
		t.Errorf("protocol/network = %q/%q, want vless/ws", parsed.Protocol, parsed.Net)
	}
	if parsed.Add != "127.0.0.1" || parsed.Port != "443" {
		t.Errorf("server = %s:%s, want 127.0.0.1:443", parsed.Add, parsed.Port)
	}
	if parsed.Path != "/local" {
		t.Errorf("Path = %q, want %q", parsed.Path, "/local")
	}
	if parsed.Flow != "" {
		t.Errorf("Flow = %q, want empty", parsed.Flow)
	}
}

func TestParseVlessURLFieldsAndFlowValidation(t *testing.T) {
	tests := []struct {
		name         string
		link         string
		wantHost     string
		wantName     string
		wantPath     string
		wantFlow     string
		wantNet      string
		wantType     string
		wantSecurity string
	}{
		{
			name:         "IPv4 defaults and URL encoding",
			link:         "vless://00000000-0000-4000-8000-000000000001@127.0.0.1:443?path=%2Fencoded%20path#encoded%20name",
			wantHost:     "127.0.0.1",
			wantName:     "encoded name",
			wantPath:     "/encoded path",
			wantNet:      "tcp",
			wantType:     "none",
			wantSecurity: "none",
		},
		{
			name:         "IPv6 Vision",
			link:         "vless://00000000-0000-4000-8000-000000000001@[::1]:8443?flow=xtls-rprx-vision&type=tcp&security=tls",
			wantHost:     "::1",
			wantFlow:     "xtls-rprx-vision",
			wantNet:      "tcp",
			wantType:     "none",
			wantSecurity: "tls",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ParseVlessURL(tt.link)
			if err != nil {
				t.Fatalf("ParseVlessURL() error = %v", err)
			}
			if parsed.Add != tt.wantHost || parsed.Ps != tt.wantName || parsed.Path != tt.wantPath {
				t.Errorf("host/name/path = %q/%q/%q, want %q/%q/%q", parsed.Add, parsed.Ps, parsed.Path, tt.wantHost, tt.wantName, tt.wantPath)
			}
			if parsed.Flow != tt.wantFlow || parsed.Net != tt.wantNet || parsed.Type != tt.wantType || parsed.TLS != tt.wantSecurity {
				t.Errorf("flow/net/type/security = %q/%q/%q/%q, want %q/%q/%q/%q", parsed.Flow, parsed.Net, parsed.Type, parsed.TLS, tt.wantFlow, tt.wantNet, tt.wantType, tt.wantSecurity)
			}
			outbound, err := buildVLESSOutbound(parsed, "validated-vless")
			if err != nil {
				t.Fatalf("buildVLESSOutbound() error = %v", err)
			}
			if got := outbound.Options.(*option.VLESSOutboundOptions).Flow; got != tt.wantFlow {
				t.Errorf("outbound flow = %q, want %q", got, tt.wantFlow)
			}
		})
	}
}

func TestVlessDeprecatedFlowRejectedBeforeBoxCreation(t *testing.T) {
	link := "vless://00000000-0000-4000-8000-000000000001@127.0.0.1:443?flow=xtls-rprx-direct"
	if _, err := NewV2Ray(link, nil); err == nil {
		t.Fatal("NewV2Ray() error = nil, want unsupported flow error")
	} else if !errors.Is(err, dialer.InvalidParameterErr) {
		t.Fatalf("NewV2Ray() error = %v, want errors.Is(InvalidParameterErr)", err)
	}
}

func TestVlessWithoutFlowBuildsSupportedOutbound(t *testing.T) {
	parsed, err := ParseVlessURL("vless://00000000-0000-4000-8000-000000000001@127.0.0.1:443")
	if err != nil {
		t.Fatalf("ParseVlessURL() error = %v", err)
	}
	outbound, err := buildVLESSOutbound(parsed, "plain-vless")
	if err != nil {
		t.Fatalf("buildVLESSOutbound() error = %v", err)
	}
	opts := outbound.Options.(*option.VLESSOutboundOptions)
	if opts.Flow != "" {
		t.Fatalf("outbound flow = %q, want empty", opts.Flow)
	}
}

func TestNewV2RayVlessWithoutFlowCreatesLocalBox(t *testing.T) {
	d, err := NewV2Ray("vless://00000000-0000-4000-8000-000000000001@127.0.0.1:443", nil)
	if err != nil {
		if errors.Is(err, os.ErrPermission) || strings.Contains(strings.ToLower(err.Error()), "operation not permitted") {
			t.Skipf("NewV2Ray() cannot start the sing-box route/listener in this sandbox due to insufficient permissions: %v", err)
		}
		t.Fatalf("NewV2Ray() error = %v, want successful local box creation", err)
	}
	t.Cleanup(func() {
		if err := d.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
}

func TestBuildVLESSOutboundValid(t *testing.T) {
	config := &V2Ray{
		Add:  "127.0.0.1",
		Port: "443",
		ID:   "00000000-0000-4000-8000-000000000001",
		Net:  "tcp",
		TLS:  "none",
	}
	outbound, err := buildVLESSOutbound(config, "local-vless")
	if err != nil {
		t.Fatalf("buildVLESSOutbound() error = %v", err)
	}
	if outbound.Type != C.TypeVLESS || outbound.Tag != "local-vless" {
		t.Fatalf("outbound type/tag = %q/%q, want %q/local-vless", outbound.Type, outbound.Tag, C.TypeVLESS)
	}
	opts, ok := outbound.Options.(*option.VLESSOutboundOptions)
	if !ok {
		t.Fatalf("outbound options type = %T, want *option.VLESSOutboundOptions", outbound.Options)
	}
	if opts.Server != "127.0.0.1" || opts.ServerPort != 443 || opts.UUID != config.ID {
		t.Fatalf("outbound server/UUID = %s:%d/%q, want 127.0.0.1:443/%q", opts.Server, opts.ServerPort, opts.UUID, config.ID)
	}
}

func TestProductionClashShadowsocksCreator(t *testing.T) {
	originalCreateBox := createShadowsocksBox
	var captured option.Outbound
	box := &fakeBox{}
	createShadowsocksBox = func(outbound option.Outbound) (interface{ Close() error }, singBoxOutbound, error) {
		captured = outbound
		return box, &fakeOutbound{networks: []string{N.NetworkTCP, N.NetworkUDP}}, nil
	}
	t.Cleanup(func() { createShadowsocksBox = originalCreateBox })

	RegisterAll()
	var node yaml.Node
	if err := yaml.Unmarshal([]byte("name: local-clash\ntype: ss\nserver: 127.0.0.1\nport: 8388\ncipher: aes-128-gcm\npassword: test-password\nudp: true\n"), &node); err != nil {
		t.Fatalf("yaml.Unmarshal() error = %v", err)
	}
	d, err := dialer.NewFromClash(node.Content[0], &dialer.GlobalOption{})
	if err != nil {
		t.Fatalf("dialer.NewFromClash() error = %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	if d.Name() != "local-clash" || d.Protocol() != "shadowsocks" || !d.SupportUDP() {
		t.Fatalf("dialer name/protocol/UDP = %q/%q/%v", d.Name(), d.Protocol(), d.SupportUDP())
	}
	opts, ok := captured.Options.(*option.ShadowsocksOutboundOptions)
	if !ok {
		t.Fatalf("captured options type = %T", captured.Options)
	}
	if opts.Server != "127.0.0.1" || opts.ServerPort != 8388 || opts.Method != "aes-128-gcm" || opts.Password != "test-password" {
		t.Fatalf("captured Shadowsocks options = %#v", opts)
	}
}

func TestMalformedExternalLinksReturnErrorWithoutPanic(t *testing.T) {
	validVMessJSON := base64.RawStdEncoding.EncodeToString([]byte(`{}`))
	tests := []struct {
		name  string
		parse func() error
	}{
		{name: "empty shadowsocks constructor", parse: func() error { _, err := NewShadowsocks("ss://", nil); return err }},
		{name: "short shadowsocks", parse: func() error { _, err := ParseSSURL("ss:"); return err }},
		{name: "empty shadowsocks", parse: func() error { _, err := ParseSSURL("ss://"); return err }},
		{name: "shadowsocks missing user", parse: func() error { _, err := ParseSSURL("ss://127.0.0.1:8388"); return err }},
		{name: "shadowsocks empty base64", parse: func() error { _, err := ParseSSURL("ss://@127.0.0.1:8388"); return err }},
		{name: "shadowsocks missing port", parse: func() error { _, err := ParseSSURL("ss://YWVzLTEyOC1nY206cGFzcw@127.0.0.1"); return err }},
		{name: "shadowsocks bad port", parse: func() error { _, err := ParseSSURL("ss://YWVzLTEyOC1nY206cGFzcw@127.0.0.1:99999"); return err }},
		{name: "shadowsocks invalid escape", parse: func() error { _, err := ParseSSURL("ss://YWVzLTEyOC1nY206cGFzcw@127.0.0.1:8388#bad%zz"); return err }},
		{name: "vless constructor missing user", parse: func() error { _, err := NewV2Ray("vless://127.0.0.1:443", nil); return err }},
		{name: "vless bad UUID", parse: func() error { _, err := ParseVlessURL("vless://not-a-uuid@127.0.0.1:443"); return err }},
		{name: "vless missing host", parse: func() error { _, err := ParseVlessURL("vless://00000000-0000-4000-8000-000000000001@:443"); return err }},
		{name: "vless missing port", parse: func() error {
			_, err := ParseVlessURL("vless://00000000-0000-4000-8000-000000000001@127.0.0.1")
			return err
		}},
		{name: "vless zero port", parse: func() error {
			_, err := ParseVlessURL("vless://00000000-0000-4000-8000-000000000001@127.0.0.1:0")
			return err
		}},
		{name: "vless invalid escape", parse: func() error {
			_, err := ParseVlessURL("vless://00000000-0000-4000-8000-000000000001@127.0.0.1:443#bad%zz")
			return err
		}},
		{name: "short vmess", parse: func() error { _, err := ParseVmessURL("vmess:"); return err }},
		{name: "empty vmess", parse: func() error { _, err := ParseVmessURL("vmess://"); return err }},
		{name: "vmess empty object", parse: func() error { _, err := ParseVmessURL("vmess://" + validVMessJSON); return err }},
		{name: "vmess bad base64", parse: func() error { _, err := ParseVmessURL("vmess://%%%"); return err }},
		{name: "short hysteria2", parse: func() error { _, err := NewHysteria2("hysteria2:", nil); return err }},
		{name: "hysteria2 missing user", parse: func() error { _, err := NewHysteria2("hysteria2://127.0.0.1:443", nil); return err }},
		{name: "short tuic", parse: func() error { _, err := NewTUIC("tuic:", nil); return err }},
		{name: "tuic missing password", parse: func() error {
			_, err := NewTUIC("tuic://00000000-0000-4000-8000-000000000001@127.0.0.1:443", nil)
			return err
		}},
		{name: "short trojan", parse: func() error { _, err := NewTrojan("trojan:", nil); return err }},
		{name: "trojan missing user", parse: func() error { _, err := NewTrojan("trojan://127.0.0.1:443", nil); return err }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("parser panicked: %v", recovered)
				}
			}()
			if err := tt.parse(); err == nil {
				t.Fatal("parser error = nil, want malformed link error")
			} else if !errors.Is(err, dialer.InvalidParameterErr) {
				t.Errorf("parser error = %v, want errors.Is(InvalidParameterErr)", err)
			}
		})
	}
}

func TestNewSingBoxDialerSupportUDPAndClose(t *testing.T) {
	box := &fakeBox{}
	d := newSingBoxDialer(
		&fakeOutbound{networks: []string{N.NetworkTCP, N.NetworkUDP}},
		box,
		"local-construction",
		"fake",
		"fake://local",
	)

	if !d.SupportUDP() {
		t.Error("SupportUDP() = false, want true")
	}
	if d.Protocol() != "fake" {
		t.Errorf("Protocol() = %q, want fake", d.Protocol())
	}
	if err := d.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if got := box.closeCalls.Load(); got != 1 {
		t.Fatalf("box Close() calls = %d, want 1", got)
	}
}
