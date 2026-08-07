package singbox

import (
	"fmt"
	"strconv"

	"github.com/gofrs/uuid/v5"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/mzz2017/gg/dialer"
)

// NewV2Ray creates a *dialer.Dialer from a vmess:// or vless:// URL using sing-box.
func NewV2Ray(link string, opt *dialer.GlobalOption) (*dialer.Dialer, error) {
	var (
		s        *V2Ray
		err      error
		protocol string
	)
	switch {
	case len(link) >= 8 && link[:8] == "vmess://":
		s, err = ParseVmessURL(link)
		if err != nil {
			return nil, err
		}
		if s.Aid != "0" && s.Aid != "" {
			return nil, fmt.Errorf("%w: aid: %v, we only support AEAD encryption", dialer.UnexpectedFieldErr, s.Aid)
		}
		protocol = "vmess"
	case len(link) >= 8 && link[:8] == "vless://":
		s, err = ParseVlessURL(link)
		if err != nil {
			return nil, err
		}
		protocol = "vless"
	default:
		return nil, dialer.InvalidParameterErr
	}
	if opt != nil && opt.AllowInsecure {
		s.AllowInsecure = true
	}
	return buildV2RayDialer(s, protocol, link)
}

func buildV2RayDialer(s *V2Ray, protocol, link string) (*dialer.Dialer, error) {
	tag := protocol + "-" + s.Ps
	if tag == protocol+"-" {
		tag = protocol + "-outbound"
	}

	var obOpt option.Outbound
	var err error

	switch protocol {
	case "vmess":
		obOpt, err = buildVMessOutbound(s, tag)
	case "vless":
		obOpt, err = buildVLESSOutbound(s, tag)
	}
	if err != nil {
		return nil, err
	}

	box, outbound, err := CreateBox(obOpt)
	if err != nil {
		return nil, fmt.Errorf("create sing-box for %s: %w", protocol, err)
	}

	return NewSingBoxDialer(outbound, box, s.Ps, protocol, link), nil
}

func buildVMessOutbound(s *V2Ray, tag string) (option.Outbound, error) {
	portInt, err := strconv.Atoi(s.Port)
	if s.Add == "" || s.ID == "" || err != nil || portInt < 1 || portInt > 65535 {
		return option.Outbound{}, fmt.Errorf("%w: vmess requires user, host, and valid port", dialer.InvalidParameterErr)
	}

	opts := &option.VMessOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     s.Add,
			ServerPort: uint16(portInt),
		},
		UUID:     s.ID,
		Security: "auto",
	}

	applyV2RayTransportToVMess(opts, s)

	return option.Outbound{
		Type:    C.TypeVMess,
		Tag:     tag,
		Options: opts,
	}, nil
}

func buildVLESSOutbound(s *V2Ray, tag string) (option.Outbound, error) {
	portInt, err := strconv.Atoi(s.Port)
	if s.Add == "" || err != nil || portInt < 1 || portInt > 65535 {
		return option.Outbound{}, fmt.Errorf("%w: vless requires host and valid port", dialer.InvalidParameterErr)
	}
	if _, err := uuid.FromString(s.ID); err != nil {
		return option.Outbound{}, fmt.Errorf("%w: invalid vless UUID", dialer.InvalidParameterErr)
	}
	if err := validateVLESSFlow(s.Flow); err != nil {
		return option.Outbound{}, err
	}

	opts := &option.VLESSOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     s.Add,
			ServerPort: uint16(portInt),
		},
		UUID: s.ID,
		Flow: s.Flow,
	}

	applyV2RayTransportToVLESS(opts, s)

	return option.Outbound{
		Type:    C.TypeVLESS,
		Tag:     tag,
		Options: opts,
	}, nil
}

func validateVLESSFlow(flow string) error {
	switch flow {
	case "", "xtls-rprx-vision":
		return nil
	default:
		return fmt.Errorf("%w: unsupported vless flow %q", dialer.InvalidParameterErr, flow)
	}
}

func applyV2RayTransportToVMess(opts *option.VMessOutboundOptions, s *V2Ray) {
	transport := buildV2RayTransport(s)
	if transport != nil {
		opts.Transport = transport
	}
	if s.TLS != "" && s.TLS != "none" {
		opts.OutboundTLSOptionsContainer.TLS = buildV2RayTLS(s)
	}
}

func applyV2RayTransportToVLESS(opts *option.VLESSOutboundOptions, s *V2Ray) {
	transport := buildV2RayTransport(s)
	if transport != nil {
		opts.Transport = transport
	}
	if s.TLS != "" && s.TLS != "none" {
		opts.OutboundTLSOptionsContainer.TLS = buildV2RayTLS(s)
	}
}

func buildV2RayTransport(s *V2Ray) *option.V2RayTransportOptions {
	switch s.Net {
	case "ws":
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeWebsocket,
			WebsocketOptions: option.V2RayWebsocketOptions{
				Path: s.Path,
				Headers: map[string]badoption.Listable[string]{
					"Host": {s.Host},
				},
			},
		}
	case "grpc":
		serviceName := s.Path
		if serviceName == "" {
			serviceName = "GunService"
		}
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeGRPC,
			GRPCOptions: option.V2RayGRPCOptions{
				ServiceName: serviceName,
			},
		}
	}
	return nil
}

func buildV2RayTLS(s *V2Ray) *option.OutboundTLSOptions {
	sni := s.SNI
	if sni == "" {
		sni = s.Host
	}
	tlsOpt := &option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: sni,
		Insecure:   s.AllowInsecure,
	}
	if s.Alpn != "" {
		tlsOpt.ALPN = badoption.Listable[string]{s.Alpn}
	}
	// REALITY
	if s.TLS == "reality" && s.Pbk != "" {
		tlsOpt.Reality = &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: s.Pbk,
			ShortID:   s.Sid,
		}
	}
	// UTLS fingerprint
	if s.Fp != "" {
		tlsOpt.UTLS = &option.OutboundUTLSOptions{
			Enabled:     true,
			Fingerprint: s.Fp,
		}
	}
	return tlsOpt
}
