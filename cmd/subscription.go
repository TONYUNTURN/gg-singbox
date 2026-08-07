package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/mzz2017/gg/common"
	"github.com/mzz2017/gg/dialer"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	maxSubscriptionBodySize = 1 << 20
	subscriptionHTTPTimeout = 30 * time.Second
)

type ClashConfig struct {
	Proxy []yaml.Node `yaml:"proxies"`
}

type SIP008 struct {
	Version        int            `json:"version"`
	Servers        []SIP008Server `json:"servers"`
	BytesUsed      int64          `json:"bytes_used"`
	BytesRemaining int64          `json:"bytes_remaining"`
}

type SIP008Server struct {
	Id         string `json:"id"`
	Remarks    string `json:"remarks"`
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
	Password   string `json:"password"`
	Method     string `json:"method"`
	Plugin     string `json:"plugin"`
	PluginOpts string `json:"plugin_opts"`
}

func resolveSubscriptionAsClash(log *logrus.Logger, opt *dialer.GlobalOption, b []byte) (dialers []*dialer.Dialer, err error) {
	log.Traceln("try to resolve as Clash")
	b = normalizeSubscriptionInput(b)

	var conf ClashConfig
	if err = yaml.NewDecoder(strings.NewReader(string(b))).Decode(&conf); err != nil {
		return nil, err
	}
	if len(conf.Proxy) == 0 {
		return nil, fmt.Errorf("does not seem like a Clash subscription")
	}
	for i, node := range conf.Proxy {
		d, e := dialer.NewFromClash(&node, opt)
		if e != nil {
			if d != nil {
				_ = d.Close()
			}
			log.Tracef("proxies[%v]: %v\n", i, e)
			continue
		}
		dialers = append(dialers, d)
	}
	if len(dialers) == 0 {
		return nil, fmt.Errorf("Clash subscription contains no supported nodes")
	}
	return dialers, nil
}

func resolveSubscriptionAsLinks(log *logrus.Logger, opt *dialer.GlobalOption, b []byte) (dialers []*dialer.Dialer, err error) {
	b = normalizeSubscriptionInput(b)
	lines := strings.Split(string(b), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		d, e := GetDialerFromLink(line, opt, false, "")
		if e != nil {
			if d != nil {
				_ = d.Close()
			}
			log.Tracef("invalid share link: %v", e)
			continue
		}
		dialers = append(dialers, d)
	}
	if len(dialers) == 0 {
		return nil, fmt.Errorf("subscription contains no supported share links")
	}
	return dialers, nil
}

func resolveSubscriptionAsBase64(log *logrus.Logger, opt *dialer.GlobalOption, b []byte) ([]*dialer.Dialer, error) {
	log.Traceln("try to resolve as base64")
	b = normalizeSubscriptionInput(b)

	raw, err := common.Base64StdDecode(string(b))
	if err != nil {
		raw, err = common.Base64URLDecode(string(b))
		if err != nil {
			return nil, fmt.Errorf("decode base64 subscription: %w", err)
		}
	}
	decoded := []byte(raw)
	if dialers, err := resolveSubscriptionAsSIP008(log, opt, decoded); err == nil {
		return dialers, nil
	}
	if dialers, err := resolveSubscriptionAsClash(log, opt, decoded); err == nil {
		return dialers, nil
	}
	return resolveSubscriptionAsLinks(log, opt, decoded)
}

func resolveSubscriptionAsSIP008(log *logrus.Logger, opt *dialer.GlobalOption, b []byte) (dialers []*dialer.Dialer, err error) {
	log.Traceln("try to resolve as SIP008")
	b = normalizeSubscriptionInput(b)

	var sip SIP008
	err = json.Unmarshal(b, &sip)
	if err != nil {
		return
	}
	if sip.Version != 1 || len(sip.Servers) == 0 {
		return nil, fmt.Errorf("does not seem like a SIP008 subscription")
	}
	for i, server := range sip.Servers {
		if server.Server == "" || server.ServerPort < 1 || server.ServerPort > 65535 || server.Method == "" || server.Password == "" {
			log.Tracef("servers[%v]: missing required Shadowsocks fields", i)
			continue
		}
		u := url.URL{
			Scheme:   "ss",
			User:     url.UserPassword(server.Method, server.Password),
			Host:     net.JoinHostPort(server.Server, strconv.Itoa(server.ServerPort)),
			RawQuery: url.Values{"plugin": []string{server.PluginOpts}}.Encode(),
			Fragment: server.Remarks,
		}
		d, e := dialer.NewFromLink("shadowsocks", u.String(), opt)
		if e != nil {
			if d != nil {
				_ = d.Close()
			}
			log.Tracef("servers[%v]: %v\n", i, e)
			continue
		}
		dialers = append(dialers, d)
	}
	if len(dialers) == 0 {
		return nil, fmt.Errorf("SIP008 subscription contains no supported nodes")
	}
	return dialers, nil
}

// resolveSubscription parses subscription content without fetching it. It is
// the deterministic seam used by tests and by the HTTP subscription path.
func resolveSubscription(log *logrus.Logger, opt *dialer.GlobalOption, b []byte) ([]*dialer.Dialer, error) {
	b = normalizeSubscriptionInput(b)
	dialers, sipErr := resolveSubscriptionAsSIP008(log, opt, b)
	if sipErr == nil {
		return dialers, nil
	}
	dialers, clashErr := resolveSubscriptionAsClash(log, opt, b)
	if clashErr == nil {
		return dialers, nil
	}
	dialers, linksErr := resolveSubscriptionAsLinks(log, opt, b)
	if linksErr == nil {
		return dialers, nil
	}
	dialers, base64Err := resolveSubscriptionAsBase64(log, opt, b)
	if base64Err == nil {
		return dialers, nil
	}
	return nil, fmt.Errorf("unrecognized subscription (SIP008: %v; Clash: %v; links: %v; Base64: %w)", sipErr, clashErr, linksErr, base64Err)
}

func normalizeSubscriptionInput(b []byte) []byte {
	b = bytes.TrimSpace(b)
	b = bytes.TrimPrefix(b, []byte{0xef, 0xbb, 0xbf})
	return bytes.TrimSpace(b)
}

func pullDialersFromSubscription(log *logrus.Logger, opt *dialer.GlobalOption, subscription string, proxyDialer *dialer.Dialer) (dialers []*dialer.Dialer, err error) {
	var client *http.Client
	var transport *http.Transport
	if proxyDialer != nil {
		defer proxyDialer.Close()
		contextDialer, ok := proxyDialer.Dialer.(interface {
			DialContext(context.Context, string, string) (net.Conn, error)
		})
		if !ok {
			return nil, fmt.Errorf("subscription proxy dialer does not support cancellation")
		}
		transport = &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return contextDialer.DialContext(ctx, network, addr)
			},
		}
		client = &http.Client{
			Transport: transport,
			Timeout:   subscriptionHTTPTimeout,
		}
	} else {
		client = &http.Client{Timeout: subscriptionHTTPTimeout}
	}
	if transport != nil {
		defer transport.CloseIdleConnections()
	}
	return pullDialersFromSubscriptionWithClient(log, opt, subscription, client)
}

func pullDialersFromSubscriptionWithClient(log *logrus.Logger, opt *dialer.GlobalOption, subscription string, client *http.Client) ([]*dialer.Dialer, error) {
	if client == nil {
		return nil, fmt.Errorf("subscription HTTP client is nil")
	}
	ctx, cancel := context.WithTimeout(context.Background(), subscriptionHTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, subscription, nil)
	if err != nil {
		return nil, fmt.Errorf("create subscription request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch subscription: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("fetch subscription: unexpected HTTP status %s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxSubscriptionBodySize+1))
	if err != nil {
		return nil, fmt.Errorf("read subscription response: %w", err)
	}
	if len(b) > maxSubscriptionBodySize {
		return nil, fmt.Errorf("subscription response exceeds %d bytes", maxSubscriptionBodySize)
	}
	return resolveSubscription(log, opt, b)
}
