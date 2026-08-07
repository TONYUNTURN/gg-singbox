package cmd

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mzz2017/gg/config"
	"github.com/mzz2017/gg/dialer"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

func TestMain(m *testing.M) {
	fromLink := func(link string, _ *dialer.GlobalOption) (*dialer.Dialer, error) {
		u, err := url.Parse(link)
		if err != nil {
			return nil, err
		}
		return dialer.NewDialer(subscriptionResolverDialer{}, true, u.Fragment, "shadowsocks", link), nil
	}
	fromClash := func(clashObj *yaml.Node, _ *dialer.GlobalOption) (*dialer.Dialer, error) {
		var proxy struct {
			Name string `yaml:"name"`
			UDP  bool   `yaml:"udp"`
		}
		if err := clashObj.Decode(&proxy); err != nil {
			return nil, err
		}
		return dialer.NewDialer(subscriptionResolverDialer{}, proxy.UDP, proxy.Name, "shadowsocks", ""), nil
	}
	dialer.FromLinkRegister("ss", fromLink)
	dialer.FromLinkRegister("shadowsocks", fromLink)
	dialer.FromClashRegister("ss", fromClash)
	os.Exit(m.Run())
}

type subscriptionResolverDialer struct{}

func (subscriptionResolverDialer) Dial(network, _ string) (net.Conn, error) {
	return nil, net.UnknownNetworkError(network)
}

func TestResolveSubscriptionRawSIP008(t *testing.T) {
	raw := []byte(`{
  "version": 1,
  "servers": [{
    "id": "local-sip008",
    "remarks": "local-sip008",
    "server": "127.0.0.1",
    "server_port": 8388,
    "password": "test-password",
    "method": "aes-128-gcm"
  }]
}`)

	dialers, err := resolveSubscription(testLogger(), &dialer.GlobalOption{}, raw)
	if err != nil {
		t.Fatalf("resolveSubscription(raw SIP008) error = %v", err)
	}
	assertSingleDialer(t, dialers, "local-sip008", "shadowsocks", true)
}

func TestResolveSubscriptionBase64SIP008DoesNotReturnEmptySuccess(t *testing.T) {
	raw := []byte(`{"version":1,"servers":[{"id":"local-base64-sip008","remarks":"local-base64-sip008","server":"127.0.0.1","server_port":8388,"password":"test-password","method":"aes-128-gcm"}]}`)
	encoded := []byte(base64.StdEncoding.EncodeToString(raw))

	dialers, err := resolveSubscription(testLogger(), &dialer.GlobalOption{}, encoded)
	if err != nil {
		t.Fatalf("resolveSubscription(base64 SIP008) error = %v", err)
	}
	assertSingleDialer(t, dialers, "local-base64-sip008", "shadowsocks", true)
}

func TestResolveSubscriptionBase64ShareLinks(t *testing.T) {
	link := "ss://YWVzLTEyOC1nY206dGVzdC1wYXNzd29yZA@127.0.0.1:8388#local-share-link"
	encoded := []byte(base64.StdEncoding.EncodeToString([]byte(link + "\n")))

	dialers, err := resolveSubscription(testLogger(), &dialer.GlobalOption{}, encoded)
	if err != nil {
		t.Fatalf("resolveSubscription(base64 share links) error = %v", err)
	}
	assertSingleDialer(t, dialers, "local-share-link", "shadowsocks", true)
}

func TestResolveSubscriptionBase64Clash(t *testing.T) {
	raw := []byte("proxies:\n  - name: base64-clash\n    type: ss\n    server: 127.0.0.1\n    port: 8388\n    cipher: aes-128-gcm\n    password: test-password\n    udp: true\n")
	encoded := []byte(base64.RawURLEncoding.EncodeToString(raw))
	dialers, err := resolveSubscription(testLogger(), &dialer.GlobalOption{}, encoded)
	if err != nil {
		t.Fatalf("resolveSubscription(base64 Clash) error = %v", err)
	}
	assertSingleDialer(t, dialers, "base64-clash", "shadowsocks", true)
}

func TestResolveSubscriptionRawClash(t *testing.T) {
	raw := []byte(`proxies:
  - name: local-clash
    type: ss
    server: 127.0.0.1
    port: 8388
    cipher: aes-128-gcm
    password: test-password
    udp: true
`)

	dialers, err := resolveSubscription(testLogger(), &dialer.GlobalOption{}, raw)
	if err != nil {
		t.Fatalf("resolveSubscription(raw Clash) error = %v", err)
	}
	assertSingleDialer(t, dialers, "local-clash", "shadowsocks", true)
}

func TestResolveSubscriptionWhitespaceBOMAndPartialFailures(t *testing.T) {
	t.Run("raw SIP008 BOM", func(t *testing.T) {
		raw := []byte(" \r\n\ufeff" + `{"version":1,"servers":[{"remarks":"bom-sip008","server":"127.0.0.1","server_port":8388,"password":"test-password","method":"aes-128-gcm"}]}` + "\n ")
		dialers, err := resolveSubscription(testLogger(), &dialer.GlobalOption{}, raw)
		if err != nil {
			t.Fatalf("resolveSubscription() error = %v", err)
		}
		assertSingleDialer(t, dialers, "bom-sip008", "shadowsocks", true)
	})

	t.Run("SIP008 keep valid server", func(t *testing.T) {
		raw := []byte(`{"version":1,"servers":[{"remarks":"invalid","server":"127.0.0.1","server_port":0,"password":"test-password","method":"aes-128-gcm"},{"remarks":"kept-sip008","server":"127.0.0.1","server_port":8388,"password":"test-password","method":"aes-128-gcm"}]}`)
		dialers, err := resolveSubscription(testLogger(), &dialer.GlobalOption{}, raw)
		if err != nil {
			t.Fatalf("resolveSubscription() error = %v", err)
		}
		assertSingleDialer(t, dialers, "kept-sip008", "shadowsocks", true)
	})

	t.Run("share links CRLF keep valid", func(t *testing.T) {
		valid := "ss://YWVzLTEyOC1nY206dGVzdC1wYXNzd29yZA@127.0.0.1:8388#kept-link"
		raw := []byte(" \r\ninvalid://node\r\n  " + valid + "  \r\n\r\n")
		dialers, err := resolveSubscription(testLogger(), &dialer.GlobalOption{}, raw)
		if err != nil {
			t.Fatalf("resolveSubscription() error = %v", err)
		}
		assertSingleDialer(t, dialers, "kept-link", "shadowsocks", true)
	})

	t.Run("Clash keep supported node", func(t *testing.T) {
		raw := []byte("\ufeffproxies:\n  - name: ignored\n    type: unsupported\n  - name: kept-clash\n    type: ss\n    server: 127.0.0.1\n    port: 8388\n    cipher: aes-128-gcm\n    password: test-password\n    udp: true\n")
		dialers, err := resolveSubscription(testLogger(), &dialer.GlobalOption{}, raw)
		if err != nil {
			t.Fatalf("resolveSubscription() error = %v", err)
		}
		assertSingleDialer(t, dialers, "kept-clash", "shadowsocks", true)
	})
}

func TestResolveSubscriptionBase64Variants(t *testing.T) {
	link := "ss://YWVzLTEyOC1nY206dGVzdC1wYXNzd29yZA@127.0.0.1:8388#base64-variant"
	tests := map[string]string{
		"standard padded": base64.StdEncoding.EncodeToString([]byte(link)),
		"standard raw":    base64.RawStdEncoding.EncodeToString([]byte(link)),
		"URL-safe padded": base64.URLEncoding.EncodeToString([]byte(link)),
		"URL-safe raw":    base64.RawURLEncoding.EncodeToString([]byte(link)),
	}
	for name, encoded := range tests {
		t.Run(name, func(t *testing.T) {
			dialers, err := resolveSubscription(testLogger(), &dialer.GlobalOption{}, []byte(" \ufeff"+encoded+"\r\n"))
			if err != nil {
				t.Fatalf("resolveSubscription() error = %v", err)
			}
			assertSingleDialer(t, dialers, "base64-variant", "shadowsocks", true)
		})
	}
}

func TestResolveSubscriptionEmptyRecognizedFormatsReturnError(t *testing.T) {
	inputs := map[string]string{
		"SIP008":        `{"version":1,"servers":[]}`,
		"Clash":         "proxies: []\n",
		"links":         "\r\n  \r\n",
		"bad link list": "invalid://node\r\nalso-invalid",
	}
	for name, input := range inputs {
		t.Run(name, func(t *testing.T) {
			if dialers, err := resolveSubscription(testLogger(), &dialer.GlobalOption{}, []byte(input)); err == nil {
				closeDialers(dialers)
				t.Fatalf("resolveSubscription() = %d dialers, nil error", len(dialers))
			}
		})
	}
}

func TestPullSubscriptionHTTPBoundaries(t *testing.T) {
	valid := "ss://YWVzLTEyOC1nY206dGVzdC1wYXNzd29yZA@127.0.0.1:8388#http-node"

	t.Run("body closed", func(t *testing.T) {
		body := &trackingReadCloser{Reader: strings.NewReader(valid)}
		client := &http.Client{
			Timeout: time.Second,
			Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Status:     "200 OK",
					Body:       body,
				}, nil
			}),
		}
		dialers, err := pullDialersFromSubscriptionWithClient(testLogger(), &dialer.GlobalOption{}, "http://127.0.0.1/subscription", client)
		if err != nil {
			t.Fatalf("pullDialersFromSubscriptionWithClient() error = %v", err)
		}
		assertSingleDialer(t, dialers, "http-node", "shadowsocks", true)
		if !body.closed {
			t.Fatal("response body was not closed")
		}
	})

	t.Run("non-2xx deterministic", func(t *testing.T) {
		body := &trackingReadCloser{Reader: strings.NewReader("local failure")}
		client := &http.Client{
			Timeout: time.Second,
			Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusBadGateway, Status: "502 Bad Gateway", Body: body}, nil
			}),
		}
		if _, err := pullDialersFromSubscriptionWithClient(testLogger(), &dialer.GlobalOption{}, "http://127.0.0.1/subscription", client); err == nil {
			t.Fatal("pullDialersFromSubscriptionWithClient() error = nil, want status error")
		}
		if !body.closed {
			t.Fatal("response body was not closed")
		}
	})

	t.Run("body too large deterministic", func(t *testing.T) {
		body := &trackingReadCloser{Reader: strings.NewReader(strings.Repeat("x", maxSubscriptionBodySize+1))}
		client := &http.Client{
			Timeout: time.Second,
			Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: body}, nil
			}),
		}
		if _, err := pullDialersFromSubscriptionWithClient(testLogger(), &dialer.GlobalOption{}, "http://127.0.0.1/subscription", client); err == nil {
			t.Fatal("pullDialersFromSubscriptionWithClient() error = nil, want size error")
		}
		if !body.closed {
			t.Fatal("response body was not closed")
		}
	})

	t.Run("success", func(t *testing.T) {
		server := newLocalHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, valid)
		}))
		client := server.Client()
		client.Timeout = time.Second
		dialers, err := pullDialersFromSubscriptionWithClient(testLogger(), &dialer.GlobalOption{}, server.URL, client)
		if err != nil {
			t.Fatalf("pullDialersFromSubscriptionWithClient() error = %v", err)
		}
		assertSingleDialer(t, dialers, "http-node", "shadowsocks", true)
	})

	t.Run("non-2xx", func(t *testing.T) {
		server := newLocalHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "local failure", http.StatusBadGateway)
		}))
		client := server.Client()
		client.Timeout = time.Second
		if _, err := pullDialersFromSubscriptionWithClient(testLogger(), &dialer.GlobalOption{}, server.URL, client); err == nil {
			t.Fatal("pullDialersFromSubscriptionWithClient() error = nil, want status error")
		}
	})

	t.Run("body too large", func(t *testing.T) {
		server := newLocalHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.Copy(w, strings.NewReader(strings.Repeat("x", maxSubscriptionBodySize+1)))
		}))
		client := server.Client()
		client.Timeout = time.Second
		if _, err := pullDialersFromSubscriptionWithClient(testLogger(), &dialer.GlobalOption{}, server.URL, client); err == nil {
			t.Fatal("pullDialersFromSubscriptionWithClient() error = nil, want size error")
		}
	})

	t.Run("request timeout", func(t *testing.T) {
		server := newLocalHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			timer := time.NewTimer(time.Second)
			defer timer.Stop()
			select {
			case <-r.Context().Done():
			case <-timer.C:
				_, _ = io.WriteString(w, valid)
			}
		}))
		client := server.Client()
		client.Timeout = 20 * time.Millisecond
		if _, err := pullDialersFromSubscriptionWithClient(testLogger(), &dialer.GlobalOption{}, server.URL, client); err == nil {
			t.Fatal("pullDialersFromSubscriptionWithClient() error = nil, want timeout error")
		}
	})

	t.Run("body read timeout", func(t *testing.T) {
		server := newLocalHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			flusher, ok := w.(http.Flusher)
			if !ok {
				t.Error("response writer does not implement http.Flusher")
				return
			}
			w.WriteHeader(http.StatusOK)
			flusher.Flush()
			<-r.Context().Done()
		}))
		client := server.Client()
		client.Timeout = 20 * time.Millisecond
		if _, err := pullDialersFromSubscriptionWithClient(testLogger(), &dialer.GlobalOption{}, server.URL, client); err == nil {
			t.Fatal("pullDialersFromSubscriptionWithClient() error = nil, want body read timeout")
		}
	})

	t.Run("connection error", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Skipf("loopback sockets unavailable: %v", err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		address := listener.Addr().String()
		if err := listener.Close(); err != nil {
			t.Fatalf("listener.Close() error = %v", err)
		}
		client := &http.Client{Timeout: 100 * time.Millisecond}
		if _, err := pullDialersFromSubscriptionWithClient(testLogger(), &dialer.GlobalOption{}, "http://"+address, client); err == nil {
			t.Fatal("pullDialersFromSubscriptionWithClient() error = nil, want connection error")
		}
	})
}

func newLocalHTTPTestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback sockets unavailable: %v", err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.Listener = listener
	server.Start()
	t.Cleanup(server.Close)
	return server
}

func TestCloseDialersExcept(t *testing.T) {
	keptBox := &fakeSubscriptionBox{}
	closedBox := &fakeSubscriptionBox{}
	kept := dialer.NewDialer(keptBox, false, "kept", "fake", "")
	closed := dialer.NewDialer(closedBox, false, "closed", "fake", "")
	t.Cleanup(func() { _ = kept.Close() })

	closeDialersExcept([]*dialer.Dialer{kept, closed}, kept)
	if keptBox.closed != 0 || closedBox.closed != 1 {
		t.Fatalf("close calls kept/closed = %d/%d, want 0/1", keptBox.closed, closedBox.closed)
	}
}

func TestGetDialerFromSubscriptionManualKeepsSelectedAndClosesOthers(t *testing.T) {
	selectedBox := &fakeSubscriptionBox{}
	otherBox := &fakeSubscriptionBox{}
	dialer.FromLinkRegister("lifecycle", func(link string, _ *dialer.GlobalOption) (*dialer.Dialer, error) {
		u, err := url.Parse(link)
		if err != nil {
			return nil, err
		}
		box := otherBox
		if u.Fragment == "selected" {
			box = selectedBox
		}
		return dialer.NewDialer(box, false, u.Fragment, "lifecycle", link), nil
	})

	server := newLocalHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "lifecycle://127.0.0.1:1#other\nlifecycle://127.0.0.1:2#selected\n")
	}))
	originalParams := config.ParamsObj
	config.ParamsObj = config.Params{
		Subscription: config.Subscription{
			Link:   server.URL,
			Select: "manual",
		},
	}
	t.Cleanup(func() { config.ParamsObj = originalParams })

	originalSelector := selectSubscriptionNodeFromInput
	selectSubscriptionNodeFromInput = func(nodes []*DialerWithLatency) (*DialerWithLatency, error) {
		for _, node := range nodes {
			if node.Dialer.Name() == "selected" {
				return node, nil
			}
		}
		return nil, errors.New("selected test node not found")
	}
	t.Cleanup(func() { selectSubscriptionNodeFromInput = originalSelector })

	selected, err := GetDialerFromSubscription(testLogger(), &dialer.GlobalOption{}, false, "")
	if err != nil {
		t.Fatalf("GetDialerFromSubscription() error = %v", err)
	}
	t.Cleanup(func() { _ = selected.Close() })
	if selected.Name() != "selected" {
		t.Fatalf("GetDialerFromSubscription().Name() = %q, want selected", selected.Name())
	}
	if selectedBox.closed != 0 || otherBox.closed != 1 {
		t.Fatalf("close calls selected/other = %d/%d, want 0/1", selectedBox.closed, otherBox.closed)
	}
}

func TestSubscriptionProxyRequiresCancellationAndCloses(t *testing.T) {
	box := &fakeSubscriptionBox{}
	proxyDialer := dialer.NewDialer(box, false, "legacy", "fake", "")
	if _, err := pullDialersFromSubscription(testLogger(), &dialer.GlobalOption{}, "http://127.0.0.1/subscription", proxyDialer); err == nil {
		t.Fatal("pullDialersFromSubscription() error = nil, want cancellation support error")
	}
	if box.closed != 1 {
		t.Fatalf("proxy dialer close calls = %d, want 1", box.closed)
	}
}

type fakeSubscriptionBox struct {
	closed int
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type trackingReadCloser struct {
	io.Reader
	closed bool
}

func (r *trackingReadCloser) Close() error {
	r.closed = true
	return nil
}

func (b *fakeSubscriptionBox) Dial(string, string) (net.Conn, error) {
	return nil, context.Canceled
}

func (b *fakeSubscriptionBox) Close() error {
	b.closed++
	return nil
}

func TestResolveSubscriptionInvalidBase64ReturnsError(t *testing.T) {
	dialers, err := resolveSubscription(testLogger(), &dialer.GlobalOption{}, []byte("not a subscription"))
	if err == nil {
		t.Fatalf("resolveSubscription(invalid input) = %d dialers, nil error; want an error", len(dialers))
	}
	if len(dialers) != 0 {
		t.Fatalf("resolveSubscription(invalid input) returned %d dialers, want 0", len(dialers))
	}
}

func assertSingleDialer(t *testing.T, dialers []*dialer.Dialer, name, protocol string, supportUDP bool) {
	t.Helper()
	if len(dialers) != 1 {
		t.Fatalf("resolved dialer count = %d, want 1", len(dialers))
	}
	d := dialers[0]
	t.Cleanup(func() {
		if err := d.Close(); err != nil {
			t.Errorf("dialer.Close() error = %v", err)
		}
	})
	if got := d.Name(); got != name {
		t.Errorf("dialer.Name() = %q, want %q", got, name)
	}
	if got := d.Protocol(); got != protocol {
		t.Errorf("dialer.Protocol() = %q, want %q", got, protocol)
	}
	if got := d.SupportUDP(); got != supportUDP {
		t.Errorf("dialer.SupportUDP() = %v, want %v", got, supportUDP)
	}
}

func testLogger() *logrus.Logger {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	return logger
}
