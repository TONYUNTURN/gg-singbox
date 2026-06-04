package singbox

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	jsoniter "github.com/json-iterator/go"

	"github.com/mzz2017/gg/common"
	"github.com/mzz2017/gg/dialer"
)

// V2Ray holds parsed VMess/VLESS URL data.
type V2Ray struct {
	Ps            string `json:"ps"`
	Add           string `json:"add"`
	Port          string `json:"port"`
	ID            string `json:"id"`
	Aid           string `json:"aid"`
	Net           string `json:"net"`
	Type          string `json:"type"`
	Host          string `json:"host"`
	SNI           string `json:"sni"`
	Path          string `json:"path"`
	TLS           string `json:"tls"`
	Flow          string `json:"flow,omitempty"`
	Alpn          string `json:"alpn,omitempty"`
	AllowInsecure bool   `json:"allowInsecure"`
	V             string `json:"v"`
	Protocol      string `json:"protocol"`
	// REALITY fields
	Pbk string `json:"pbk,omitempty"` // public key
	Sid string `json:"sid,omitempty"` // short ID
	Fp  string `json:"fp,omitempty"`  // fingerprint (e.g. chrome)
}

// ExportToURL exports the V2Ray config back to a share-link URL.
func (s *V2Ray) ExportToURL() string {
	switch s.Protocol {
	case "vless":
		var query = make(url.Values)
		common.SetValue(&query, "type", s.Net)
		common.SetValue(&query, "security", s.TLS)
		switch s.Net {
		case "websocket", "ws", "http", "h2":
			common.SetValue(&query, "path", s.Path)
			common.SetValue(&query, "host", s.Host)
		case "mkcp", "kcp":
			common.SetValue(&query, "headerType", s.Type)
			common.SetValue(&query, "seed", s.Path)
		case "tcp":
			common.SetValue(&query, "headerType", s.Type)
			common.SetValue(&query, "host", s.Host)
			common.SetValue(&query, "path", s.Path)
		case "grpc":
			common.SetValue(&query, "serviceName", s.Path)
		}
		if s.TLS != "none" {
			common.SetValue(&query, "sni", s.Host)
			common.SetValue(&query, "alpn", s.Alpn)
			common.SetValue(&query, "allowInsecure", common.BoolToString(s.AllowInsecure))
		}
		if s.TLS == "xtls" {
			common.SetValue(&query, "flow", s.Flow)
		}
		U := url.URL{
			Scheme:   "vless",
			User:     url.User(s.ID),
			Host:     s.Add + ":" + s.Port,
			RawQuery: query.Encode(),
			Fragment: s.Ps,
		}
		return U.String()
	case "vmess":
		s.V = "2"
		b, _ := jsoniter.Marshal(s)
		return "vmess://" + strings.TrimSuffix(base64.StdEncoding.EncodeToString(b), "=")
	}
	return ""
}

// ParseVlessURL parses a vless:// URL into V2Ray struct.
func ParseVlessURL(vless string) (data *V2Ray, err error) {
	u, err := url.Parse(vless)
	if err != nil {
		return nil, err
	}
	data = &V2Ray{
		Ps:            u.Fragment,
		Add:           u.Hostname(),
		Port:          u.Port(),
		ID:            u.User.String(),
		Net:           u.Query().Get("type"),
		Type:          u.Query().Get("headerType"),
		SNI:           u.Query().Get("sni"),
		Host:          u.Query().Get("host"),
		Path:          u.Query().Get("path"),
		TLS:           u.Query().Get("security"),
		Flow:          u.Query().Get("flow"),
		Alpn:          u.Query().Get("alpn"),
		AllowInsecure: common.StringToBool(u.Query().Get("allowInsecure")),
		Protocol:      "vless",
		Pbk:           u.Query().Get("pbk"),
		Sid:           u.Query().Get("sid"),
		Fp:            u.Query().Get("fp"),
	}
	if data.Net == "" {
		data.Net = "tcp"
	}
	if data.Net == "grpc" {
		data.Path = u.Query().Get("serviceName")
	}
	if data.Type == "" {
		data.Type = "none"
	}
	if data.TLS == "" {
		data.TLS = "none"
	}
	if data.Flow == "" {
		data.Flow = "xtls-rprx-direct"
	}
	return data, nil
}

// ParseVmessURL parses a vmess:// URL into V2Ray struct.
func ParseVmessURL(vmess string) (data *V2Ray, err error) {
	var info V2Ray
	raw, err := common.Base64StdDecode(vmess[8:])
	if err != nil {
		raw, err = common.Base64URLDecode(vmess[8:])
	}
	if err != nil {
		u, err := url.Parse(vmess)
		if err != nil {
			return nil, err
		}
		re := regexp.MustCompile(`.*:(.+)@(.+):(\d+)`)
		s := strings.Split(vmess[8:], "?")[0]
		s, err = common.Base64StdDecode(s)
		if err != nil {
			s, err = common.Base64URLDecode(s)
		}
		subMatch := re.FindStringSubmatch(s)
		if subMatch == nil {
			return nil, fmt.Errorf("%w: unrecognized vmess address", dialer.InvalidParameterErr)
		}
		q := u.Query()
		ps := q.Get("remarks")
		if ps == "" {
			ps = q.Get("remark")
		}
		obfs := q.Get("obfs")
		obfsParam := q.Get("obfsParam")
		path := q.Get("path")
		if obfs == "kcp" || obfs == "mkcp" {
			m := make(map[string]string)
			_ = jsoniter.Unmarshal([]byte(obfsParam), &m)
			path = m["seed"]
			obfsParam = ""
		}
		aid := q.Get("alterId")
		if aid == "" {
			aid = q.Get("aid")
		}
		info = V2Ray{
			ID:            subMatch[1],
			Add:           subMatch[2],
			Port:          subMatch[3],
			Ps:            ps,
			Host:          obfsParam,
			Path:          path,
			Net:           obfs,
			Aid:           aid,
			TLS:           map[string]string{"1": "tls"}[q.Get("tls")],
			AllowInsecure: common.StringToBool(q.Get("allowInsecure")),
		}
		if info.Net == "websocket" {
			info.Net = "ws"
		}
	} else {
		err = jsoniter.Unmarshal([]byte(raw), &info)
		if err != nil {
			return nil, err
		}
	}
	if strings.HasPrefix(info.Host, "/") && info.Path == "" {
		info.Path = info.Host
		info.Host = ""
	}
	if info.Aid == "" {
		info.Aid = "0"
	}
	info.Protocol = "vmess"
	return &info, nil
}

// ParseVmessPort parses the port string to int.
func ParseVmessPort(port string) (int, error) {
	return strconv.Atoi(port)
}
