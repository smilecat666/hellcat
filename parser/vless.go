package parser

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ==================== Плоские структуры ====================

type VLESSConfig struct {
	ID          string
	Host        string
	Port        string
	Network     string
	Security    string
	SNI         string
	Flow        string
	PublicKey   string
	ShortID     string
	Fingerprint string
	Encryption  string
	Path        string
	HostHeader  string
	ServiceName string
	Authority   string
	Mode        string
	Extra       string
	Raw         string
}

type VMessConfig struct {
	Add         string
	Port        string
	ID          string
	AlterID     string
	Security    string
	Network     string
	Type        string
	Host        string
	Path        string
	TLS         string
	SNI         string
	ALPN        string
	Fingerprint string
	Raw         string
}

type ShadowsocksConfig struct {
	Method   string
	Password string
	Host     string
	Port     string
	Raw      string
}

type TrojanConfig struct {
	Password    string
	Host        string
	Port        string
	Network     string
	Security    string
	SNI         string
	ALPN        string
	Fingerprint string
	Encryption  string
	Path        string
	HostHeader  string
	ServiceName string
	Authority   string
	Mode        string
	Insecure    bool
	Raw         string
}

type Hysteria2Config struct {
	Host         string
	Port         string
	Password     string
	SNI          string
	Insecure     bool
	Obfs         string
	ObfsPassword string
	Raw          string
}

type TuicConfig struct {
	UUID              string
	Password          string
	Host              string
	Port              string
	SNI               string
	ALPN              string
	CongestionControl string
	UDPRelayMode      string
	AllowInsecure     bool
	Raw               string
}

// ==================== Вспомогательные функции ====================

func getParam(params url.Values, key, fallback string) string {
	if val, ok := params[key]; ok && len(val) > 0 && val[0] != "" {
		return val[0]
	}
	return fallback
}

func getBoolParam(params url.Values, key string, fallback bool) bool {
	val := getParam(params, key, "")
	switch strings.ToLower(val) {
	case "1", "true":
		return true
	case "0", "false":
		return false
	}
	return fallback
}

func getAlpnParam(params url.Values, key string) string {
	val := getParam(params, key, "")
	if val == "" {
		return ""
	}
	return val
}

func decodeBase64(s string) ([]byte, error) {
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, " ", "")
	s = strings.TrimSpace(s)

	if len(s)%4 != 0 {
		s += strings.Repeat("=", 4-len(s)%4)
	}

	if decoded, err := base64.StdEncoding.DecodeString(s); err == nil {
		return decoded, nil
	}
	if decoded, err := base64.URLEncoding.DecodeString(s); err == nil {
		return decoded, nil
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "=")); err == nil {
		return decoded, nil
	}
	return nil, fmt.Errorf("base64 decode failed")
}

// ==================== Диспетчер ====================

func Parse(rawURL string) (interface{}, error) {
	switch {
	case strings.HasPrefix(rawURL, "vless://"):
		return ParseVLESS(rawURL)
	case strings.HasPrefix(rawURL, "vmess://"):
		return ParseVMess(rawURL)
	case strings.HasPrefix(rawURL, "ss://"):
		return ParseShadowsocks(rawURL)
	case strings.HasPrefix(rawURL, "trojan://"):
		return ParseTrojan(rawURL)
	case strings.HasPrefix(rawURL, "hysteria2://"), strings.HasPrefix(rawURL, "hy2://"):
		return ParseHysteria2(rawURL)
	case strings.HasPrefix(rawURL, "tuic://"):
		return ParseTuic(rawURL)
	}
	return nil, fmt.Errorf("неизвестная схема протокола")
}

// ==================== VLESS ====================

func ParseVLESS(vlessURL string) (*VLESSConfig, error) {
	if !strings.HasPrefix(vlessURL, "vless://") {
		return nil, errors.New("невалидный VLESS URL")
	}

	u, err := url.Parse(vlessURL)
	if err != nil {
		return nil, fmt.Errorf("невалидный URL: %w", err)
	}

	if u.User == nil || u.User.Username() == "" {
		return nil, errors.New("UUID отсутствует")
	}

	params := u.Query()

	cfg := &VLESSConfig{
		ID:          u.User.Username(),
		Host:        u.Hostname(),
		Port:        u.Port(),
		Network:     getParam(params, "type", "tcp"),
		Security:    getParam(params, "security", "none"),
		SNI:         params.Get("sni"),
		Flow:        params.Get("flow"),
		PublicKey:   params.Get("pbk"),
		ShortID:     params.Get("sid"),
		Fingerprint: getParam(params, "fp", ""),
		Encryption:  getParam(params, "encryption", "none"),
		Path:        getParam(params, "path", "/"),
		HostHeader:  params.Get("host"),
		ServiceName: params.Get("serviceName"),
		Authority:   params.Get("authority"),
		Mode:        params.Get("mode"),
		Extra:       params.Get("extra"),
		Raw:         vlessURL,
	}

	if cfg.Port == "" {
		cfg.Port = "443"
	}
	if cfg.Fingerprint == "" && cfg.Security == "reality" {
		cfg.Fingerprint = "chrome"
	}
	if cfg.Network == "grpc" && cfg.ServiceName == "" {
		cfg.ServiceName = "GunService"
	}
	return cfg, nil
}

// ==================== VMess ====================

type vmessLink struct {
	V    string `json:"v"`
	Ps   string `json:"ps"`
	Add  string `json:"add"`
	Port string `json:"port"`
	Id   string `json:"id"`
	Aid  string `json:"aid"`
	Scy  string `json:"scy"`
	Net  string `json:"net"`
	Type string `json:"type"`
	Host string `json:"host"`
	Path string `json:"path"`
	Tls  string `json:"tls"`
	Sni  string `json:"sni"`
	Alpn string `json:"alpn"`
	Fp   string `json:"fp"`
}

func ParseVMess(rawURL string) (*VMessConfig, error) {
	if !strings.HasPrefix(rawURL, "vmess://") {
		return nil, errors.New("невалидный VMess URL")
	}
	b64 := strings.TrimPrefix(rawURL, "vmess://")

	decoded, err := decodeBase64(b64)
	if err != nil {
		return nil, fmt.Errorf("ошибка base64: %w", err)
	}

	var v vmessLink
	if err := json.Unmarshal(decoded, &v); err != nil {
		return nil, fmt.Errorf("ошибка JSON: %w", err)
	}

	cfg := &VMessConfig{
		Add:         v.Add,
		Port:        v.Port,
		ID:          v.Id,
		AlterID:     v.Aid,
		Security:    v.Scy,
		Network:     v.Net,
		Type:        v.Type,
		Host:        v.Host,
		Path:        v.Path,
		TLS:         v.Tls,
		SNI:         v.Sni,
		ALPN:        v.Alpn,
		Fingerprint: v.Fp,
		Raw:         rawURL,
	}

	if cfg.Port == "" {
		cfg.Port = "443"
	}
	if cfg.Network == "" {
		cfg.Network = "tcp"
	}
	if cfg.Security == "" {
		cfg.Security = "auto"
	}
	return cfg, nil
}

// ==================== Shadowsocks ====================

func ParseShadowsocks(rawURL string) (*ShadowsocksConfig, error) {
	if !strings.HasPrefix(rawURL, "ss://") {
		return nil, errors.New("невалидный Shadowsocks URL")
	}

	uriWithoutScheme := strings.TrimPrefix(rawURL, "ss://")
	parts := strings.SplitN(uriWithoutScheme, "#", 2)
	mainPart := parts[0]

	var method, password, host, portStr string
	var decoded []byte
	var err error

	if strings.Contains(mainPart, "@") {
		// SIP002
		sip002Parts := strings.SplitN(mainPart, "@", 2)
		if len(sip002Parts) != 2 {
			return nil, errors.New("неверный SIP002 формат")
		}
		decoded, err = decodeBase64(sip002Parts[0])
		if err != nil {
			return nil, fmt.Errorf("ошибка base64 SIP002: %w", err)
		}
		credParts := strings.SplitN(string(decoded), ":", 2)
		if len(credParts) != 2 {
			return nil, errors.New("неверные учётные данные SIP002")
		}
		method = credParts[0]
		password = credParts[1]
		host, portStr, err = net.SplitHostPort(sip002Parts[1])
		if err != nil {
			return nil, fmt.Errorf("неверный хост:порт SIP002: %w", err)
		}
	} else {
		// Legacy
		decoded, err = decodeBase64(mainPart)
		if err != nil {
			return nil, fmt.Errorf("ошибка base64 legacy: %w", err)
		}
		decodedStr := string(decoded)

		atIdx := strings.LastIndex(decodedStr, "@")
		if atIdx == -1 {
			return nil, errors.New("неверный legacy формат: нет @")
		}
		credPart := decodedStr[:atIdx]
		hostPortStr := decodedStr[atIdx+1:]

		credParts := strings.SplitN(credPart, ":", 2)
		if len(credParts) != 2 {
			return nil, errors.New("неверные учётные данные legacy")
		}
		method = credParts[0]
		password = credParts[1]

		host, portStr, err = net.SplitHostPort(hostPortStr)
		if err != nil {
			return nil, fmt.Errorf("неверный хост:порт legacy: %w", err)
		}
	}

	if _, err := fmt.Sscanf(portStr, "%d", new(int)); err != nil || portStr == "0" {
		return nil, fmt.Errorf("неверный порт: %s", portStr)
	}

	return &ShadowsocksConfig{
		Method:   method,
		Password: password,
		Host:     host,
		Port:     portStr,
		Raw:      rawURL,
	}, nil
}

// ==================== Trojan ====================

func ParseTrojan(rawURL string) (*TrojanConfig, error) {
	if !strings.HasPrefix(rawURL, "trojan://") {
		return nil, errors.New("невалидный Trojan URL")
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}

	password := u.User.Username()
	address := u.Hostname()
	port := u.Port()
	params := u.Query()

	if port == "" {
		port = "443"
	}

	cfg := &TrojanConfig{
		Password:    password,
		Host:        address,
		Port:        port,
		Network:     getParam(params, "type", "tcp"),
		Security:    getParam(params, "security", "tls"),
		SNI:         getParam(params, "sni", address),
		ALPN:        getAlpnParam(params, "alpn"),
		Fingerprint: getParam(params, "fp", ""),
		Encryption:  getParam(params, "encryption", ""),
		Path:        getParam(params, "path", "/"),
		HostHeader:  getParam(params, "host", ""),
		ServiceName: getParam(params, "serviceName", ""),
		Authority:   getParam(params, "authority", ""),
		Mode:        getParam(params, "mode", ""),
		Insecure:    getBoolParam(params, "allowInsecure", false) || getBoolParam(params, "insecure", false),
		Raw:         rawURL,
	}

	return cfg, nil
}

// ==================== Hysteria2 ====================

func ParseHysteria2(rawURL string) (*Hysteria2Config, error) {
	if !strings.HasPrefix(rawURL, "hysteria2://") && !strings.HasPrefix(rawURL, "hy2://") {
		return nil, errors.New("невалидный Hysteria2 URL")
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}

	password := u.User.String()
	if strings.Contains(password, ":") {
		password = strings.Split(password, ":")[0]
	}

	address := u.Hostname()
	port := u.Port()
	params := u.Query()

	if port == "" {
		port = "443"
	}

	return &Hysteria2Config{
		Host:         address,
		Port:         port,
		Password:     password,
		SNI:          getParam(params, "sni", ""),
		Insecure:     getBoolParam(params, "insecure", false),
		Obfs:         getParam(params, "obfs", ""),
		ObfsPassword: getParam(params, "obfs-password", ""),
		Raw:          rawURL,
	}, nil
}

// ==================== TUIC ====================

func ParseTuic(rawURL string) (*TuicConfig, error) {
	if !strings.HasPrefix(rawURL, "tuic://") {
		return nil, errors.New("невалидный TUIC URL")
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}

	uuid := u.User.Username()
	password, _ := u.User.Password()
	address := u.Hostname()
	port := u.Port()
	params := u.Query()

	if port == "" {
		port = "443"
	}

	return &TuicConfig{
		UUID:              uuid,
		Password:          password,
		Host:              address,
		Port:              port,
		SNI:               getParam(params, "sni", ""),
		ALPN:              getAlpnParam(params, "alpn"),
		CongestionControl: getParam(params, "congestion_control", ""),
		UDPRelayMode:      getParam(params, "udp_relay_mode", ""),
		AllowInsecure:     getBoolParam(params, "allow_insecure", false),
		Raw:               rawURL,
	}, nil
}

// ==================== Утилита Lines ====================

func Lines(input string) []string {
	var result []string
	for _, l := range strings.Split(input, "\n") {
		l = strings.TrimSpace(l)
		if l != "" {
			result = append(result, l)
		}
	}
	return result
}
