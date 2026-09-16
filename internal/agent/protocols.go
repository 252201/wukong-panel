package agent

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strings"

	"github.com/252201/wukong-panel/internal/model"
	"github.com/252201/wukong-panel/internal/security"
)

const (
	protocolHysteria2     = "hysteria2"
	protocolVLESS         = "vless"
	protocolVLESSWSTunnel = "vless-ws-tunnel"
	protocolShadowsocks   = "shadowsocks"
	protocolTUIC          = "tuic"
	protocolTrojan        = "trojan"
	protocolAnyTLS        = "anytls"
	shadowsocks2022       = "2022-blake3-aes-128-gcm"
	realityDefaultSNI     = "www.cloudflare.com"
)

var supportedProtocols = map[string]bool{
	protocolHysteria2: true, protocolVLESS: true, protocolVLESSWSTunnel: true, protocolShadowsocks: true, protocolTUIC: true, protocolTrojan: true, protocolAnyTLS: true,
}

type protocolCredentials struct {
	Password          string `json:"password,omitempty"`
	UUID              string `json:"uuid,omitempty"`
	Method            string `json:"method,omitempty"`
	RealityPublicKey  string `json:"realityPublicKey,omitempty"`
	RealityShortID    string `json:"realityShortId,omitempty"`
	RealityPrivateKey string `json:"-"`
	WebSocketPath     string `json:"webSocketPath,omitempty"`
	TunnelToken       string `json:"tunnelToken,omitempty"`
}

func normalizeProtocol(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "hy2", "hysteria-2", protocolHysteria2:
		return protocolHysteria2
	case "vless-reality", "reality", protocolVLESS:
		return protocolVLESS
	case "vless-ws", "vless-websocket", "argo", "cloudflare-tunnel", protocolVLESSWSTunnel:
		return protocolVLESSWSTunnel
	case "ss", "ss2022", "shadowsocks-2022", protocolShadowsocks:
		return protocolShadowsocks
	case protocolTUIC:
		return protocolTUIC
	case protocolTrojan:
		return protocolTrojan
	case "any-tls", protocolAnyTLS:
		return protocolAnyTLS
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func protocolUsesCertificate(protocol string) bool {
	switch normalizeProtocol(protocol) {
	case protocolHysteria2, protocolTUIC, protocolTrojan, protocolAnyTLS:
		return true
	default:
		return false
	}
}

func protocolUsesUDP(protocol string) bool {
	switch normalizeProtocol(protocol) {
	case protocolHysteria2, protocolTUIC, protocolShadowsocks:
		return true
	default:
		return false
	}
}

func protocolUsesTCP(protocol string) bool {
	switch normalizeProtocol(protocol) {
	case protocolVLESS, protocolVLESSWSTunnel, protocolShadowsocks, protocolTrojan, protocolAnyTLS:
		return true
	default:
		return false
	}
}

func protocolTagPrefix(protocol string) string {
	switch normalizeProtocol(protocol) {
	case protocolHysteria2:
		return "hy2"
	case protocolShadowsocks:
		return "ss"
	default:
		return normalizeProtocol(protocol)
	}
}

func generateProtocolCredentials(protocol, explicit string) (protocolCredentials, error) {
	protocol = normalizeProtocol(protocol)
	credentials := protocolCredentials{}
	switch protocol {
	case protocolHysteria2, protocolTrojan, protocolAnyTLS:
		credentials.Password = strings.TrimSpace(explicit)
		if credentials.Password == "" {
			value, err := security.RandomToken(24)
			if err != nil {
				return credentials, err
			}
			credentials.Password = value
		}
	case protocolTUIC:
		var err error
		credentials.UUID, err = newUUID()
		if err != nil {
			return credentials, err
		}
		credentials.Password = strings.TrimSpace(explicit)
		if credentials.Password == "" {
			value, err := security.RandomToken(24)
			if err != nil {
				return credentials, err
			}
			credentials.Password = value
		}
	case protocolShadowsocks:
		credentials.Method = shadowsocks2022
		credentials.Password = strings.TrimSpace(explicit)
		if credentials.Password == "" {
			key := make([]byte, 16)
			if _, err := rand.Read(key); err != nil {
				return credentials, err
			}
			credentials.Password = base64.StdEncoding.EncodeToString(key)
		}
		decoded, err := base64.StdEncoding.DecodeString(credentials.Password)
		if err != nil || len(decoded) != 16 {
			return credentials, errors.New("Shadowsocks 2022 AES-128-GCM password must be a base64-encoded 16-byte key")
		}
	case protocolVLESS:
		credentials.UUID = strings.TrimSpace(explicit)
		if credentials.UUID == "" {
			var err error
			credentials.UUID, err = newUUID()
			if err != nil {
				return credentials, err
			}
		} else if !validUUID(credentials.UUID) {
			return credentials, errors.New("VLESS credential must be a valid UUID")
		}
		privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return credentials, err
		}
		credentials.RealityPrivateKey = base64.RawURLEncoding.EncodeToString(privateKey.Bytes())
		credentials.RealityPublicKey = base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes())
		shortID := make([]byte, 8)
		if _, err = rand.Read(shortID); err != nil {
			return credentials, err
		}
		credentials.RealityShortID = hex.EncodeToString(shortID)
	case protocolVLESSWSTunnel:
		credentials.UUID = strings.TrimSpace(explicit)
		if credentials.UUID == "" {
			var err error
			credentials.UUID, err = newUUID()
			if err != nil {
				return credentials, err
			}
		} else if !validUUID(credentials.UUID) {
			return credentials, errors.New("VLESS credential must be a valid UUID")
		}
	default:
		return credentials, fmt.Errorf("unsupported protocol %q", protocol)
	}
	return credentials, nil
}

func encodeProtocolCredentials(credentials protocolCredentials) (string, error) {
	data, err := json.Marshal(credentials)
	return string(data), err
}

func decodeProtocolCredentials(protocol, value string) (protocolCredentials, error) {
	var credentials protocolCredentials
	if strings.HasPrefix(strings.TrimSpace(value), "{") {
		if err := json.Unmarshal([]byte(value), &credentials); err != nil {
			return credentials, err
		}
	} else {
		credentials.Password = value
	}
	if normalizeProtocol(protocol) == protocolShadowsocks && credentials.Method == "" {
		credentials.Method = shadowsocks2022
	}
	return credentials, nil
}

func credentialsFromInbound(protocol string, inbound map[string]any) (protocolCredentials, error) {
	protocol = normalizeProtocol(protocol)
	credentials := protocolCredentials{}
	firstUser := func() map[string]any {
		users, _ := inbound["users"].([]any)
		if len(users) == 0 {
			return nil
		}
		user, _ := users[0].(map[string]any)
		return user
	}
	switch protocol {
	case protocolHysteria2, protocolTrojan, protocolAnyTLS:
		credentials.Password = stringValue(firstUser()["password"])
	case protocolTUIC:
		user := firstUser()
		credentials.UUID = stringValue(user["uuid"])
		credentials.Password = stringValue(user["password"])
	case protocolShadowsocks:
		credentials.Method = stringValue(inbound["method"])
		credentials.Password = stringValue(inbound["password"])
		if credentials.Method == "" || credentials.Password == "" {
			return credentials, errors.New("multi-user or relay Shadowsocks inbound requires manual import")
		}
	case protocolVLESS:
		user := firstUser()
		credentials.UUID = stringValue(user["uuid"])
		tlsConfig, _ := inbound["tls"].(map[string]any)
		reality, _ := tlsConfig["reality"].(map[string]any)
		credentials.RealityPrivateKey = stringValue(reality["private_key"])
		if ids, ok := reality["short_id"].([]any); ok && len(ids) > 0 {
			credentials.RealityShortID = stringValue(ids[0])
		}
		credentials.RealityPublicKey = realityPublicKey(credentials.RealityPrivateKey)
	case protocolVLESSWSTunnel:
		user := firstUser()
		credentials.UUID = stringValue(user["uuid"])
		transport, _ := inbound["transport"].(map[string]any)
		if stringValue(transport["type"]) != "ws" {
			return credentials, errors.New("VLESS WebSocket inbound has no WebSocket transport")
		}
		credentials.WebSocketPath = stringValue(transport["path"])
	default:
		return credentials, fmt.Errorf("unsupported protocol %q", protocol)
	}
	if credentials.Password == "" && credentials.UUID == "" {
		return credentials, errors.New("inbound has no importable credentials")
	}
	return credentials, nil
}

// credentialsForManagedEdit restores credential material that intentionally is
// not duplicated in the database. A REALITY private key lives only in the
// root-owned sing-box configuration, so an edit must inherit it from the
// existing inbound before rebuilding the configuration.
func credentialsForManagedEdit(protocol string, stored protocolCredentials, inbound map[string]any) (protocolCredentials, error) {
	if normalizeProtocol(protocol) != protocolVLESS {
		return stored, nil
	}
	current, err := credentialsFromInbound(protocol, inbound)
	if err != nil {
		return stored, err
	}
	publicKey := realityPublicKey(current.RealityPrivateKey)
	if publicKey == "" {
		return stored, errors.New("existing VLESS REALITY inbound has an invalid private key")
	}
	if stored.UUID != "" && stored.UUID != current.UUID {
		return stored, errors.New("stored VLESS UUID does not match the running configuration")
	}
	if stored.RealityPublicKey != "" && stored.RealityPublicKey != publicKey {
		return stored, errors.New("stored REALITY public key does not match the running configuration")
	}
	if stored.RealityShortID != "" && stored.RealityShortID != current.RealityShortID {
		return stored, errors.New("stored REALITY short ID does not match the running configuration")
	}
	stored.UUID = current.UUID
	stored.RealityPrivateKey = current.RealityPrivateKey
	stored.RealityPublicKey = publicKey
	stored.RealityShortID = current.RealityShortID
	return stored, nil
}

func buildProtocolInbound(request model.NodeCreateRequest, port int, credentials protocolCredentials, certPath, keyPath string) (map[string]any, error) {
	protocol := normalizeProtocol(request.Protocol)
	listen := protocolInboundListenAddress(protocol, request.Mode, request.IPv4Bind, request.IPv6Bind)
	return buildProtocolInboundWithListen(request, port, credentials, certPath, keyPath, listen)
}

// buildProtocolInboundWithContext is used by the managed-node runtime. A pure
// IPv6 inbound must listen on the IPv6 address clients actually dial, which is
// derived from Server and verified against the host's local addresses. The
// IPv6Bind field is intentionally reserved for outbound source selection.
func buildProtocolInboundWithContext(ctx context.Context, request model.NodeCreateRequest, port int, credentials protocolCredentials, certPath, keyPath string) (map[string]any, error) {
	protocol := normalizeProtocol(request.Protocol)
	listen, err := protocolInboundListenAddressForEndpoint(ctx, protocol, request.Mode, request.Server)
	if err != nil {
		return nil, err
	}
	return buildProtocolInboundWithListen(request, port, credentials, certPath, keyPath, listen)
}

func buildProtocolInboundWithListen(request model.NodeCreateRequest, port int, credentials protocolCredentials, certPath, keyPath, listen string) (map[string]any, error) {
	protocol := normalizeProtocol(request.Protocol)
	tag := protocolTagPrefix(protocol) + "-" + strings.TrimSpace(request.Name) + "-in"
	inboundType := protocol
	if protocol == protocolVLESSWSTunnel {
		inboundType = protocolVLESS
	}
	inbound := map[string]any{"type": inboundType, "tag": tag, "listen": listen, "listen_port": port}
	switch protocol {
	case protocolHysteria2:
		inbound["users"] = []any{map[string]any{"name": "wukong", "password": credentials.Password}}
		inbound["ignore_client_bandwidth"] = true
		inbound["tls"] = certificateTLS(certPath, keyPath, true)
	case protocolVLESS:
		inbound["users"] = []any{map[string]any{"name": "wukong", "uuid": credentials.UUID, "flow": "xtls-rprx-vision"}}
		inbound["tls"] = map[string]any{
			"enabled":     true,
			"server_name": request.Domain,
			"reality": map[string]any{
				"enabled":             true,
				"handshake":           map[string]any{"server": request.Domain, "server_port": 443},
				"private_key":         credentials.RealityPrivateKey,
				"short_id":            []any{credentials.RealityShortID},
				"max_time_difference": "1m",
			},
		}
	case protocolVLESSWSTunnel:
		inbound["users"] = []any{map[string]any{"name": "wukong", "uuid": credentials.UUID}}
		inbound["transport"] = map[string]any{"type": "ws", "path": credentials.WebSocketPath}
	case protocolShadowsocks:
		inbound["method"] = credentials.Method
		inbound["password"] = credentials.Password
	case protocolTUIC:
		inbound["users"] = []any{map[string]any{"name": "wukong", "uuid": credentials.UUID, "password": credentials.Password}}
		inbound["congestion_control"] = "bbr"
		inbound["zero_rtt_handshake"] = false
		inbound["tls"] = certificateTLS(certPath, keyPath, true)
	case protocolTrojan:
		inbound["users"] = []any{map[string]any{"name": "wukong", "password": credentials.Password}}
		inbound["tls"] = certificateTLS(certPath, keyPath, false)
	case protocolAnyTLS:
		inbound["users"] = []any{map[string]any{"name": "wukong", "password": credentials.Password}}
		inbound["tls"] = certificateTLS(certPath, keyPath, false)
	default:
		return nil, fmt.Errorf("unsupported protocol %q", protocol)
	}
	return inbound, nil
}

// protocolInboundListenAddressForEndpoint returns the address used by the
// server-side inbound socket. For v4only and dual-stack modes the wildcard
// addresses are intentional. For v6only, using IPv6Bind is incorrect because
// it controls the source address of outbound connections, not where clients
// connect. Resolve the public endpoint and select the matching local address
// instead, failing closed when the endpoint cannot be served locally.
func protocolInboundListenAddressForEndpoint(ctx context.Context, protocol, mode, server string) (string, error) {
	base := protocolInboundListenAddress(protocol, mode, "", "")
	if base != "::" || strings.ToLower(strings.TrimSpace(mode)) != "v6only" {
		return base, nil
	}

	return resolveLocalIPv6Endpoint(ctx, server)
}

func resolveLocalIPv6Endpoint(ctx context.Context, server string) (string, error) {
	server = strings.TrimSpace(server)
	if server == "" {
		return "", errors.New("pure IPv6 inbound requires a server endpoint")
	}

	local, err := localGlobalIPv6Addresses()
	if err != nil {
		return "", fmt.Errorf("discover local IPv6 addresses: %w", err)
	}

	if literal := endpointIPv6Literal(server); literal != nil {
		if selected := selectLocalIPv6Address([]net.IP{literal}, local); selected != "" {
			return selected, nil
		}
		return "", fmt.Errorf("server IPv6 %q is not assigned to this host", server)
	}

	host := endpointHost(server)
	if host == "" {
		return "", fmt.Errorf("invalid server endpoint %q", server)
	}
	resolved, err := net.DefaultResolver.LookupIP(ctx, "ip6", host)
	if err != nil {
		return "", fmt.Errorf("resolve IPv6 endpoint %q: %w", host, err)
	}
	if selected := selectLocalIPv6Address(resolved, local); selected != "" {
		return selected, nil
	}
	return "", fmt.Errorf("IPv6 endpoint %q does not resolve to a local IPv6 address", host)
}

func localGlobalIPv6Addresses() ([]net.IP, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	addresses := make([]net.IP, 0)
	seen := make(map[string]struct{})
	for _, iface := range interfaces {
		ifaceAddresses, err := iface.Addrs()
		if err != nil {
			return nil, fmt.Errorf("list addresses for %s: %w", iface.Name, err)
		}
		for _, address := range ifaceAddresses {
			ip := addressIP(address)
			if ip == nil || ip.To4() != nil || !ip.IsGlobalUnicast() {
				continue
			}
			key := ip.String()
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			addresses = append(addresses, ip)
		}
	}
	return addresses, nil
}

func addressIP(address net.Addr) net.IP {
	switch value := address.(type) {
	case *net.IPNet:
		return value.IP
	case *net.IPAddr:
		return value.IP
	default:
		valueText := strings.TrimSpace(address.String())
		if host, _, err := net.SplitHostPort(valueText); err == nil {
			valueText = host
		} else if slash := strings.IndexByte(valueText, '/'); slash >= 0 {
			valueText = valueText[:slash]
		}
		return net.ParseIP(strings.Trim(valueText, "[]"))
	}
}

func endpointIPv6Literal(value string) net.IP {
	host := endpointHost(value)
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() != nil || !ip.IsGlobalUnicast() {
		return nil
	}
	return ip
}

func endpointHost(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "[") {
		if end := strings.IndexByte(value, ']'); end > 1 {
			return value[1:end]
		}
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		return host
	}
	return strings.TrimSuffix(value, ".")
}

// selectLocalIPv6Address returns a stable address from the intersection of
// resolved endpoint addresses and local addresses. Keeping this logic pure
// makes the address-family decision independently testable.
func selectLocalIPv6Address(resolved, local []net.IP) string {
	localSet := make(map[string]struct{}, len(local))
	for _, ip := range local {
		if ip == nil || ip.To4() != nil || !ip.IsGlobalUnicast() {
			continue
		}
		localSet[ip.String()] = struct{}{}
	}

	candidates := make([]string, 0, len(resolved))
	seen := make(map[string]struct{})
	for _, ip := range resolved {
		if ip == nil || ip.To4() != nil || !ip.IsGlobalUnicast() {
			continue
		}
		key := ip.String()
		if _, ok := localSet[key]; !ok {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		candidates = append(candidates, key)
	}
	if len(candidates) == 0 {
		return ""
	}
	sort.Strings(candidates)
	return candidates[0]
}

// protocolInboundListenAddress keeps the listener family aligned with the
// node's addressing mode. prefer_v6 intentionally remains dual-stack so
// clients can choose the best transport family; v4only is an IPv4 listener;
// v6only binds the selected IPv6 address, which also prevents Linux from
// accepting IPv4-mapped connections on an unspecified :: listener. WebSocket
// tunnel origins are always kept on loopback.
func protocolInboundListenAddress(protocol, mode, ipv4Bind, ipv6Bind string) string {
	if normalizeProtocol(protocol) == protocolVLESSWSTunnel {
		return "127.0.0.1"
	}
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "v4only":
		return "0.0.0.0"
	case "v6only":
		if address := net.ParseIP(strings.TrimSpace(ipv6Bind)); address != nil && address.To4() == nil {
			return address.String()
		}
	}
	return "::"
}

func certificateTLS(certPath, keyPath string, h3 bool) map[string]any {
	tlsConfig := map[string]any{"enabled": true, "certificate_path": certPath, "key_path": keyPath}
	if h3 {
		tlsConfig["alpn"] = []string{"h3"}
	}
	return tlsConfig
}

func inboundDomain(protocol string, inbound map[string]any) string {
	tlsConfig, _ := inbound["tls"].(map[string]any)
	if normalizeProtocol(protocol) == protocolVLESS {
		reality, _ := tlsConfig["reality"].(map[string]any)
		handshake, _ := reality["handshake"].(map[string]any)
		return stringValue(handshake["server"])
	}
	certificatePath := stringValue(tlsConfig["certificate_path"])
	if certificate, err := loadCertificate(certificatePath); err == nil {
		if len(certificate.DNSNames) > 0 {
			return certificate.DNSNames[0]
		}
		if len(certificate.IPAddresses) > 0 {
			return certificate.IPAddresses[0].String()
		}
		if value := strings.TrimSpace(certificate.Subject.CommonName); value != "" && (net.ParseIP(value) != nil || strings.Contains(value, ".")) {
			return value
		}
	}
	filename := filepath.Base(strings.TrimSpace(certificatePath))
	base := strings.TrimSuffix(strings.TrimSuffix(filename, "-fullchain.cer"), ".cer")
	if base != filename {
		return base
	}
	return ""
}

func buildShareURI(node model.Node, credentials protocolCredentials, insecure bool) (string, error) {
	return buildShareURIWithServer(node, credentials, insecure, "")
}

// buildShareURIWithServer keeps the public client endpoint separate from the
// TLS SNI. Pure IPv6 nodes may need to publish a literal address even when
// their certificate and SNI continue to use the configured domain name.
func buildShareURIWithServer(node model.Node, credentials protocolCredentials, insecure bool, serverOverride string) (string, error) {
	server := strings.TrimSpace(serverOverride)
	if server == "" {
		server = strings.TrimSpace(node.Server)
	}
	if server == "" {
		server = strings.TrimSpace(node.Domain)
	}
	if server == "" {
		server = "127.0.0.1"
	}
	host := hostForURI(server)
	name := urlEncode(node.Name)
	sni := urlEncode(node.Domain)
	switch normalizeProtocol(node.Protocol) {
	case protocolHysteria2:
		query := "sni=" + sni
		if insecure {
			query += "&insecure=1"
		}
		return fmt.Sprintf("hysteria2://%s@%s:%d/?%s#%s", urlEncode(credentials.Password), host, node.ListenPort, query, name), nil
	case protocolVLESS:
		if credentials.UUID == "" || credentials.RealityPublicKey == "" || credentials.RealityShortID == "" {
			return "", errors.New("VLESS REALITY credentials are incomplete")
		}
		query := fmt.Sprintf("encryption=none&flow=xtls-rprx-vision&security=reality&sni=%s&fp=chrome&pbk=%s&sid=%s&type=tcp", sni, urlEncode(credentials.RealityPublicKey), urlEncode(credentials.RealityShortID))
		return fmt.Sprintf("vless://%s@%s:%d?%s#%s", urlEncode(credentials.UUID), host, node.ListenPort, query, name), nil
	case protocolVLESSWSTunnel:
		if credentials.UUID == "" || credentials.WebSocketPath == "" {
			return "", errors.New("VLESS WebSocket Tunnel credentials are incomplete")
		}
		publishedServer := strings.TrimSpace(node.Server)
		if publishedServer == "" {
			publishedServer = strings.TrimSpace(node.Domain)
		}
		dialServer := strings.TrimSpace(node.PreferredServer)
		if dialServer == "" {
			dialServer = publishedServer
		}
		query := fmt.Sprintf("encryption=none&security=tls&sni=%s&fp=chrome&type=ws&host=%s&path=%s", urlEncode(publishedServer), urlEncode(publishedServer), urlEncode(credentials.WebSocketPath))
		return fmt.Sprintf("vless://%s@%s:443?%s#%s", urlEncode(credentials.UUID), hostForURI(dialServer), query, name), nil
	case protocolShadowsocks:
		userinfo := base64.RawURLEncoding.EncodeToString([]byte(credentials.Method + ":" + credentials.Password))
		return fmt.Sprintf("ss://%s@%s:%d#%s", userinfo, host, node.ListenPort, name), nil
	case protocolTUIC:
		query := fmt.Sprintf("congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=%s", sni)
		if insecure {
			query += "&allow_insecure=1"
		}
		return fmt.Sprintf("tuic://%s:%s@%s:%d?%s#%s", urlEncode(credentials.UUID), urlEncode(credentials.Password), host, node.ListenPort, query, name), nil
	case protocolTrojan:
		query := fmt.Sprintf("security=tls&sni=%s&type=tcp", sni)
		if insecure {
			query += "&allowInsecure=1"
		}
		return fmt.Sprintf("trojan://%s@%s:%d?%s#%s", urlEncode(credentials.Password), host, node.ListenPort, query, name), nil
	case protocolAnyTLS:
		query := "sni=" + sni
		if insecure {
			query += "&insecure=1"
		}
		return fmt.Sprintf("anytls://%s@%s:%d/?%s#%s", urlEncode(credentials.Password), host, node.ListenPort, query, name), nil
	default:
		return "", fmt.Errorf("unsupported protocol %q", node.Protocol)
	}
}

func realityPublicKey(privateValue string) string {
	privateBytes, err := base64.RawURLEncoding.DecodeString(privateValue)
	if err != nil {
		return ""
	}
	privateKey, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes())
}

func newUUID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}

func validUUID(value string) bool {
	compact := strings.ReplaceAll(strings.TrimSpace(value), "-", "")
	if len(compact) != 32 {
		return false
	}
	_, err := hex.DecodeString(compact)
	return err == nil
}
