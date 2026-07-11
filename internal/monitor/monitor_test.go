package monitor

import "testing"

func TestEndpointPacketUsesIPv4PacketLength(t *testing.T) {
	var pending int64
	if _, _, _, _, ok := endpointPacket("1700000000.1 IP (tos 0x0, ttl 64, id 1, offset 0, flags [DF], proto UDP (17), length 1280)", &pending); ok {
		t.Fatal("metadata line must not produce a packet")
	}
	port, host, clientPort, size, ok := endpointPacket("    192.0.2.10.45080 > 198.51.100.20.54321: UDP, length 1252", &pending)
	if !ok || port != 45080 || host != "198.51.100.20" || clientPort != "54321" || size != 1280 {
		t.Fatalf("unexpected IPv4 packet: %d %q %q %d %v", port, host, clientPort, size, ok)
	}
}

func TestEndpointPacketIncludesIPv6Header(t *testing.T) {
	var pending int64
	endpointPacket("1700000000.2 IP6 (flowlabel 0x1, hlim 64, next-header UDP (17) payload length: 1240)", &pending)
	port, host, clientPort, size, ok := endpointPacket("    2001:db8::1.45081 > 2001:db8::2.54322: UDP, length 1232", &pending)
	if !ok || port != 45081 || host != "2001:db8::2" || clientPort != "54322" || size != 1280 {
		t.Fatalf("unexpected IPv6 packet: %d %q %q %d %v", port, host, clientPort, size, ok)
	}
}

func TestEndpointPacketRejectsLineWithoutLengthMetadata(t *testing.T) {
	var pending int64
	if _, _, _, _, ok := endpointPacket("192.0.2.10.45080 > 198.51.100.20.54321: UDP, length 100", &pending); ok {
		t.Fatal("endpoint without IP packet length metadata must be ignored")
	}
}
