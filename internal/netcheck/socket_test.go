package netcheck

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type socketReply struct {
	packet []byte
	sender net.Addr
}

type fakeICMPSocket struct {
	t             *testing.T
	datagram      bool
	drop          bool
	dropSequences map[int]bool
	invalid       bool
	closed        bool
	writes        int
	writeErr      error
	queue         []socketReply
}

func (s *fakeICMPSocket) Close() error { s.closed = true; return nil }
func (s *fakeICMPSocket) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4zero, Port: 4242}
}
func (s *fakeICMPSocket) SetReadDeadline(time.Time) error { return nil }
func (s *fakeICMPSocket) WriteTo(packet []byte, destination net.Addr) (int, error) {
	s.t.Helper()
	if s.writeErr != nil {
		return 0, s.writeErr
	}
	message, err := icmp.ParseMessage(1, packet)
	if err != nil {
		s.t.Fatal(err)
	}
	echo, ok := message.Body.(*icmp.Echo)
	if !ok || message.Type != ipv4.ICMPTypeEcho || echo.Seq != s.writes {
		s.t.Fatalf("unexpected request: %+v", message)
	}
	s.writes++
	var sender net.Addr
	if s.datagram {
		address, ok := destination.(*net.UDPAddr)
		if !ok || echo.ID != 4242 {
			s.t.Fatalf("datagram destination=%v Echo ID=%d", destination, echo.ID)
		}
		sender = &net.UDPAddr{IP: address.IP}
	} else {
		address, ok := destination.(*net.IPAddr)
		if !ok {
			s.t.Fatalf("raw destination=%v", destination)
		}
		sender = address
	}
	if s.drop || s.dropSequences[echo.Seq] {
		return len(packet), nil
	}
	addReply := func(body icmp.Echo, peer net.Addr) {
		response, err := (&icmp.Message{Type: ipv4.ICMPTypeEchoReply, Body: &body}).Marshal(nil)
		if err != nil {
			s.t.Fatal(err)
		}
		s.queue = append(s.queue, socketReply{response, peer})
	}
	if s.invalid {
		wrongID := *echo
		wrongID.ID++
		addReply(wrongID, sender)
		wrongSequence := *echo
		wrongSequence.Seq++
		addReply(wrongSequence, sender)
		wrongToken := *echo
		wrongToken.Data = []byte("foreign payload")
		addReply(wrongToken, sender)
		addReply(*echo, &net.UDPAddr{IP: net.ParseIP("192.0.2.99")})
		s.queue = append(s.queue, socketReply{[]byte{0}, sender})
	}
	addReply(*echo, sender)
	return len(packet), nil
}
func (s *fakeICMPSocket) ReadFrom(buffer []byte) (int, net.Addr, error) {
	if len(s.queue) == 0 {
		return 0, nil, os.ErrDeadlineExceeded
	}
	reply := s.queue[0]
	s.queue = s.queue[1:]
	return copy(buffer, reply.packet), reply.sender, nil
}

func TestProbeRawAndDatagramReplies(t *testing.T) {
	for _, datagram := range []bool{false, true} {
		name := "raw"
		if datagram {
			name = "datagram after NET_RAW denial"
		}
		t.Run(name, func(t *testing.T) {
			socket := &fakeICMPSocket{t: t, datagram: datagram, invalid: true}
			var networks []string
			result := probeTargetWithListener(context.Background(), net.ParseIP("127.0.0.1"), func(network, address string) (icmpSocket, error) {
				networks = append(networks, network)
				if address != "0.0.0.0" {
					t.Fatalf("bind address=%s", address)
				}
				if datagram && network == "ip4:icmp" {
					return nil, syscall.EPERM
				}
				return socket, nil
			})
			wantNetworks := "ip4:icmp"
			if datagram {
				wantNetworks += ",udp4"
			}
			if strings.Join(networks, ",") != wantNetworks || !socket.closed || len(socket.queue) != 0 || result.err != nil || result.sent != 5 || result.received != 5 || len(result.roundTrips) != 5 {
				t.Fatalf("networks=%v closed=%v unread replies=%d result=%+v", networks, socket.closed, len(socket.queue), result)
			}
		})
	}
}

func TestProbeBothSocketModesDenied(t *testing.T) {
	targets, labels, _ := parseTargets("127.0.0.1")
	health := measure(context.Background(), targets, labels, func(ctx context.Context, ip net.IP) targetResult {
		return probeTargetWithListener(ctx, ip, func(network, _ string) (icmpSocket, error) {
			if network == "ip4:icmp" {
				return nil, syscall.EPERM
			}
			return nil, syscall.EACCES
		})
	})
	if health.Status != "error" || health.PacketsSent != 0 || health.PacketLossPct != 0 || !strings.Contains(health.Error, syscall.EPERM.Error()) || !strings.Contains(health.Error, syscall.EACCES.Error()) {
		t.Fatalf("socket denial should be unavailable, not loss: %+v", health)
	}
}

func TestProbeDatagramTimeoutAndSendFailure(t *testing.T) {
	for _, writeErr := range []error{nil, errors.New("send denied")} {
		name := "unanswered packets"
		if writeErr != nil {
			name = "failed send"
		}
		t.Run(name, func(t *testing.T) {
			socket := &fakeICMPSocket{t: t, datagram: true, drop: true, writeErr: writeErr}
			targets, labels, _ := parseTargets("127.0.0.1")
			health := measure(context.Background(), targets, labels, func(ctx context.Context, ip net.IP) targetResult {
				return probeTargetWithListener(ctx, ip, func(network, _ string) (icmpSocket, error) {
					if network == "ip4:icmp" {
						return nil, syscall.EPERM
					}
					return socket, nil
				})
			})
			if writeErr == nil {
				if health.Status != "ok" || health.PacketsSent != 5 || health.PacketsReceived != 0 || health.PacketLossPct != 100 {
					t.Fatalf("actual unanswered packets should count as loss: %+v", health)
				}
			} else if health.Status != "error" || health.PacketsSent != 0 || health.PacketLossPct != 0 {
				t.Fatalf("failed sends should be unavailable: %+v", health)
			}
			if !socket.closed {
				t.Fatal("socket leaked")
			}
		})
	}
}

func TestProbeDatagramPartialLoss(t *testing.T) {
	socket := &fakeICMPSocket{t: t, datagram: true, dropSequences: map[int]bool{2: true}}
	targets, labels, _ := parseTargets("127.0.0.1")
	health := measure(context.Background(), targets, labels, func(ctx context.Context, ip net.IP) targetResult {
		return probeTargetWithListener(ctx, ip, func(network, _ string) (icmpSocket, error) {
			if network == "ip4:icmp" {
				return nil, syscall.EPERM
			}
			return socket, nil
		})
	})
	if health.Status != "ok" || health.PacketsSent != 5 || health.PacketsReceived != 4 || health.PacketLossPct != 20 || len(health.TargetResults) != 1 || health.TargetResults[0].PacketsReceived != 4 {
		t.Fatalf("datagram loss counters changed: %+v", health)
	}
}
