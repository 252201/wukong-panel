package fleetprobe

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestFrameRejectsTampering(t *testing.T) {
	session, err := newSession()
	if err != nil {
		t.Fatal(err)
	}
	value, err := newRequest("host-a", session, 3)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := encodeFrame(value, []byte("probe-key"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = decodeFrame(packet, []byte("wrong-key")); err == nil {
		t.Fatal("frame authenticated with the wrong key")
	}
	packet[len(packet)-1] ^= 1
	if _, err = decodeFrame(packet, []byte("probe-key")); err == nil {
		t.Fatal("tampered frame was accepted")
	}
}

func TestProbeCountsMissingResponsesWithoutRetry(t *testing.T) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	key := []byte("probe-key")
	serverDone := make(chan struct{})
	serverErrors := make(chan error, 1)
	go func() {
		defer close(serverDone)
		buffer := make([]byte, 512)
		for received := 0; received < SampleCount; received++ {
			if err := server.SetReadDeadline(time.Now().Add(8 * time.Second)); err != nil {
				serverErrors <- err
				return
			}
			n, remote, readErr := server.ReadFromUDP(buffer)
			if readErr != nil {
				serverErrors <- readErr
				return
			}
			value, decodeErr := decodeFrame(buffer[:n], key)
			if decodeErr != nil || value.kind != requestKind {
				serverErrors <- errors.New("invalid request received")
				return
			}
			if value.sequence%5 == 0 {
				continue
			}
			value.kind = responseKind
			packet, encodeErr := encodeFrame(value, key)
			if encodeErr != nil {
				serverErrors <- encodeErr
				return
			}
			if _, writeErr := server.WriteToUDP(packet, remote); writeErr != nil {
				serverErrors <- writeErr
				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	result, err := Probe(ctx, server.LocalAddr().String(), "host-a", string(key))
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "ok" || result.PacketsSent != SampleCount || result.PacketsReceived != SampleCount-4 {
		t.Fatalf("unexpected probe result: %+v", result)
	}
	if result.PacketLossPct != 20 {
		t.Fatalf("packet loss=%v, want 20", result.PacketLossPct)
	}
	select {
	case err := <-serverErrors:
		t.Fatal(err)
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("probe server did not receive the complete sample")
	}
}
