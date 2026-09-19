package fleetprobe

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"sort"
	"time"

	"github.com/252201/wukong-panel/internal/model"
)

const (
	Magic                 = "WKP1"
	Version               = 1
	SampleCount           = 20
	SampleInterval        = 200 * time.Millisecond
	ResponseWait          = 1500 * time.Millisecond
	ProbePayloadSize      = 32
	maxHostIDLength       = 64
	macSize               = sha256.Size
	frameFixedSize        = 4 + 1 + 1 + 1 + 16 + 4 + 8 + ProbePayloadSize + macSize
	requestKind      byte = 1
	responseKind     byte = 2
)

var errInvalidFrame = errors.New("invalid fleet probe frame")

type frame struct {
	kind     byte
	hostID   string
	session  [16]byte
	sequence uint32
	sentAt   int64
	payload  [ProbePayloadSize]byte
}

type response struct {
	sequence uint32
	received time.Time
}

func encodeFrame(value frame, key []byte) ([]byte, error) {
	if len(value.hostID) == 0 || len(value.hostID) > maxHostIDLength {
		return nil, errInvalidFrame
	}
	if value.kind != requestKind && value.kind != responseKind {
		return nil, errInvalidFrame
	}
	result := make([]byte, frameFixedSize+len(value.hostID))
	copy(result[:4], Magic)
	result[4] = Version
	result[5] = value.kind
	result[6] = byte(len(value.hostID))
	offset := 7
	copy(result[offset:], value.hostID)
	offset += len(value.hostID)
	copy(result[offset:offset+len(value.session)], value.session[:])
	offset += len(value.session)
	binary.BigEndian.PutUint32(result[offset:offset+4], value.sequence)
	offset += 4
	binary.BigEndian.PutUint64(result[offset:offset+8], uint64(value.sentAt))
	offset += 8
	copy(result[offset:offset+ProbePayloadSize], value.payload[:])
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(result[:len(result)-macSize])
	copy(result[len(result)-macSize:], mac.Sum(nil))
	return result, nil
}

func decodeFrame(data, key []byte) (frame, error) {
	var value frame
	if len(data) < frameFixedSize || string(data[:4]) != Magic || data[4] != Version {
		return value, errInvalidFrame
	}
	hostIDLength := int(data[6])
	if hostIDLength == 0 || hostIDLength > maxHostIDLength || len(data) != frameFixedSize+hostIDLength {
		return value, errInvalidFrame
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data[:len(data)-macSize])
	if !hmac.Equal(mac.Sum(nil), data[len(data)-macSize:]) {
		return value, errInvalidFrame
	}
	value.kind = data[5]
	if value.kind != requestKind && value.kind != responseKind {
		return value, errInvalidFrame
	}
	offset := 7
	value.hostID = string(data[offset : offset+hostIDLength])
	offset += hostIDLength
	copy(value.session[:], data[offset:offset+len(value.session)])
	offset += len(value.session)
	value.sequence = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4
	value.sentAt = int64(binary.BigEndian.Uint64(data[offset : offset+8]))
	offset += 8
	copy(value.payload[:], data[offset:offset+ProbePayloadSize])
	return value, nil
}

func newRequest(hostID string, session [16]byte, sequence uint32) (frame, error) {
	value := frame{kind: requestKind, hostID: hostID, session: session, sequence: sequence, sentAt: time.Now().UnixNano()}
	if _, err := rand.Read(value.payload[:]); err != nil {
		return frame{}, err
	}
	return value, nil
}

func newSession() ([16]byte, error) {
	var session [16]byte
	_, err := rand.Read(session[:])
	return session, err
}

// Probe sends a fixed number of authenticated UDP datagrams without retrying
// them. A response is counted once by sequence number, so packet loss is
// calculated from the controlled sample rather than inferred from TCP.
func Probe(ctx context.Context, address, hostID, key string) (model.FleetNetworkHealth, error) {
	checkedAt := time.Now().UTC()
	result := model.FleetNetworkHealth{Status: "error", CheckedAt: checkedAt}
	if address == "" || hostID == "" || key == "" {
		result.Error = "fleet UDP probe is not configured"
		return result, errors.New(result.Error)
	}
	if len(hostID) > maxHostIDLength {
		result.Error = "fleet host ID is too long"
		return result, errors.New(result.Error)
	}
	remote, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		result.Error = fmt.Sprintf("resolve probe address: %v", err)
		return result, err
	}
	conn, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		result.Error = fmt.Sprintf("dial probe address: %v", err)
		return result, err
	}
	defer conn.Close()
	session, err := newSession()
	if err != nil {
		result.Error = "create probe session"
		return result, err
	}
	sentAt := make(map[uint32]time.Time, SampleCount)
	for sequence := 0; sequence < SampleCount; sequence++ {
		if err = ctx.Err(); err != nil {
			return result, err
		}
		value, frameErr := newRequest(hostID, session, uint32(sequence))
		if frameErr != nil {
			result.Error = "create probe packet"
			return result, frameErr
		}
		packet, frameErr := encodeFrame(value, []byte(key))
		if frameErr != nil {
			result.Error = "encode probe packet"
			return result, frameErr
		}
		if _, err = conn.Write(packet); err != nil {
			result.Error = fmt.Sprintf("send probe packet: %v", err)
			return result, err
		}
		sentAt[uint32(sequence)] = time.Now()
		result.PacketsSent++
		if sequence+1 < SampleCount {
			timer := time.NewTimer(SampleInterval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return result, ctx.Err()
			case <-timer.C:
			}
		}
	}

	deadline := time.Now().Add(ResponseWait)
	seen := make(map[uint32]bool, SampleCount)
	latencies := make([]time.Duration, 0, SampleCount)
	buffer := make([]byte, 512)
	for time.Now().Before(deadline) && result.PacketsReceived < SampleCount {
		if err = ctx.Err(); err != nil {
			return result, err
		}
		_ = conn.SetReadDeadline(deadline)
		n, _, readErr := conn.ReadFromUDP(buffer)
		if readErr != nil {
			if errors.Is(readErr, net.ErrClosed) || errors.Is(readErr, context.Canceled) {
				return result, readErr
			}
			if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
				break
			}
			continue
		}
		value, decodeErr := decodeFrame(buffer[:n], []byte(key))
		if decodeErr != nil || value.kind != responseKind || value.hostID != hostID || value.session != session || seen[value.sequence] {
			continue
		}
		sent, ok := sentAt[value.sequence]
		if !ok {
			continue
		}
		seen[value.sequence] = true
		result.PacketsReceived++
		latencies = append(latencies, time.Since(sent))
	}

	result.PacketLossPct = float64(result.PacketsSent-result.PacketsReceived) * 100 / float64(result.PacketsSent)
	if len(latencies) > 0 {
		sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
		median := latencies[len(latencies)/2]
		if len(latencies)%2 == 0 {
			median = (latencies[len(latencies)/2-1] + latencies[len(latencies)/2]) / 2
		}
		result.LatencyMS = int64(math.Round(float64(median) / float64(time.Millisecond)))
	}
	result.Status = "ok"
	return result, nil
}

type KeyLookup func(hostID string) ([]byte, bool)

// Serve handles only authenticated fixed-size echo packets. The controller
// never sends unsolicited traffic, which keeps the endpoint from becoming an
// open UDP reflector.
func Serve(ctx context.Context, conn *net.UDPConn, lookup KeyLookup) error {
	buffer := make([]byte, 2048)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		n, remote, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return err
		}
		value, key, keyOK := func() (frame, []byte, bool) {
			if n < 7 {
				return frame{}, nil, false
			}
			hostIDLength := int(buffer[6])
			if hostIDLength == 0 || hostIDLength > maxHostIDLength || n < 7+hostIDLength {
				return frame{}, nil, false
			}
			hostID := string(buffer[7 : 7+hostIDLength])
			key, ok := lookup(hostID)
			if !ok {
				return frame{}, nil, false
			}
			decoded, err := decodeFrame(buffer[:n], key)
			return decoded, key, err == nil
		}()
		if !keyOK || value.kind != requestKind {
			continue
		}
		value.kind = responseKind
		packet, err := encodeFrame(value, key)
		if err != nil {
			continue
		}
		_, _ = conn.WriteToUDP(packet, remote)
	}
}
