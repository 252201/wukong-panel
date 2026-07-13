package agent

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/252201/wukong-panel/internal/singboxconfig"
)

func TestGeneratedVLESSRealityCompletesFullRoundTrip(t *testing.T) {
	binary := os.Getenv("SING_BOX_TEST_BIN")
	if binary == "" {
		t.Skip("set SING_BOX_TEST_BIN to run the REALITY handshake integration test")
	}
	listener, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	request := baseRequest()
	request.Protocol = protocolVLESS
	request.Mode = "v4only"
	request.IPv4Bind = ""
	request.IPv6Bind = ""
	request.Domain = realityDefaultSNI
	credentials, err := generateProtocolCredentials(protocolVLESS, "")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := buildConfig(request, port, credentials, "", "", "1.13.14")
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "reality.json")
	if err = os.WriteFile(configPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if output, checkErr := exec.Command(binary, "check", "-c", configPath).CombinedOutput(); checkErr != nil {
		t.Fatalf("sing-box rejected generated REALITY config: %v\n%s", checkErr, output)
	}

	ctx, cancel := context.WithCancel(t.Context())
	server := exec.CommandContext(ctx, binary, "run", "-c", configPath)
	if err = server.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	defer func() {
		cancel()
		_ = server.Wait()
	}()

	deadline := time.Now().Add(3 * time.Second)
	for {
		connection, dialErr := net.DialTimeout("tcp6", net.JoinHostPort("::1", fmt.Sprint(port)), 100*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("generated REALITY server did not listen on port %d: %v", port, dialErr)
		}
		time.Sleep(25 * time.Millisecond)
	}

	result, err := singboxconfig.ProbeConfigInbound(t.Context(), binary, configPath, protocolVLESS, port)
	if err != nil {
		t.Fatalf("generated REALITY node failed its full round trip: %v", err)
	}
	if !result.OK || result.LatencyMS < 1 {
		t.Fatalf("unexpected REALITY probe result: %+v", result)
	}
}
