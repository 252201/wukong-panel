package security

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestPasswordHashAndVerify(t *testing.T) {
	hash, err := HashPassword("a-long-test-password")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(hash, "$m=19456,t=2,p=1$") {
		t.Fatalf("new password hash uses unexpected parameters: %s", hash)
	}
	if !VerifyPassword(hash, "a-long-test-password") {
		t.Fatal("correct password was rejected")
	}
	if VerifyPassword(hash, "incorrect-password") {
		t.Fatal("incorrect password was accepted")
	}
}

func TestPasswordVerificationAcceptsLegacyParameters(t *testing.T) {
	salt := []byte("legacy-salt-2026")
	want := argon2.IDKey([]byte("legacy-password"), salt, 2, 64*1024, 2, 32)
	encoded := fmt.Sprintf("argon2id$v=19$m=65536,t=2,p=2$%s$%s", base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(want))
	if !VerifyPassword(encoded, "legacy-password") {
		t.Fatal("legacy Argon2id password hash was rejected")
	}
}

func TestPasswordVerificationRejectsUnsafeParameters(t *testing.T) {
	for _, encoded := range []string{
		"argon2id$v=19$m=1048576,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"argon2id$v=19$m=19456,t=0,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"argon2id$v=19$m=19456,t=2,p=0$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"argon2id$v=16$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
	} {
		if VerifyPassword(encoded, "password") {
			t.Fatalf("unsafe password hash parameters were accepted: %s", encoded)
		}
	}
}

func TestPasswordDerivationReleasesHeapOnLowMemoryHost(t *testing.T) {
	originalRelease := releasePasswordHeap
	originalFree := freePasswordHeap
	t.Cleanup(func() {
		releasePasswordHeap = originalRelease
		freePasswordHeap = originalFree
	})
	releasePasswordHeap = true
	calls := 0
	freePasswordHeap = func() { calls++ }

	_ = derivePasswordKey([]byte("password"), []byte("sixteen-byte-salt"), passwordParams{memory: 8 * 1024, time: 1, threads: 1}, 16)
	if calls != 1 {
		t.Fatalf("low-memory heap release calls = %d, want 1", calls)
	}
}

func TestVaultRoundTripAndPermissions(t *testing.T) {
	dir := t.TempDir()
	vault, err := OpenVault(dir)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := vault.Encrypt("node-secret")
	if err != nil {
		t.Fatal(err)
	}
	plain, err := vault.Decrypt(encoded)
	if err != nil || plain != "node-secret" {
		t.Fatalf("round trip failed: %q %v", plain, err)
	}
	info, err := os.Stat(filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("master key mode = %o", info.Mode().Perm())
	}
}
