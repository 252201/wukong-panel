package security

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPasswordHashAndVerify(t *testing.T) {
	hash, err := HashPassword("a-long-test-password")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(hash, "a-long-test-password") {
		t.Fatal("correct password was rejected")
	}
	if VerifyPassword(hash, "incorrect-password") {
		t.Fatal("incorrect password was accepted")
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
