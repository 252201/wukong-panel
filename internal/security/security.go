package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	passwordMemoryKiB uint32 = 19 * 1024
	maxPasswordMemory uint64 = 64 * 1024
	passwordTime      uint32 = 2
	passwordThreads   uint8  = 1
	passwordKeyLength uint32 = 32

	lowMemoryThresholdBytes uint64 = 512 * 1024 * 1024
)

type passwordParams struct {
	memory  uint32
	time    uint32
	threads uint8
}

var (
	releasePasswordHeap = detectLowMemoryHost()
	freePasswordHeap    = debug.FreeOSMemory
)

func RandomToken(bytes int) (string, error) {
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func HashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	params := passwordParams{memory: passwordMemoryKiB, time: passwordTime, threads: passwordThreads}
	hash := derivePasswordKey([]byte(password), salt, params, passwordKeyLength)
	return fmt.Sprintf("argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", params.memory, params.time, params.threads, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(hash)), nil
}

func VerifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "argon2id" || parts[1] != "v=19" {
		return false
	}
	params, ok := parsePasswordParams(parts[2])
	if !ok {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[3])
	want, err2 := base64.RawStdEncoding.DecodeString(parts[4])
	if err1 != nil || err2 != nil || len(salt) < 8 || len(salt) > 64 || len(want) < 16 || len(want) > 64 {
		return false
	}
	got := derivePasswordKey([]byte(password), salt, params, uint32(len(want)))
	matched := subtle.ConstantTimeCompare(got, want) == 1
	for index := range got {
		got[index] = 0
	}
	return matched
}

func parsePasswordParams(encoded string) (passwordParams, bool) {
	values := strings.Split(encoded, ",")
	if len(values) != 3 {
		return passwordParams{}, false
	}
	parsed := make(map[string]uint64, len(values))
	for _, value := range values {
		pair := strings.SplitN(value, "=", 2)
		if len(pair) != 2 || pair[0] == "" {
			return passwordParams{}, false
		}
		number, err := strconv.ParseUint(pair[1], 10, 32)
		if err != nil {
			return passwordParams{}, false
		}
		if _, duplicate := parsed[pair[0]]; duplicate {
			return passwordParams{}, false
		}
		parsed[pair[0]] = number
	}
	memory, hasMemory := parsed["m"]
	timeCost, hasTime := parsed["t"]
	threads, hasThreads := parsed["p"]
	if !hasMemory || !hasTime || !hasThreads || memory < 8*1024 || memory > maxPasswordMemory || timeCost < 1 || timeCost > 10 || threads < 1 || threads > 8 {
		return passwordParams{}, false
	}
	return passwordParams{memory: uint32(memory), time: uint32(timeCost), threads: uint8(threads)}, true
}

func derivePasswordKey(password, salt []byte, params passwordParams, keyLength uint32) []byte {
	if releasePasswordHeap {
		defer freePasswordHeap()
	}
	return argon2.IDKey(password, salt, params.time, params.memory, params.threads, keyLength)
}

func detectLowMemoryHost() bool {
	limit := memTotalBytes()
	for _, path := range []string{"/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"} {
		if candidate := byteLimit(path); candidate > 0 && (limit == 0 || candidate < limit) {
			limit = candidate
		}
	}
	return limit > 0 && limit <= lowMemoryThresholdBytes
}

func memTotalBytes() uint64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "MemTotal:" {
			value, err := strconv.ParseUint(fields[1], 10, 64)
			if err == nil {
				return value * 1024
			}
		}
	}
	return 0
}

func byteLimit(path string) uint64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	value := strings.TrimSpace(string(data))
	if value == "" || value == "max" {
		return 0
	}
	limit, err := strconv.ParseUint(value, 10, 64)
	if err != nil || limit >= 1<<60 {
		return 0
	}
	return limit
}

type Vault struct{ aead cipher.AEAD }

func OpenVault(dataDir string) (*Vault, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	keyPath := filepath.Join(dataDir, "master.key")
	key, err := os.ReadFile(keyPath)
	if errors.Is(err, os.ErrNotExist) {
		key = make([]byte, 32)
		if _, err = rand.Read(key); err != nil {
			return nil, err
		}
		if err = os.WriteFile(keyPath, key, 0o600); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, errors.New("invalid master key length")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Vault{aead: aead}, nil
}

func (v *Vault) Encrypt(plaintext string) (string, error) {
	nonce := make([]byte, v.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := v.aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.RawStdEncoding.EncodeToString(sealed), nil
}

func (v *Vault) Decrypt(encoded string) (string, error) {
	sealed, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil || len(sealed) < v.aead.NonceSize() {
		return "", errors.New("invalid ciphertext")
	}
	nonce, payload := sealed[:v.aead.NonceSize()], sealed[v.aead.NonceSize():]
	plain, err := v.aead.Open(nil, nonce, payload, nil)
	return string(plain), err
}
