package web

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/252201/wukong-panel/internal/fleetprobe"
	"github.com/252201/wukong-panel/internal/security"
)

func (s *Server) startFleetProbe(ctx context.Context) error {
	listen := strings.TrimSpace(s.cfg.FleetProbeListen)
	if listen == "" {
		return nil
	}
	address, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		return fmt.Errorf("invalid UDP probe listen address: %w", err)
	}
	conn, err := net.ListenUDP("udp", address)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", listen, err)
	}
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()
	go func() {
		if err := fleetprobe.Serve(ctx, conn, s.lookupFleetProbeKey); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("fleet UDP probe: %v", err)
		}
	}()
	log.Printf("fleet UDP probe listening on %s", conn.LocalAddr().String())
	return nil
}

func (s *Server) lookupFleetProbeKey(hostID string) ([]byte, bool) {
	s.fleetProbeMu.RLock()
	cached, ok := s.fleetProbeKeys[hostID]
	if ok {
		key := append([]byte(nil), cached...)
		s.fleetProbeMu.RUnlock()
		return key, true
	}
	s.fleetProbeMu.RUnlock()

	ciphertext, err := s.store.FleetProbeSecret(hostID)
	if err != nil || s.fleetVaultErr != nil {
		return nil, false
	}
	plain, err := s.fleetVault.Decrypt(ciphertext)
	if err != nil || plain == "" {
		return nil, false
	}
	key := []byte(plain)
	s.fleetProbeMu.Lock()
	s.fleetProbeKeys[hostID] = append([]byte(nil), key...)
	s.fleetProbeMu.Unlock()
	return key, true
}

func (s *Server) ensureFleetProbeKey(hostID string) (string, error) {
	s.fleetProbeMu.Lock()
	defer s.fleetProbeMu.Unlock()
	if cached, ok := s.fleetProbeKeys[hostID]; ok {
		return string(cached), nil
	}
	if ciphertext, err := s.store.FleetProbeSecret(hostID); err == nil {
		if s.fleetVaultErr != nil {
			return "", s.fleetVaultErr
		}
		plain, decryptErr := s.fleetVault.Decrypt(ciphertext)
		if decryptErr != nil {
			return "", decryptErr
		}
		s.fleetProbeKeys[hostID] = []byte(plain)
		return plain, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	if s.fleetVaultErr != nil {
		return "", s.fleetVaultErr
	}
	key, err := security.RandomToken(32)
	if err != nil {
		return "", err
	}
	ciphertext, err := s.fleetVault.Encrypt(key)
	if err != nil {
		return "", err
	}
	if err = s.store.SetFleetProbeSecret(hostID, ciphertext); err != nil {
		return "", err
	}
	s.fleetProbeKeys[hostID] = []byte(key)
	return key, nil
}

func (s *Server) forgetFleetProbeKey(hostID string) {
	s.fleetProbeMu.Lock()
	delete(s.fleetProbeKeys, hostID)
	s.fleetProbeMu.Unlock()
}
