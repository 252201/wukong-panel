package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/252201/wukong-panel/internal/model"
)

// ChainedProxies returns all configured chained proxies ordered by created_at asc.
func (s *Store) ChainedProxies() ([]model.ChainedProxy, error) {
	rows, err := s.DB.Query(`
		SELECT id, name, entry_node_name, exit_node_name, enabled, created_at, updated_at
		FROM chained_proxies
		ORDER BY created_at ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []model.ChainedProxy
	for rows.Next() {
		var cp model.ChainedProxy
		var enabledInt int
		var createdAtUnix, updatedAtUnix int64

		err := rows.Scan(
			&cp.ID, &cp.Name, &cp.EntryNodeName, &cp.ExitNodeName,
			&enabledInt, &createdAtUnix, &updatedAtUnix,
		)
		if err != nil {
			return nil, err
		}

		cp.Enabled = enabledInt != 0
		if createdAtUnix > 0 {
			cp.CreatedAt = time.Unix(createdAtUnix, 0)
		}
		if updatedAtUnix > 0 {
			cp.UpdatedAt = time.Unix(updatedAtUnix, 0)
		}
		list = append(list, cp)
	}

	if list == nil {
		list = []model.ChainedProxy{}
	}
	return list, nil
}

// SaveChainedProxy inserts or updates a chained proxy.
func (s *Store) SaveChainedProxy(cp model.ChainedProxy) error {
	cp.ID = strings.TrimSpace(cp.ID)
	cp.EntryNodeName = strings.TrimSpace(cp.EntryNodeName)
	cp.ExitNodeName = strings.TrimSpace(cp.ExitNodeName)
	cp.Name = strings.TrimSpace(cp.Name)

	if cp.ID == "" {
		return errors.New("chained proxy id cannot be empty")
	}
	if cp.EntryNodeName == "" || cp.ExitNodeName == "" {
		return errors.New("both entry and exit node names are required")
	}
	if cp.EntryNodeName == cp.ExitNodeName {
		return errors.New("entry node and exit node cannot be the same")
	}
	if cp.Name == "" {
		cp.Name = "🔗 " + cp.EntryNodeName + " ➔ " + cp.ExitNodeName
	}

	now := time.Now()
	enabledInt := 0
	if cp.Enabled {
		enabledInt = 1
	}

	var existingCreatedAt int64
	err := s.DB.QueryRow(`SELECT created_at FROM chained_proxies WHERE id = ?`, cp.ID).Scan(&existingCreatedAt)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	if errors.Is(err, sql.ErrNoRows) {
		_, err = s.DB.Exec(`
			INSERT INTO chained_proxies (id, name, entry_node_name, exit_node_name, enabled, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`, cp.ID, cp.Name, cp.EntryNodeName, cp.ExitNodeName, enabledInt, now.Unix(), now.Unix())
	} else {
		_, err = s.DB.Exec(`
			UPDATE chained_proxies
			SET name = ?, entry_node_name = ?, exit_node_name = ?, enabled = ?, updated_at = ?
			WHERE id = ?
		`, cp.Name, cp.EntryNodeName, cp.ExitNodeName, enabledInt, now.Unix(), cp.ID)
	}
	return err
}

// DeleteChainedProxy deletes a chained proxy by ID.
func (s *Store) DeleteChainedProxy(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return errors.New("chained proxy id cannot be empty")
	}
	_, err := s.DB.Exec(`DELETE FROM chained_proxies WHERE id = ?`, id)
	return err
}

// ToggleChainedProxy toggles the enabled state of a chained proxy.
func (s *Store) ToggleChainedProxy(id string, enabled bool) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return errors.New("chained proxy id cannot be empty")
	}
	enabledInt := 0
	if enabled {
		enabledInt = 1
	}
	res, err := s.DB.Exec(`UPDATE chained_proxies SET enabled = ?, updated_at = ? WHERE id = ?`, enabledInt, time.Now().Unix(), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("chained proxy not found")
	}
	return nil
}
