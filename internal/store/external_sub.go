package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/252201/wukong-panel/internal/model"
)

func (s *Store) ExternalSubscriptions() ([]model.ExternalSubscription, error) {
	rows, err := s.DB.Query(`
		SELECT id, name, url, proxy_url, raw_content, user_agent, enabled, auto_sync, sync_interval_hours,
		       last_sync_at, last_error, upload_bytes, download_bytes, total_bytes,
		       expires_at, nodes_json, selected_node_ids_json, created_at, updated_at
		FROM external_subscriptions
		ORDER BY created_at ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var subs []model.ExternalSubscription
	for rows.Next() {
		var sub model.ExternalSubscription
		var enabledInt, autoSyncInt int
		var lastSyncAtUnix, createdAtUnix, updatedAtUnix int64
		var nodesJSON, selectedNodesJSON string

		err := rows.Scan(
			&sub.ID, &sub.Name, &sub.URL, &sub.ProxyURL, &sub.RawContent, &sub.UserAgent, &enabledInt, &autoSyncInt,
			&sub.SyncIntervalHours, &lastSyncAtUnix, &sub.LastError, &sub.UploadBytes,
			&sub.DownloadBytes, &sub.TotalBytes, &sub.ExpiresAt, &nodesJSON,
			&selectedNodesJSON, &createdAtUnix, &updatedAtUnix,
		)
		if err != nil {
			return nil, err
		}

		sub.Enabled = enabledInt != 0
		sub.AutoSync = autoSyncInt != 0
		if lastSyncAtUnix > 0 {
			sub.LastSyncAt = time.Unix(lastSyncAtUnix, 0)
		}
		if createdAtUnix > 0 {
			sub.CreatedAt = time.Unix(createdAtUnix, 0)
		}
		if updatedAtUnix > 0 {
			sub.UpdatedAt = time.Unix(updatedAtUnix, 0)
		}
		_ = json.Unmarshal([]byte(nodesJSON), &sub.Nodes)
		_ = json.Unmarshal([]byte(selectedNodesJSON), &sub.SelectedNodeIDs)
		if sub.Nodes == nil {
			sub.Nodes = []model.Node{}
		}
		if sub.SelectedNodeIDs == nil {
			sub.SelectedNodeIDs = []string{}
		}
		if len(sub.SelectedNodeIDs) > 0 && len(sub.Nodes) > 0 {
			validMap := make(map[string]bool, len(sub.Nodes))
			for _, n := range sub.Nodes {
				validMap[n.ID] = true
			}
			filtered := make([]string, 0, len(sub.SelectedNodeIDs))
			for _, sid := range sub.SelectedNodeIDs {
				if validMap[sid] {
					filtered = append(filtered, sid)
				}
			}
			sub.SelectedNodeIDs = filtered
		}

		subs = append(subs, sub)
	}

	if subs == nil {
		subs = []model.ExternalSubscription{}
	}
	return subs, rows.Err()
}

func (s *Store) ExternalSubscription(id string) (model.ExternalSubscription, error) {
	var sub model.ExternalSubscription
	var enabledInt, autoSyncInt int
	var lastSyncAtUnix, createdAtUnix, updatedAtUnix int64
	var nodesJSON, selectedNodesJSON string

	err := s.DB.QueryRow(`
		SELECT id, name, url, proxy_url, raw_content, user_agent, enabled, auto_sync, sync_interval_hours,
		       last_sync_at, last_error, upload_bytes, download_bytes, total_bytes,
		       expires_at, nodes_json, selected_node_ids_json, created_at, updated_at
		FROM external_subscriptions
		WHERE id = ?
	`, id).Scan(
		&sub.ID, &sub.Name, &sub.URL, &sub.ProxyURL, &sub.RawContent, &sub.UserAgent, &enabledInt, &autoSyncInt,
		&sub.SyncIntervalHours, &lastSyncAtUnix, &sub.LastError, &sub.UploadBytes,
		&sub.DownloadBytes, &sub.TotalBytes, &sub.ExpiresAt, &nodesJSON,
		&selectedNodesJSON, &createdAtUnix, &updatedAtUnix,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return sub, errors.New("external subscription not found")
	}
	if err != nil {
		return sub, err
	}

	sub.Enabled = enabledInt != 0
	sub.AutoSync = autoSyncInt != 0
	if lastSyncAtUnix > 0 {
		sub.LastSyncAt = time.Unix(lastSyncAtUnix, 0)
	}
	if createdAtUnix > 0 {
		sub.CreatedAt = time.Unix(createdAtUnix, 0)
	}
	if updatedAtUnix > 0 {
		sub.UpdatedAt = time.Unix(updatedAtUnix, 0)
	}
	_ = json.Unmarshal([]byte(nodesJSON), &sub.Nodes)
	_ = json.Unmarshal([]byte(selectedNodesJSON), &sub.SelectedNodeIDs)
	if sub.Nodes == nil {
		sub.Nodes = []model.Node{}
	}
	if sub.SelectedNodeIDs == nil {
		sub.SelectedNodeIDs = []string{}
	}
	if len(sub.SelectedNodeIDs) > 0 && len(sub.Nodes) > 0 {
		validMap := make(map[string]bool, len(sub.Nodes))
		for _, n := range sub.Nodes {
			validMap[n.ID] = true
		}
		filtered := make([]string, 0, len(sub.SelectedNodeIDs))
		for _, sid := range sub.SelectedNodeIDs {
			if validMap[sid] {
				filtered = append(filtered, sid)
			}
		}
		sub.SelectedNodeIDs = filtered
	}

	return sub, nil
}

func (s *Store) SaveExternalSubscription(sub model.ExternalSubscription) error {
	now := time.Now()
	if sub.CreatedAt.IsZero() {
		sub.CreatedAt = now
	}
	sub.UpdatedAt = now

	if sub.SyncIntervalHours <= 0 {
		sub.SyncIntervalHours = 12
	}

	enabledInt := 0
	if sub.Enabled {
		enabledInt = 1
	}
	autoSyncInt := 0
	if sub.AutoSync {
		autoSyncInt = 1
	}

	if sub.Nodes == nil {
		sub.Nodes = []model.Node{}
	}
	if sub.SelectedNodeIDs == nil {
		sub.SelectedNodeIDs = []string{}
	}

	nodesJSON, err := json.Marshal(sub.Nodes)
	if err != nil || string(nodesJSON) == "null" {
		nodesJSON = []byte("[]")
	}
	selectedNodesJSON, err := json.Marshal(sub.SelectedNodeIDs)
	if err != nil || string(selectedNodesJSON) == "null" {
		selectedNodesJSON = []byte("[]")
	}

	lastSyncUnix := int64(0)
	if !sub.LastSyncAt.IsZero() {
		lastSyncUnix = sub.LastSyncAt.Unix()
	}

	_, err = s.DB.Exec(`
		INSERT INTO external_subscriptions (
			id, name, url, proxy_url, raw_content, user_agent, enabled, auto_sync, sync_interval_hours,
			last_sync_at, last_error, upload_bytes, download_bytes, total_bytes,
			expires_at, nodes_json, selected_node_ids_json, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name = excluded.name,
			url = excluded.url,
			proxy_url = excluded.proxy_url,
			raw_content = excluded.raw_content,
			user_agent = excluded.user_agent,
			enabled = excluded.enabled,
			auto_sync = excluded.auto_sync,
			sync_interval_hours = excluded.sync_interval_hours,
			last_sync_at = excluded.last_sync_at,
			last_error = excluded.last_error,
			upload_bytes = excluded.upload_bytes,
			download_bytes = excluded.download_bytes,
			total_bytes = excluded.total_bytes,
			expires_at = excluded.expires_at,
			nodes_json = excluded.nodes_json,
			selected_node_ids_json = excluded.selected_node_ids_json,
			updated_at = excluded.updated_at
	`,
		sub.ID, sub.Name, sub.URL, sub.ProxyURL, sub.RawContent, sub.UserAgent, enabledInt, autoSyncInt,
		sub.SyncIntervalHours, lastSyncUnix, sub.LastError, sub.UploadBytes,
		sub.DownloadBytes, sub.TotalBytes, sub.ExpiresAt, string(nodesJSON),
		string(selectedNodesJSON), sub.CreatedAt.Unix(), sub.UpdatedAt.Unix(),
	)
	return err
}

func (s *Store) DeleteExternalSubscription(id string) error {
	_, err := s.DB.Exec(`DELETE FROM external_subscriptions WHERE id = ?`, id)
	return err
}

func (s *Store) UpdateExternalSubscriptionSyncResult(id string, upload, download, total int64, expiresAt string, nodes []model.Node, lastErr error) error {
	now := time.Now()
	errStr := ""
	if lastErr != nil {
		errStr = lastErr.Error()
	}

	// If there was an error and no nodes were returned, preserve existing nodes, traffic quotas, and expiry
	if lastErr != nil && len(nodes) == 0 {
		_, err := s.DB.Exec(`
			UPDATE external_subscriptions SET
				last_error = ?,
				updated_at = ?
			WHERE id = ?
		`, errStr, now.Unix(), id)
		return err
	}

	if nodes == nil {
		nodes = []model.Node{}
	}
	nodesJSON, err := json.Marshal(nodes)
	if err != nil || string(nodesJSON) == "null" {
		nodesJSON = []byte("[]")
	}

	// Prune obsolete node IDs from selected_node_ids_json if nodes were updated
	var currentSelectedJSON string
	_ = s.DB.QueryRow(`SELECT selected_node_ids_json FROM external_subscriptions WHERE id = ?`, id).Scan(&currentSelectedJSON)
	var currentSelected []string
	if currentSelectedJSON != "" {
		_ = json.Unmarshal([]byte(currentSelectedJSON), &currentSelected)
	}
	newSelectedJSON := currentSelectedJSON
	if len(currentSelected) > 0 && len(nodes) > 0 {
		validMap := make(map[string]bool, len(nodes))
		for _, n := range nodes {
			validMap[n.ID] = true
		}
		var pruned []string
		for _, sid := range currentSelected {
			if validMap[sid] {
				pruned = append(pruned, sid)
			}
		}
		if len(pruned) != len(currentSelected) {
			marshaled, _ := json.Marshal(pruned)
			newSelectedJSON = string(marshaled)
		}
	}
	if newSelectedJSON == "" {
		newSelectedJSON = "[]"
	}

	_, err = s.DB.Exec(`
		UPDATE external_subscriptions SET
			upload_bytes = ?,
			download_bytes = ?,
			total_bytes = ?,
			expires_at = ?,
			nodes_json = ?,
			selected_node_ids_json = ?,
			last_sync_at = ?,
			last_error = ?,
			updated_at = ?
		WHERE id = ?
	`, upload, download, total, expiresAt, string(nodesJSON), newSelectedJSON, now.Unix(), errStr, now.Unix(), id)
	return err
}
