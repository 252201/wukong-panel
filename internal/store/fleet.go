package store

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/252201/wukong-panel/internal/model"
	"github.com/252201/wukong-panel/internal/security"
)

func (s *Store) CreateFleetEnrollmentToken(token string, expires time.Time) error {
	_, err := s.DB.Exec(`INSERT INTO fleet_enrollment_tokens(token_hash,expires_at,created_at) VALUES(?,?,?)`, security.HashToken(token), expires.Unix(), time.Now().Unix())
	return err
}

func (s *Store) ConsumeFleetEnrollmentToken(token string, host model.FleetHost, agentToken string) error {
	now := time.Now().Unix()
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`UPDATE fleet_enrollment_tokens SET used_at=? WHERE token_hash=? AND used_at=0 AND expires_at>=?`, now, security.HashToken(token), now)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count != 1 {
		return errors.New("接入令牌无效、已使用或已过期")
	}
	capabilities, _ := json.Marshal(host.Capabilities)
	_, err = tx.Exec(`INSERT INTO fleet_hosts(id,name,hostname,os,arch,service_manager,panel_version,sing_box_version,protocol_version,capabilities_json,token_hash,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		host.ID, host.Name, host.Hostname, host.OS, host.Arch, host.ServiceManager, host.PanelVersion, host.SingBoxVersion, host.ProtocolVersion, string(capabilities), security.HashToken(agentToken), now, now)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) AuthenticateFleetHost(hostID, token string) bool {
	var hash string
	if err := s.DB.QueryRow(`SELECT token_hash FROM fleet_hosts WHERE id=? AND archived_at=0`, hostID).Scan(&hash); err != nil {
		return false
	}
	got := []byte(security.HashToken(token))
	want := []byte(hash)
	return len(got) == len(want) && subtle.ConstantTimeCompare(got, want) == 1
}

func (s *Store) SaveFleetHeartbeat(ctx context.Context, hostID string, heartbeat model.FleetHeartbeat) error {
	if !heartbeat.Snapshot.Full {
		var existingRaw string
		if err := s.DB.QueryRowContext(ctx, `SELECT snapshot_json FROM fleet_hosts WHERE id=? AND archived_at=0`, hostID).Scan(&existingRaw); err == nil {
			var existing model.FleetSnapshot
			if json.Unmarshal([]byte(existingRaw), &existing) == nil {
				existing.Overview = heartbeat.Snapshot.Overview
				states := make(map[string]model.Node, len(heartbeat.Snapshot.Nodes))
				for _, node := range heartbeat.Snapshot.Nodes {
					states[node.ID] = node
				}
				for index := range existing.Nodes {
					if state, ok := states[existing.Nodes[index].ID]; ok {
						existing.Nodes[index].Status = state.Status
						existing.Nodes[index].ProbeStatus = state.ProbeStatus
						existing.Nodes[index].ProbeLatencyMS = state.ProbeLatencyMS
						existing.Nodes[index].ProbeExitIP = state.ProbeExitIP
						existing.Nodes[index].ProbeError = state.ProbeError
						existing.Nodes[index].ProbeCheckedAt = state.ProbeCheckedAt
					}
				}
				heartbeat.Snapshot = existing
			}
		}
	}
	snapshot, err := json.Marshal(heartbeat.Snapshot)
	if err != nil {
		return err
	}
	capabilities, _ := json.Marshal(heartbeat.Capabilities)
	now := time.Now().Unix()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE fleet_hosts SET panel_version=?,sing_box_version=?,protocol_version=?,capabilities_json=?,snapshot_json=?,last_seen_at=?,updated_at=? WHERE id=? AND archived_at=0`, heartbeat.PanelVersion, heartbeat.SingBoxVersion, heartbeat.ProtocolVersion, string(capabilities), string(snapshot), now, now, hostID)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count != 1 {
		return sql.ErrNoRows
	}
	metric, _ := json.Marshal(heartbeat.Snapshot.Overview.Now)
	if heartbeat.Snapshot.Overview.Now.Timestamp > 0 {
		_, err = tx.ExecContext(ctx, `INSERT INTO fleet_metrics(host_id,ts,metric_json) VALUES(?,?,?) ON CONFLICT(host_id,ts) DO UPDATE SET metric_json=excluded.metric_json`, hostID, heartbeat.Snapshot.Overview.Now.Timestamp, string(metric))
		if err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM fleet_metrics WHERE ts<?`, time.Now().Add(-90*24*time.Hour).Unix()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) FleetHosts(includeArchived bool) ([]model.FleetHost, error) {
	query := `SELECT id,name,hostname,os,arch,service_manager,panel_version,sing_box_version,protocol_version,capabilities_json,snapshot_json,last_seen_at,archived_at,created_at FROM fleet_hosts`
	if !includeArchived {
		query += ` WHERE archived_at=0`
	}
	query += ` ORDER BY name,id`
	rows, err := s.DB.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []model.FleetHost{}
	for rows.Next() {
		var host model.FleetHost
		var capabilities, snapshot string
		var lastSeen, archived, created int64
		if err = rows.Scan(&host.ID, &host.Name, &host.Hostname, &host.OS, &host.Arch, &host.ServiceManager, &host.PanelVersion, &host.SingBoxVersion, &host.ProtocolVersion, &capabilities, &snapshot, &lastSeen, &archived, &created); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(capabilities), &host.Capabilities)
		_ = json.Unmarshal([]byte(snapshot), &host.Snapshot)
		host.LastSeenAt = time.Unix(lastSeen, 0)
		host.CreatedAt = time.Unix(created, 0)
		host.Archived = archived > 0
		host.Online = !host.Archived && lastSeen > 0 && time.Since(host.LastSeenAt) <= 30*time.Second
		host.Compatible = host.ProtocolVersion == model.FleetProtocolVersion
		result = append(result, host)
	}
	return result, rows.Err()
}

func (s *Store) FleetHost(id string) (model.FleetHost, error) {
	hosts, err := s.FleetHosts(true)
	if err != nil {
		return model.FleetHost{}, err
	}
	for _, host := range hosts {
		if host.ID == id {
			return host, nil
		}
	}
	return model.FleetHost{}, sql.ErrNoRows
}

func (s *Store) FleetMetrics(hostID string, limit int) ([]model.Metric, error) {
	if limit < 1 || limit > 1000 {
		limit = 80
	}
	rows, err := s.DB.Query(`SELECT metric_json FROM fleet_metrics WHERE host_id=? ORDER BY ts DESC LIMIT ?`, hostID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	reversed := []model.Metric{}
	for rows.Next() {
		var raw string
		var metric model.Metric
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		if json.Unmarshal([]byte(raw), &metric) == nil {
			reversed = append(reversed, metric)
		}
	}
	result := make([]model.Metric, len(reversed))
	for index := range reversed {
		result[len(reversed)-1-index] = reversed[index]
	}
	return result, rows.Err()
}

func (s *Store) RenameFleetHost(id, name string) error {
	if name == "" {
		return errors.New("主机名称不能为空")
	}
	_, err := s.DB.Exec(`UPDATE fleet_hosts SET name=?,updated_at=? WHERE id=? AND archived_at=0`, name, time.Now().Unix(), id)
	return err
}

func (s *Store) ArchiveFleetHost(id string) error {
	now := time.Now().Unix()
	_, err := s.DB.Exec(`UPDATE fleet_hosts SET archived_at=?,token_hash=?,updated_at=? WHERE id=? AND archived_at=0`, now, "revoked:"+id+":"+time.Now().String(), now, id)
	return err
}

func (s *Store) PurgeFleetHost(id string) error {
	_, err := s.DB.Exec(`DELETE FROM fleet_hosts WHERE id=? AND archived_at>0`, id)
	return err
}

func (s *Store) PurgeExpiredFleetArchives(before time.Time) error {
	_, err := s.DB.Exec(`DELETE FROM fleet_hosts WHERE archived_at>0 AND archived_at<?`, before.Unix())
	return err
}

func (s *Store) QueueFleetCommand(hostID, jobID, kind, actor, payloadCipher string, expires time.Time) (model.FleetCommand, error) {
	id, err := security.RandomToken(12)
	if err != nil {
		return model.FleetCommand{}, err
	}
	now := time.Now()
	_, err = s.DB.Exec(`INSERT INTO fleet_commands(id,host_id,job_id,kind,actor,payload_cipher,status,expires_at,created_at,updated_at) VALUES(?,?,?,?,?,?,'queued',?,?,?)`, id, hostID, jobID, kind, actor, payloadCipher, expires.Unix(), now.Unix(), now.Unix())
	return model.FleetCommand{ID: id, Kind: kind, Actor: actor, ExpiresAt: expires}, err
}

type FleetCommandRecord struct {
	Command              model.FleetCommand
	PayloadCipher, JobID string
}

func (s *Store) NextFleetCommand(hostID string) (FleetCommandRecord, error) {
	now := time.Now().Unix()
	tx, err := s.DB.Begin()
	if err != nil {
		return FleetCommandRecord{}, err
	}
	defer tx.Rollback()
	rows, _ := tx.Query(`SELECT job_id FROM fleet_commands WHERE host_id=? AND status IN ('queued','running') AND expires_at<? AND job_id<>''`, hostID, now)
	expiredJobs := []string{}
	if rows != nil {
		for rows.Next() {
			var id string
			if rows.Scan(&id) == nil {
				expiredJobs = append(expiredJobs, id)
			}
		}
		_ = rows.Close()
	}
	_, _ = tx.Exec(`UPDATE fleet_commands SET status='expired',error='命令已过期',updated_at=? WHERE host_id=? AND status IN ('queued','running') AND expires_at<?`, now, hostID, now)
	for _, jobID := range expiredJobs {
		_, _ = tx.Exec(`UPDATE jobs SET status='failed',progress=100,message='远端命令已过期',error='命令超时且不会在重连后补执行',updated_at=? WHERE id=?`, now, jobID)
	}
	var record FleetCommandRecord
	var expires int64
	err = tx.QueryRow(`SELECT id,kind,actor,payload_cipher,job_id,expires_at FROM fleet_commands WHERE host_id=? AND status IN ('running','queued') AND expires_at>=? ORDER BY CASE status WHEN 'running' THEN 0 ELSE 1 END,created_at LIMIT 1`, hostID, now).Scan(&record.Command.ID, &record.Command.Kind, &record.Command.Actor, &record.PayloadCipher, &record.JobID, &expires)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			if commitErr := tx.Commit(); commitErr != nil {
				return FleetCommandRecord{}, commitErr
			}
		}
		return FleetCommandRecord{}, err
	}
	result, err := tx.Exec(`UPDATE fleet_commands SET status='running',updated_at=? WHERE id=? AND status IN ('queued','running')`, now, record.Command.ID)
	if err != nil {
		return FleetCommandRecord{}, err
	}
	count, _ := result.RowsAffected()
	if count != 1 {
		return FleetCommandRecord{}, sql.ErrNoRows
	}
	record.Command.ExpiresAt = time.Unix(expires, 0)
	return record, tx.Commit()
}

func (s *Store) CompleteFleetCommand(id, status, resultCipher, commandErr string) (string, error) {
	var jobID string
	var current string
	if err := s.DB.QueryRow(`SELECT job_id,status FROM fleet_commands WHERE id=?`, id).Scan(&jobID, &current); err != nil {
		return "", err
	}
	if current == "success" || current == "failed" || current == "expired" {
		return jobID, nil
	}
	_, err := s.DB.Exec(`UPDATE fleet_commands SET status=?,result_cipher=?,error=?,updated_at=? WHERE id=?`, status, resultCipher, commandErr, time.Now().Unix(), id)
	return jobID, err
}

func (s *Store) FleetCommand(id string) (status, resultCipher, commandErr string, err error) {
	err = s.DB.QueryRow(`SELECT status,result_cipher,error FROM fleet_commands WHERE id=?`, id).Scan(&status, &resultCipher, &commandErr)
	return
}

func (s *Store) FleetCommandHost(id string) (string, error) {
	var hostID string
	err := s.DB.QueryRow(`SELECT host_id FROM fleet_commands WHERE id=?`, id).Scan(&hostID)
	return hostID, err
}

func (s *Store) SaveFleetReceipt(id, status, resultJSON, receiptErr string) error {
	_, err := s.DB.Exec(`INSERT INTO fleet_command_receipts(command_id,status,result_json,error,completed_at) VALUES(?,?,?,?,?) ON CONFLICT(command_id) DO NOTHING`, id, status, resultJSON, receiptErr, time.Now().Unix())
	return err
}

func (s *Store) FleetReceipt(id string) (model.FleetCommandResult, error) {
	var result model.FleetCommandResult
	var raw string
	err := s.DB.QueryRow(`SELECT status,result_json,error FROM fleet_command_receipts WHERE command_id=?`, id).Scan(&result.Status, &raw, &result.Error)
	result.Result = json.RawMessage(raw)
	return result, err
}

func (s *Store) SaveFleetSubscriptionCache(hostID, revision, cipher string) error {
	_, err := s.DB.Exec(`INSERT INTO fleet_subscription_cache(host_id,revision,cipher,updated_at) VALUES(?,?,?,?) ON CONFLICT(host_id) DO UPDATE SET revision=excluded.revision,cipher=excluded.cipher,updated_at=excluded.updated_at`, hostID, revision, cipher, time.Now().Unix())
	return err
}

func (s *Store) FleetSubscriptionCache(hostID string) (revision, cipher string, updated time.Time, err error) {
	var ts int64
	err = s.DB.QueryRow(`SELECT revision,cipher,updated_at FROM fleet_subscription_cache WHERE host_id=?`, hostID).Scan(&revision, &cipher, &ts)
	updated = time.Unix(ts, 0)
	return
}

func (s *Store) ClearFleetSubscriptionCaches() error {
	_, err := s.DB.Exec(`DELETE FROM fleet_subscription_cache`)
	return err
}
