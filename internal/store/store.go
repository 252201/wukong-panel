package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/252201/wukong-panel/internal/model"
	"github.com/252201/wukong-panel/internal/security"
)

type Store struct{ DB *sql.DB }

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	s := &Store{DB: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.DB.Close() }

func (s *Store) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
  must_change INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, csrf TEXT NOT NULL,
  expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS nodes (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, protocol TEXT NOT NULL, mode TEXT NOT NULL,
  listen_port INTEGER NOT NULL, server TEXT NOT NULL DEFAULT '', domain TEXT NOT NULL DEFAULT '',
  preferred_server TEXT NOT NULL DEFAULT '',
  websocket_path TEXT NOT NULL DEFAULT '',
  ipv4_bind TEXT NOT NULL DEFAULT '', ipv6_bind TEXT NOT NULL DEFAULT '', auto_bind INTEGER NOT NULL DEFAULT 1,
  service_name TEXT NOT NULL, service_manager TEXT NOT NULL, config_path TEXT NOT NULL,
  config_version TEXT NOT NULL, ownership TEXT NOT NULL, shared_group TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'unknown', secret_cipher TEXT NOT NULL,
  probe_status TEXT NOT NULL DEFAULT '', probe_latency_ms INTEGER NOT NULL DEFAULT 0,
  probe_exit_ip TEXT NOT NULL DEFAULT '', probe_target TEXT NOT NULL DEFAULT '',
  probe_error TEXT NOT NULL DEFAULT '', probe_checked_at INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_nodes_config_port ON nodes(config_path, listen_port);
CREATE TABLE IF NOT EXISTS metrics (
  ts INTEGER PRIMARY KEY, iface TEXT NOT NULL, rx_bytes INTEGER NOT NULL, tx_bytes INTEGER NOT NULL,
  rx_bps REAL NOT NULL, tx_bps REAL NOT NULL, cpu REAL NOT NULL, memory REAL NOT NULL,
  memory_used_bytes INTEGER NOT NULL DEFAULT 0, memory_total_bytes INTEGER NOT NULL DEFAULT 0,
  disk REAL NOT NULL, disk_used_bytes INTEGER NOT NULL DEFAULT 0, disk_total_bytes INTEGER NOT NULL DEFAULT 0,
  load1 REAL NOT NULL, uptime INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS process_recent (
  pid INTEGER PRIMARY KEY, name TEXT NOT NULL, cpu REAL NOT NULL, rss_bytes INTEGER NOT NULL,
  memory_percent REAL NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS process_state (
  id INTEGER PRIMARY KEY CHECK(id=1), total_count INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO process_state(id) VALUES(1);
CREATE TABLE IF NOT EXISTS traffic_state (
  id INTEGER PRIMARY KEY CHECK(id=1), iface TEXT NOT NULL DEFAULT '', last_rx INTEGER NOT NULL DEFAULT 0,
  last_tx INTEGER NOT NULL DEFAULT 0, accumulated_rx INTEGER NOT NULL DEFAULT 0,
  accumulated_tx INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO traffic_state(id) VALUES(1);
CREATE TABLE IF NOT EXISTS endpoint_samples (
  ts INTEGER NOT NULL, node_id TEXT NOT NULL, endpoint TEXT NOT NULL, bytes INTEGER NOT NULL,
  PRIMARY KEY(ts,node_id,endpoint)
);
CREATE INDEX IF NOT EXISTS idx_endpoint_samples_ts ON endpoint_samples(ts);
CREATE TABLE IF NOT EXISTS endpoint_daily (
  day TEXT NOT NULL, node_id TEXT NOT NULL, node_name TEXT NOT NULL, bytes INTEGER NOT NULL,
  PRIMARY KEY(day,node_id)
);
CREATE TABLE IF NOT EXISTS endpoint_recent (
  node_id TEXT PRIMARY KEY, node_name TEXT NOT NULL, bytes INTEGER NOT NULL,
  duration_ms INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS traffic_daily (
  day TEXT PRIMARY KEY, rx_bytes INTEGER NOT NULL, tx_bytes INTEGER NOT NULL, source TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, target TEXT NOT NULL, status TEXT NOT NULL,
  progress INTEGER NOT NULL, message TEXT NOT NULL, error TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, actor TEXT NOT NULL,
  action TEXT NOT NULL, target TEXT NOT NULL, detail TEXT NOT NULL
);
`
	if _, err := s.DB.Exec(schema); err != nil {
		return err
	}
	for name, definition := range map[string]string{
		"memory_used_bytes":  "INTEGER NOT NULL DEFAULT 0",
		"memory_total_bytes": "INTEGER NOT NULL DEFAULT 0",
		"disk_used_bytes":    "INTEGER NOT NULL DEFAULT 0",
		"disk_total_bytes":   "INTEGER NOT NULL DEFAULT 0",
	} {
		if err := s.ensureColumn("metrics", name, definition); err != nil {
			return err
		}
	}
	for name, definition := range map[string]string{
		"preferred_server": "TEXT NOT NULL DEFAULT ''",
		"websocket_path":   "TEXT NOT NULL DEFAULT ''",
		"probe_status":     "TEXT NOT NULL DEFAULT ''",
		"probe_latency_ms": "INTEGER NOT NULL DEFAULT 0",
		"probe_exit_ip":    "TEXT NOT NULL DEFAULT ''",
		"probe_target":     "TEXT NOT NULL DEFAULT ''",
		"probe_error":      "TEXT NOT NULL DEFAULT ''",
		"probe_checked_at": "INTEGER NOT NULL DEFAULT 0",
	} {
		if err := s.ensureColumn("nodes", name, definition); err != nil {
			return err
		}
	}
	defaults := map[string]string{
		"language": "zh-CN", "timezone": "Asia/Shanghai", "interface": "auto",
		"traffic_quota_bytes": "0", "billing_reset_day": "1", "collect_endpoints": "true",
	}
	for key, value := range defaults {
		if _, err := s.DB.Exec("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)", key, value); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ensureColumn(table, column, definition string) error {
	rows, err := s.DB.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return err
	}
	found := false
	for rows.Next() {
		var cid int
		var name, kind string
		var notNull, primaryKey int
		var defaultValue any
		if err = rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &primaryKey); err != nil {
			rows.Close()
			return err
		}
		if name == column {
			found = true
		}
	}
	if err = rows.Close(); err != nil || found {
		return err
	}
	_, err = s.DB.Exec("ALTER TABLE " + table + " ADD COLUMN " + column + " " + definition)
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "duplicate column") {
		return nil
	}
	return err
}

func (s *Store) EnsureAdmin() (string, bool, error) {
	var count int
	if err := s.DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		return "", false, err
	}
	if count > 0 {
		return "", false, nil
	}
	password, err := security.RandomToken(15)
	if err != nil {
		return "", false, err
	}
	hash, err := security.HashPassword(password)
	if err != nil {
		return "", false, err
	}
	_, err = s.DB.Exec("INSERT INTO users(username,password_hash,must_change,created_at) VALUES('admin',?,?,?)", hash, 1, time.Now().Unix())
	return password, true, err
}

type Session struct {
	Token, CSRF string
	UserID      int64
	Username    string
	MustChange  bool
	ExpiresAt   time.Time
}

func (s *Store) Authenticate(username, password string) (int64, bool, error) {
	var id int64
	var hash string
	var must int
	err := s.DB.QueryRow("SELECT id,password_hash,must_change FROM users WHERE username=?", username).Scan(&id, &hash, &must)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	if !security.VerifyPassword(hash, password) {
		return 0, false, nil
	}
	return id, must == 1, nil
}

func (s *Store) CreateSession(userID int64) (Session, error) {
	token, err := security.RandomToken(32)
	if err != nil {
		return Session{}, err
	}
	csrf, err := security.RandomToken(24)
	if err != nil {
		return Session{}, err
	}
	expires := time.Now().Add(12 * time.Hour)
	_, err = s.DB.Exec("INSERT INTO sessions(token_hash,user_id,csrf,expires_at,created_at) VALUES(?,?,?,?,?)", security.HashToken(token), userID, csrf, expires.Unix(), time.Now().Unix())
	return Session{Token: token, CSRF: csrf, UserID: userID, ExpiresAt: expires}, err
}

func (s *Store) Session(token string) (Session, error) {
	var result Session
	var expires int64
	var must int
	err := s.DB.QueryRow(`SELECT s.user_id,u.username,u.must_change,s.csrf,s.expires_at
FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?`, security.HashToken(token), time.Now().Unix()).Scan(&result.UserID, &result.Username, &must, &result.CSRF, &expires)
	if err != nil {
		return Session{}, err
	}
	result.MustChange = must == 1
	result.ExpiresAt = time.Unix(expires, 0)
	return result, nil
}

func (s *Store) DeleteSession(token string) error {
	_, err := s.DB.Exec("DELETE FROM sessions WHERE token_hash=?", security.HashToken(token))
	return err
}

func (s *Store) ChangePassword(userID int64, password string) error {
	if len(password) < 12 {
		return errors.New("password must contain at least 12 characters")
	}
	hash, err := security.HashPassword(password)
	if err != nil {
		return err
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec("UPDATE users SET password_hash=?,must_change=0 WHERE id=?", hash, userID); err != nil {
		return err
	}
	if _, err = tx.Exec("DELETE FROM sessions WHERE user_id=?", userID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Nodes(ctx context.Context) ([]model.Node, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id,name,protocol,mode,listen_port,server,domain,preferred_server,websocket_path,ipv4_bind,ipv6_bind,auto_bind,
service_name,service_manager,config_path,config_version,ownership,shared_group,status,probe_status,probe_latency_ms,
probe_exit_ip,probe_target,probe_error,probe_checked_at,created_at,updated_at FROM nodes ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []model.Node{}
	for rows.Next() {
		var n model.Node
		var auto int
		var probeChecked, created, updated int64
		if err := rows.Scan(&n.ID, &n.Name, &n.Protocol, &n.Mode, &n.ListenPort, &n.Server, &n.Domain, &n.PreferredServer, &n.WebSocketPath, &n.IPv4Bind, &n.IPv6Bind, &auto, &n.ServiceName, &n.ServiceManager, &n.ConfigPath, &n.ConfigVersion, &n.Ownership, &n.SharedGroup, &n.Status, &n.ProbeStatus, &n.ProbeLatencyMS, &n.ProbeExitIP, &n.ProbeTarget, &n.ProbeError, &probeChecked, &created, &updated); err != nil {
			return nil, err
		}
		n.AutoBind = auto == 1
		n.CreatedAt = time.Unix(created, 0)
		n.UpdatedAt = time.Unix(updated, 0)
		if probeChecked > 0 {
			n.ProbeCheckedAt = time.Unix(probeChecked, 0)
		}
		result = append(result, n)
	}
	return result, rows.Err()
}

func (s *Store) Node(ctx context.Context, id string, includeSecret bool) (model.Node, error) {
	var n model.Node
	var auto int
	var probeChecked, created, updated int64
	var cipher string
	err := s.DB.QueryRowContext(ctx, `SELECT id,name,protocol,mode,listen_port,server,domain,preferred_server,websocket_path,ipv4_bind,ipv6_bind,auto_bind,
service_name,service_manager,config_path,config_version,ownership,shared_group,status,secret_cipher,probe_status,probe_latency_ms,
probe_exit_ip,probe_target,probe_error,probe_checked_at,created_at,updated_at FROM nodes WHERE id=?`, id).Scan(&n.ID, &n.Name, &n.Protocol, &n.Mode, &n.ListenPort, &n.Server, &n.Domain, &n.PreferredServer, &n.WebSocketPath, &n.IPv4Bind, &n.IPv6Bind, &auto, &n.ServiceName, &n.ServiceManager, &n.ConfigPath, &n.ConfigVersion, &n.Ownership, &n.SharedGroup, &n.Status, &cipher, &n.ProbeStatus, &n.ProbeLatencyMS, &n.ProbeExitIP, &n.ProbeTarget, &n.ProbeError, &probeChecked, &created, &updated)
	if err != nil {
		return n, err
	}
	n.AutoBind = auto == 1
	n.CreatedAt = time.Unix(created, 0)
	n.UpdatedAt = time.Unix(updated, 0)
	if probeChecked > 0 {
		n.ProbeCheckedAt = time.Unix(probeChecked, 0)
	}
	if includeSecret {
		n.Secret = cipher
	}
	return n, nil
}

func (s *Store) UpsertNode(ctx context.Context, n model.Node, secretCipher string) error {
	now := time.Now().Unix()
	if n.CreatedAt.IsZero() {
		n.CreatedAt = time.Unix(now, 0)
	}
	_, err := s.DB.ExecContext(ctx, `INSERT INTO nodes(id,name,protocol,mode,listen_port,server,domain,preferred_server,websocket_path,ipv4_bind,ipv6_bind,auto_bind,service_name,service_manager,config_path,config_version,ownership,shared_group,status,secret_cipher,created_at,updated_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,protocol=excluded.protocol,mode=excluded.mode,listen_port=excluded.listen_port,server=excluded.server,domain=excluded.domain,preferred_server=excluded.preferred_server,websocket_path=excluded.websocket_path,ipv4_bind=excluded.ipv4_bind,ipv6_bind=excluded.ipv6_bind,auto_bind=excluded.auto_bind,service_name=excluded.service_name,service_manager=excluded.service_manager,config_path=excluded.config_path,config_version=excluded.config_version,ownership=excluded.ownership,shared_group=excluded.shared_group,status=excluded.status,secret_cipher=excluded.secret_cipher,updated_at=excluded.updated_at`, n.ID, n.Name, n.Protocol, n.Mode, n.ListenPort, n.Server, n.Domain, n.PreferredServer, n.WebSocketPath, n.IPv4Bind, n.IPv6Bind, boolInt(n.AutoBind), n.ServiceName, n.ServiceManager, n.ConfigPath, n.ConfigVersion, n.Ownership, n.SharedGroup, n.Status, secretCipher, n.CreatedAt.Unix(), now)
	return err
}

func (s *Store) SetNodeStatus(id, status string) error {
	_, err := s.DB.Exec("UPDATE nodes SET status=?,updated_at=? WHERE id=?", status, time.Now().Unix(), id)
	return err
}
func (s *Store) SetNodeProbeResult(id, status string, latencyMS int64, exitIP, target, probeError string, checkedAt time.Time) error {
	checked := checkedAt.Unix()
	if checkedAt.IsZero() {
		checked = 0
	}
	_, err := s.DB.Exec(`UPDATE nodes SET probe_status=?,probe_latency_ms=?,probe_exit_ip=?,probe_target=?,probe_error=?,probe_checked_at=? WHERE id=?`, status, latencyMS, exitIP, target, probeError, checked, id)
	return err
}
func (s *Store) UpdateNodeBinds(id, ipv4, ipv6 string) error {
	_, err := s.DB.Exec("UPDATE nodes SET ipv4_bind=?,ipv6_bind=?,updated_at=? WHERE id=?", ipv4, ipv6, time.Now().Unix(), id)
	return err
}
func (s *Store) UpdateNodeConfigVersions(version string) error {
	_, err := s.DB.Exec("UPDATE nodes SET config_version=?,updated_at=? WHERE config_version<>?", version, time.Now().Unix(), version)
	return err
}
func (s *Store) RenameNode(ctx context.Context, id, name string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, "UPDATE nodes SET name=?,updated_at=? WHERE id=?", name, time.Now().Unix(), id)
	if err != nil {
		return err
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if updated != 1 {
		return sql.ErrNoRows
	}
	if _, err = tx.ExecContext(ctx, "UPDATE endpoint_recent SET node_name=? WHERE node_id=?", name, id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE endpoint_daily SET node_name=? WHERE node_id=?", name, id); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) DeleteNode(id string) error {
	_, err := s.DB.Exec("DELETE FROM nodes WHERE id=?", id)
	return err
}

func (s *Store) NodeGroupCount(ctx context.Context, group string) (int, error) {
	if strings.TrimSpace(group) == "" {
		return 0, nil
	}
	var count int
	err := s.DB.QueryRowContext(ctx, "SELECT count(*) FROM nodes WHERE shared_group=?", group).Scan(&count)
	return count, err
}

func (s *Store) AddMetric(m model.Metric) error {
	_, err := s.DB.Exec(`INSERT OR REPLACE INTO metrics(ts,iface,rx_bytes,tx_bytes,rx_bps,tx_bps,cpu,memory,memory_used_bytes,memory_total_bytes,disk,disk_used_bytes,disk_total_bytes,load1,uptime) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, m.Timestamp, m.Interface, m.RXBytes, m.TXBytes, m.RXBPS, m.TXBPS, m.CPU, m.Memory, m.MemoryUsedBytes, m.MemoryTotalBytes, m.Disk, m.DiskUsedBytes, m.DiskTotalBytes, m.Load1, m.Uptime)
	if err == nil {
		_, _ = s.DB.Exec("DELETE FROM metrics WHERE ts<?", time.Now().Add(-90*24*time.Hour).Unix())
	}
	return err
}

func (s *Store) Metrics(limit int) ([]model.Metric, error) {
	if limit < 1 || limit > 1000 {
		limit = 120
	}
	rows, err := s.DB.Query(`SELECT ts,iface,rx_bytes,tx_bytes,rx_bps,tx_bps,cpu,memory,memory_used_bytes,memory_total_bytes,disk,disk_used_bytes,disk_total_bytes,load1,uptime FROM metrics ORDER BY ts DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []model.Metric{}
	for rows.Next() {
		var m model.Metric
		if err := rows.Scan(&m.Timestamp, &m.Interface, &m.RXBytes, &m.TXBytes, &m.RXBPS, &m.TXBPS, &m.CPU, &m.Memory, &m.MemoryUsedBytes, &m.MemoryTotalBytes, &m.Disk, &m.DiskUsedBytes, &m.DiskTotalBytes, &m.Load1, &m.Uptime); err != nil {
			return nil, err
		}
		items = append(items, m)
	}
	for i, j := 0, len(items)-1; i < j; i, j = i+1, j-1 {
		items[i], items[j] = items[j], items[i]
	}
	return items, rows.Err()
}

func (s *Store) MetricsBetween(start, end int64) ([]model.Metric, error) {
	rows, err := s.DB.Query(`SELECT ts,iface,rx_bytes,tx_bytes,rx_bps,tx_bps,cpu,memory,memory_used_bytes,memory_total_bytes,disk,disk_used_bytes,disk_total_bytes,load1,uptime FROM metrics WHERE ts>=? AND ts<=? ORDER BY ts`, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []model.Metric{}
	for rows.Next() {
		var m model.Metric
		if err := rows.Scan(&m.Timestamp, &m.Interface, &m.RXBytes, &m.TXBytes, &m.RXBPS, &m.TXBPS, &m.CPU, &m.Memory, &m.MemoryUsedBytes, &m.MemoryTotalBytes, &m.Disk, &m.DiskUsedBytes, &m.DiskTotalBytes, &m.Load1, &m.Uptime); err != nil {
			return nil, err
		}
		items = append(items, m)
	}
	return items, rows.Err()
}

func (s *Store) ReplaceProcesses(ts int64, totalCount int, processes []model.ProcessStat) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec("DELETE FROM process_recent"); err != nil {
		return err
	}
	for _, process := range processes {
		if process.PID <= 0 || process.Name == "" {
			continue
		}
		if _, err = tx.Exec(`INSERT INTO process_recent(pid,name,cpu,rss_bytes,memory_percent,updated_at) VALUES(?,?,?,?,?,?)`, process.PID, process.Name, process.CPU, process.RSSBytes, process.MemoryPercent, ts); err != nil {
			return err
		}
	}
	if _, err = tx.Exec("UPDATE process_state SET total_count=?,updated_at=? WHERE id=1", totalCount, ts); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Processes(limit int) ([]model.ProcessStat, int, error) {
	if limit < 1 || limit > 200 {
		limit = 100
	}
	var total int
	if err := s.DB.QueryRow("SELECT total_count FROM process_state WHERE id=1").Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.DB.Query(`SELECT pid,name,cpu,rss_bytes,memory_percent FROM process_recent ORDER BY cpu DESC,rss_bytes DESC LIMIT ?`, limit)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := []model.ProcessStat{}
	for rows.Next() {
		var item model.ProcessStat
		if err = rows.Scan(&item.PID, &item.Name, &item.CPU, &item.RSSBytes, &item.MemoryPercent); err != nil {
			return nil, 0, err
		}
		items = append(items, item)
	}
	return items, total, rows.Err()
}

func (s *Store) TrafficState() (iface string, lastRX, lastTX, accRX, accTX int64, err error) {
	err = s.DB.QueryRow("SELECT iface,last_rx,last_tx,accumulated_rx,accumulated_tx FROM traffic_state WHERE id=1").Scan(&iface, &lastRX, &lastTX, &accRX, &accTX)
	return
}
func (s *Store) UpdateTrafficState(iface string, lastRX, lastTX, accRX, accTX int64) error {
	_, err := s.DB.Exec("UPDATE traffic_state SET iface=?,last_rx=?,last_tx=?,accumulated_rx=?,accumulated_tx=?,updated_at=? WHERE id=1", iface, lastRX, lastTX, accRX, accTX, time.Now().Unix())
	return err
}
func (s *Store) AddDailyTraffic(day string, rx, tx int64, source string) error {
	_, err := s.DB.Exec(`INSERT INTO traffic_daily(day,rx_bytes,tx_bytes,source) VALUES(?,?,?,?) ON CONFLICT(day) DO UPDATE SET rx_bytes=traffic_daily.rx_bytes+excluded.rx_bytes,tx_bytes=traffic_daily.tx_bytes+excluded.tx_bytes,source=excluded.source`, day, rx, tx, source)
	return err
}
func (s *Store) ImportDailyTraffic(day string, rx, tx int64) error {
	_, err := s.DB.Exec(`INSERT INTO traffic_daily(day,rx_bytes,tx_bytes,source) VALUES(?,?,?,'vnstat') ON CONFLICT(day) DO NOTHING`, day, rx, tx)
	return err
}
func (s *Store) TrafficBetween(start, end string) (int64, int64, error) {
	var rx, tx int64
	err := s.DB.QueryRow("SELECT COALESCE(SUM(rx_bytes),0),COALESCE(SUM(tx_bytes),0) FROM traffic_daily WHERE day>=? AND day<=?", start, end).Scan(&rx, &tx)
	return rx, tx, err
}

func (s *Store) TrafficBuckets(start, end string) ([]model.TrafficBucket, error) {
	rows, err := s.DB.Query(`SELECT day,rx_bytes,tx_bytes FROM traffic_daily WHERE day>=? AND day<=? ORDER BY day`, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []model.TrafficBucket{}
	for rows.Next() {
		var item model.TrafficBucket
		if err := rows.Scan(&item.Label, &item.RXBytes, &item.TXBytes); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) AddEndpointSample(ts int64, nodeID, nodeName, endpoint string, bytes int64) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	bucket := ts - ts%10
	if _, err = tx.Exec(`INSERT INTO endpoint_samples(ts,node_id,endpoint,bytes) VALUES(?,?,?,?) ON CONFLICT(ts,node_id,endpoint) DO UPDATE SET bytes=bytes+excluded.bytes`, bucket, nodeID, endpoint, bytes); err != nil {
		return err
	}
	day := time.Unix(ts, 0).UTC().Format("2006-01-02")
	if _, err = tx.Exec(`INSERT INTO endpoint_daily(day,node_id,node_name,bytes) VALUES(?,?,?,?) ON CONFLICT(day,node_id) DO UPDATE SET bytes=bytes+excluded.bytes,node_name=excluded.node_name`, day, nodeID, nodeName, bytes); err != nil {
		return err
	}
	if _, err = tx.Exec("DELETE FROM endpoint_samples WHERE ts<?", time.Now().Add(-24*time.Hour).Unix()); err != nil {
		return err
	}
	if _, err = tx.Exec("DELETE FROM endpoint_daily WHERE day<?", time.Now().AddDate(0, 0, -90).UTC().Format("2006-01-02")); err != nil {
		return err
	}
	return tx.Commit()
}

type EndpointWindowSample struct {
	NodeID   string
	NodeName string
	Endpoint string
	Bytes    int64
}

func (s *Store) ReplaceEndpointWindow(ts int64, duration time.Duration, samples []EndpointWindowSample) error {
	if duration <= 0 {
		return errors.New("endpoint window duration must be positive")
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec("DELETE FROM endpoint_recent"); err != nil {
		return err
	}
	bucket := ts - ts%10
	day := time.Unix(ts, 0).UTC().Format("2006-01-02")
	nodeTotals := map[string]EndpointWindowSample{}
	for _, sample := range samples {
		if sample.NodeID == "" || sample.Endpoint == "" || sample.Bytes <= 0 {
			continue
		}
		if _, err = tx.Exec(`INSERT INTO endpoint_samples(ts,node_id,endpoint,bytes) VALUES(?,?,?,?) ON CONFLICT(ts,node_id,endpoint) DO UPDATE SET bytes=bytes+excluded.bytes`, bucket, sample.NodeID, sample.Endpoint, sample.Bytes); err != nil {
			return err
		}
		total := nodeTotals[sample.NodeID]
		total.NodeID = sample.NodeID
		total.NodeName = sample.NodeName
		total.Bytes += sample.Bytes
		nodeTotals[sample.NodeID] = total
	}
	durationMS := max(int64(1), duration.Milliseconds())
	for _, total := range nodeTotals {
		if _, err = tx.Exec(`INSERT INTO endpoint_recent(node_id,node_name,bytes,duration_ms,updated_at) VALUES(?,?,?,?,?)`, total.NodeID, total.NodeName, total.Bytes, durationMS, ts); err != nil {
			return err
		}
		if _, err = tx.Exec(`INSERT INTO endpoint_daily(day,node_id,node_name,bytes) VALUES(?,?,?,?) ON CONFLICT(day,node_id) DO UPDATE SET bytes=bytes+excluded.bytes,node_name=excluded.node_name`, day, total.NodeID, total.NodeName, total.Bytes); err != nil {
			return err
		}
	}
	if _, err = tx.Exec("DELETE FROM endpoint_samples WHERE ts<?", time.Now().Add(-24*time.Hour).Unix()); err != nil {
		return err
	}
	if _, err = tx.Exec("DELETE FROM endpoint_daily WHERE day<?", time.Now().AddDate(0, 0, -90).UTC().Format("2006-01-02")); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) TopEndpoints(limit int) ([]model.EndpointStat, error) {
	if limit < 1 || limit > 50 {
		limit = 10
	}
	rows, err := s.DB.Query(`SELECT e.node_id,COALESCE(n.name,e.node_id),e.endpoint,SUM(e.bytes) FROM endpoint_samples e LEFT JOIN nodes n ON n.id=e.node_id WHERE e.ts>=? GROUP BY e.node_id,e.endpoint ORDER BY SUM(e.bytes) DESC LIMIT ?`, time.Now().Add(-24*time.Hour).Unix(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []model.EndpointStat{}
	for rows.Next() {
		var item model.EndpointStat
		if err := rows.Scan(&item.NodeID, &item.NodeName, &item.Endpoint, &item.Bytes); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Store) ActiveDevices(window time.Duration, limit int) ([]model.DeviceTraffic, error) {
	if window < 10*time.Second {
		window = 25 * time.Second
	}
	if limit < 1 || limit > 50 {
		limit = 12
	}
	cutoff := time.Now().Add(-window).Unix()
	rows, err := s.DB.Query(`SELECT e.node_id,COALESCE(n.name,e.node_name,e.node_id),e.bytes,e.duration_ms FROM endpoint_recent e LEFT JOIN nodes n ON n.id=e.node_id WHERE e.updated_at>=? ORDER BY e.bytes DESC LIMIT ?`, cutoff, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []model.DeviceTraffic{}
	for rows.Next() {
		var item model.DeviceTraffic
		var durationMS int64
		if err := rows.Scan(&item.NodeID, &item.NodeName, &item.Bytes, &durationMS); err != nil {
			return nil, err
		}
		item.RateBPS = float64(item.Bytes) / (float64(max(int64(1), durationMS)) / 1000)
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Store) CreateJob(kind, target string) (model.Job, error) {
	id, err := security.RandomToken(12)
	if err != nil {
		return model.Job{}, err
	}
	now := time.Now()
	job := model.Job{ID: id, Kind: kind, Target: target, Status: "queued", Progress: 0, Message: "等待执行", CreatedAt: now, UpdatedAt: now}
	_, err = s.DB.Exec("INSERT INTO jobs(id,kind,target,status,progress,message,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)", job.ID, job.Kind, job.Target, job.Status, job.Progress, job.Message, now.Unix(), now.Unix())
	return job, err
}
func (s *Store) UpdateJob(id, status string, progress int, message, jobErr string) error {
	_, err := s.DB.Exec("UPDATE jobs SET status=?,progress=?,message=?,error=?,updated_at=? WHERE id=?", status, progress, message, jobErr, time.Now().Unix(), id)
	return err
}
func (s *Store) Job(id string) (model.Job, error) {
	var j model.Job
	var c, u int64
	err := s.DB.QueryRow("SELECT id,kind,target,status,progress,message,error,created_at,updated_at FROM jobs WHERE id=?", id).Scan(&j.ID, &j.Kind, &j.Target, &j.Status, &j.Progress, &j.Message, &j.Error, &c, &u)
	j.CreatedAt = time.Unix(c, 0)
	j.UpdatedAt = time.Unix(u, 0)
	return j, err
}
func (s *Store) Jobs(limit int) ([]model.Job, error) {
	if limit < 1 || limit > 200 {
		limit = 50
	}
	rows, err := s.DB.Query("SELECT id,kind,target,status,progress,message,error,created_at,updated_at FROM jobs ORDER BY created_at DESC LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []model.Job{}
	for rows.Next() {
		var j model.Job
		var c, u int64
		if err := rows.Scan(&j.ID, &j.Kind, &j.Target, &j.Status, &j.Progress, &j.Message, &j.Error, &c, &u); err != nil {
			return nil, err
		}
		j.CreatedAt = time.Unix(c, 0)
		j.UpdatedAt = time.Unix(u, 0)
		result = append(result, j)
	}
	return result, rows.Err()
}

func (s *Store) Settings() (model.Settings, error) {
	values := map[string]string{}
	rows, err := s.DB.Query("SELECT key,value FROM settings")
	if err != nil {
		return model.Settings{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return model.Settings{}, err
		}
		values[k] = v
	}
	quota, _ := strconv.ParseInt(values["traffic_quota_bytes"], 10, 64)
	day, _ := strconv.Atoi(values["billing_reset_day"])
	return model.Settings{Language: values["language"], Timezone: values["timezone"], Interface: values["interface"], TrafficQuotaBytes: quota, BillingResetDay: day, CollectEndpoints: values["collect_endpoints"] != "false", SubscriptionToken: values["subscription_token"]}, nil
}
func (s *Store) SaveSettings(settings model.Settings) error {
	if settings.BillingResetDay < 1 || settings.BillingResetDay > 28 {
		return errors.New("billing reset day must be between 1 and 28")
	}
	values := map[string]string{"language": settings.Language, "timezone": settings.Timezone, "interface": settings.Interface, "traffic_quota_bytes": strconv.FormatInt(settings.TrafficQuotaBytes, 10), "billing_reset_day": strconv.Itoa(settings.BillingResetDay), "collect_endpoints": strconv.FormatBool(settings.CollectEndpoints)}
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for k, v := range values {
		if _, err = tx.Exec("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", k, v); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (s *Store) Setting(key string) (string, error) {
	var value string
	err := s.DB.QueryRow("SELECT value FROM settings WHERE key=?", key).Scan(&value)
	return value, err
}
func (s *Store) SetSetting(key, value string) error {
	_, err := s.DB.Exec("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", key, value)
	return err
}
func (s *Store) Audit(actor, action, target, detail string) error {
	_, err := s.DB.Exec("INSERT INTO audit_logs(ts,actor,action,target,detail) VALUES(?,?,?,?,?)", time.Now().Unix(), actor, action, target, detail)
	return err
}

func (s *Store) SeedDemo(vault *security.Vault) error {
	var count int
	if err := s.DB.QueryRow("SELECT COUNT(*) FROM nodes").Scan(&count); err != nil || count > 0 {
		return err
	}
	secret, err := vault.Encrypt("demo-only-secret")
	if err != nil {
		return err
	}
	now := time.Now()
	for i, n := range []model.Node{{ID: "demo-v6", Name: "花果山 · IPv6优先", Protocol: "hysteria2", Mode: "prefer_v6", ListenPort: 45080, Server: "edge.example.com", Domain: "edge.example.com", IPv4Bind: "192.0.2.18", IPv6Bind: "2001:db8::18", AutoBind: true, ServiceName: "sing-box-hy2v6", ServiceManager: "systemd", ConfigPath: "/etc/s-box/hy2-v6.json", ConfigVersion: "1.14", Ownership: "managed", Status: "active"}, {ID: "demo-phone", Name: "筋斗云 · iPhone", Protocol: "hysteria2", Mode: "prefer_v6", ListenPort: 45115, Server: "edge.example.com", Domain: "edge.example.com", IPv4Bind: "192.0.2.18", IPv6Bind: "2001:db8::18", AutoBind: true, ServiceName: "sing-box-hy2devices", ServiceManager: "systemd", ConfigPath: "/etc/s-box/hy2-devices.json", ConfigVersion: "1.14", Ownership: "managed", SharedGroup: "devices", Status: "active"}, {ID: "demo-v4", Name: "定海神针 · IPv4", Protocol: "hysteria2", Mode: "v4only", ListenPort: 45082, Server: "edge.example.com", Domain: "edge.example.com", IPv4Bind: "192.0.2.18", AutoBind: true, ServiceName: "sing-box-hy2v4", ServiceManager: "systemd", ConfigPath: "/etc/s-box/hy2-v4.json", ConfigVersion: "1.14", Ownership: "managed", Status: "inactive"}} {
		n.CreatedAt = now.Add(time.Duration(i) * time.Minute)
		if err := s.UpsertNode(context.Background(), n, secret); err != nil {
			return err
		}
	}
	_ = s.SetSetting("traffic_quota_bytes", fmt.Sprint(int64(2_000_000_000_000)))
	return nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
