package store

import (
	"encoding/json"
	"time"

	"github.com/252201/wukong-panel/internal/model"
)

// AddNetworkSample stores one completed check on its source VPS. A restart in
// the same second replaces that second's sample instead of duplicating it.
func (s *Store) AddNetworkSample(group string, sample model.NetworkSample) error {
	targets, err := json.Marshal(sample.Targets)
	if err != nil {
		return err
	}
	if _, err = s.DB.Exec(`INSERT OR REPLACE INTO network_group_samples
		(group_name,ts,status,latency_ms,packet_loss_pct,packets_sent,packets_received,targets_json)
		VALUES(?,?,?,?,?,?,?,?)`, group, sample.CheckedAt.Unix(), sample.Status, sample.LatencyMS,
		sample.PacketLossPct, sample.PacketsSent, sample.PacketsReceived, string(targets)); err != nil {
		return err
	}
	_, err = s.DB.Exec(`DELETE FROM network_group_samples WHERE ts<?`, time.Now().Add(-24*time.Hour).Unix())
	return err
}

// RecentNetworkSamples returns the latest samples in chronological order.
func (s *Store) RecentNetworkSamples(group string, since time.Time, limit int) ([]model.NetworkSample, error) {
	if limit < 1 || limit > 120 {
		limit = 120
	}
	rows, err := s.DB.Query(`SELECT ts,status,latency_ms,packet_loss_pct,packets_sent,packets_received,targets_json
		FROM network_group_samples WHERE group_name=? AND ts>=? ORDER BY ts DESC LIMIT ?`, group, since.Unix(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]model.NetworkSample, 0, limit)
	for rows.Next() {
		var sample model.NetworkSample
		var timestamp int64
		var targets string
		if err := rows.Scan(&timestamp, &sample.Status, &sample.LatencyMS, &sample.PacketLossPct,
			&sample.PacketsSent, &sample.PacketsReceived, &targets); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(targets), &sample.Targets); err != nil {
			return nil, err
		}
		sample.CheckedAt = time.Unix(timestamp, 0).UTC()
		result = append(result, sample)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for left, right := 0, len(result)-1; left < right; left, right = left+1, right-1 {
		result[left], result[right] = result[right], result[left]
	}
	return result, nil
}
