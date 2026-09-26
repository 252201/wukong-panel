package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/252201/wukong-panel/internal/model"
)

func TestNetworkSamplesPersistAcrossReopenAndKeepOrder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "network.db")
	database, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	for _, item := range []struct {
		group  string
		sample model.NetworkSample
	}{
		{"international", model.NetworkSample{Status: "partial", LatencyMS: 120, PacketLossPct: 20, PacketsSent: 10, PacketsReceived: 8, Targets: []string{"8.8.8.8"}, CheckedAt: now}},
		{"international", model.NetworkSample{Status: "ok", LatencyMS: 42, PacketsSent: 10, PacketsReceived: 10, Targets: []string{"1.1.1.1"}, CheckedAt: now.Add(-time.Minute)}},
		{"domestic", model.NetworkSample{Status: "ok", LatencyMS: 160, PacketsSent: 10, PacketsReceived: 10, Targets: []string{"194.138.202.35"}, CheckedAt: now}},
	} {
		if err := database.AddNetworkSample(item.group, item.sample); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := database.DB.Exec(`INSERT INTO network_samples(ts,status,latency_ms,packet_loss_pct,packets_sent,packets_received,targets_json)
		VALUES(?,?,?,?,?,?,?)`, now.Unix(), "ok", 42, 0, 10, 10, `["1.1.1.1"]`); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	database, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	samples, err := database.RecentNetworkSamples("international", now.Add(-30*time.Minute), 30)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 2 || samples[0].LatencyMS != 42 || samples[1].PacketLossPct != 20 || samples[1].Targets[0] != "8.8.8.8" {
		t.Fatalf("unexpected persisted samples: %+v", samples)
	}
	samples, err = database.RecentNetworkSamples("international", now.Add(-30*time.Second), 30)
	if err != nil || len(samples) != 1 || samples[0].CheckedAt != now {
		t.Fatalf("time window samples=%+v err=%v", samples, err)
	}
	domestic, err := database.RecentNetworkSamples("domestic", now.Add(-30*time.Second), 30)
	if err != nil || len(domestic) != 1 || domestic[0].LatencyMS != 160 {
		t.Fatalf("domestic samples=%+v err=%v", domestic, err)
	}
	var legacyCount int
	if err := database.DB.QueryRow(`SELECT COUNT(*) FROM network_samples`).Scan(&legacyCount); err != nil || legacyCount != 1 {
		t.Fatalf("legacy samples were changed: count=%d err=%v", legacyCount, err)
	}
}
