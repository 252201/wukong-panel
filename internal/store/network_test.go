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
	for _, sample := range []model.NetworkSample{
		{Status: "partial", LatencyMS: 120, PacketLossPct: 20, PacketsSent: 10, PacketsReceived: 8, Targets: []string{"8.8.8.8"}, CheckedAt: now},
		{Status: "ok", LatencyMS: 42, PacketsSent: 10, PacketsReceived: 10, Targets: []string{"1.1.1.1"}, CheckedAt: now.Add(-time.Minute)},
	} {
		if err := database.AddNetworkSample(sample); err != nil {
			t.Fatal(err)
		}
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	database, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	samples, err := database.RecentNetworkSamples(now.Add(-30*time.Minute), 30)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 2 || samples[0].LatencyMS != 42 || samples[1].PacketLossPct != 20 || samples[1].Targets[0] != "8.8.8.8" {
		t.Fatalf("unexpected persisted samples: %+v", samples)
	}
	samples, err = database.RecentNetworkSamples(now.Add(-30*time.Second), 30)
	if err != nil || len(samples) != 1 || samples[0].CheckedAt != now {
		t.Fatalf("time window samples=%+v err=%v", samples, err)
	}
}
