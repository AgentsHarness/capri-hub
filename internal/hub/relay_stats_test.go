package hub

import (
	"context"
	"testing"
	"time"
)

func TestRelayStatsSnapshot(t *testing.T) {
	var s relayStats
	s.begin()
	s.end(5*time.Millisecond, nil)
	s.begin()
	s.end(100*time.Millisecond, nil)
	s.begin()
	s.end(5*time.Second, context.Canceled)

	got := s.snapshot()
	if got.Requests != 3 || got.Completed != 2 || got.Errors != 1 || got.Inflight != 0 {
		t.Fatalf("counts = %+v, want 3/2/1/0", got)
	}
	if got.AvgMs != 1701 || got.MaxMs != 5000 {
		t.Fatalf("latency = avg %d max %d, want 1701/5000", got.AvgMs, got.MaxMs)
	}
	if got.P50Ms != 100 || got.P95Ms != 5000 || got.P99Ms != 5000 {
		t.Fatalf("percentiles = %+v, want 100/5000/5000", got)
	}
	if len(got.Buckets) != relayLatencyBucketCount {
		t.Fatalf("buckets len = %d, want %d", len(got.Buckets), relayLatencyBucketCount)
	}
	if got.Buckets[3].LeMs != 100 || got.Buckets[3].Count != 2 {
		t.Fatalf("bucket[3] = %+v, want le=100 count=2", got.Buckets[3])
	}
	if got.Buckets[relayLatencyBucketCount-1].Count != 3 {
		t.Fatalf("last cumulative count = %d, want 3", got.Buckets[relayLatencyBucketCount-1].Count)
	}
}

func TestDispatchOptsUnknownHostRecordsRelayStats(t *testing.T) {
	h := NewWithDir("")
	_, err := h.DispatchOpts(context.Background(), "missing", "GET", "/api/x", nil, DispatchOptions{})
	if err == nil {
		t.Fatal("DispatchOpts to an unknown host returned nil error")
	}
	got := h.Stats().Relay
	if got.Requests != 1 || got.Errors != 1 || got.Inflight != 0 {
		t.Fatalf("relay stats = %+v, want one error and no inflight", got)
	}
}
