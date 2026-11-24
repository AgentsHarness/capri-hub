package hub

import (
	"sync/atomic"
	"time"
)

// relayLatencyBuckets are coarse upper bounds in milliseconds for the
// debug-only latency histogram exposed by GET /api/stats. This is a
// troubleshooting aid, not a metrics backend.
const relayLatencyBucketCount = 15

var relayLatencyBuckets = [relayLatencyBucketCount]uint64{
	10, 25, 50, 100, 250,
	500, 1000, 2000, 5000, 10000,
	30000, 60000, 300000, 900000, 2700000,
}

// relayStats aggregates relay request outcomes for the debug snapshot. It
// deliberately has no labels and no external dependency: the operator can
// answer "is relay slow?" with one curl to /api/stats.
type relayStats struct {
	inflight  atomic.Int64
	requests  atomic.Uint64
	completed atomic.Uint64
	errors    atomic.Uint64
	totalMs   atomic.Uint64
	maxMs     atomic.Uint64
	buckets   [relayLatencyBucketCount]atomic.Uint64
	overflow  atomic.Uint64
}

func (s *relayStats) begin() {
	s.inflight.Add(1)
}

// end records one finished relay attempt. err is the transport/relay error
// seen by the hub; a successful HTTP response from the host is not an error,
// even when its status is 4xx.
func (s *relayStats) end(d time.Duration, err error) {
	s.inflight.Add(-1)
	s.requests.Add(1)
	if err != nil {
		s.errors.Add(1)
	} else {
		s.completed.Add(1)
	}
	ms := uint64(d.Milliseconds())
	if d < 0 {
		ms = 0
	}
	s.totalMs.Add(ms)
	for {
		cur := s.maxMs.Load()
		if ms <= cur || s.maxMs.CompareAndSwap(cur, ms) {
			break
		}
	}
	for i, upper := range relayLatencyBuckets {
		if ms <= upper {
			s.buckets[i].Add(1)
			return
		}
	}
	s.overflow.Add(1)
}

type relayBucket struct {
	LeMs  uint64 `json:"leMs"`
	Count uint64 `json:"count"`
}

type relayStatSnapshot struct {
	Requests  uint64        `json:"requests"`
	Completed uint64        `json:"completed"`
	Errors    uint64        `json:"errors"`
	Inflight  int64         `json:"inflight"`
	AvgMs     uint64        `json:"avgMs"`
	MaxMs     uint64        `json:"maxMs"`
	P50Ms     uint64        `json:"p50Ms"`
	P95Ms     uint64        `json:"p95Ms"`
	P99Ms     uint64        `json:"p99Ms"`
	Buckets   []relayBucket `json:"buckets,omitempty"`
	Overflow  uint64        `json:"overflow,omitempty"`
}

func (s *relayStats) snapshot() relayStatSnapshot {
	requests := s.requests.Load()
	out := relayStatSnapshot{
		Requests:  requests,
		Completed: s.completed.Load(),
		Errors:    s.errors.Load(),
		Inflight:  s.inflight.Load(),
		MaxMs:     s.maxMs.Load(),
		Overflow:  s.overflow.Load(),
	}
	if requests > 0 {
		out.AvgMs = s.totalMs.Load() / requests
	}
	out.Buckets = make([]relayBucket, 0, relayLatencyBucketCount)
	var cumulative uint64
	for i, upper := range relayLatencyBuckets {
		cumulative += s.buckets[i].Load()
		out.Buckets = append(out.Buckets, relayBucket{LeMs: upper, Count: cumulative})
	}
	percentile := func(p uint64) uint64 {
		if requests == 0 {
			return 0
		}
		target := (requests*p + 99) / 100
		for _, b := range out.Buckets {
			if target <= b.Count {
				return b.LeMs
			}
		}
		return out.MaxMs
	}
	out.P50Ms = percentile(50)
	out.P95Ms = percentile(95)
	out.P99Ms = percentile(99)
	return out
}
