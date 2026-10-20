package connector

import (
	"context"
	"sync"
	"time"
)

// Limiter spaces requests at a fixed QPS. Cloud security APIs (notably Tencent
// CSIP) enforce strict per-account rate limits, so every connector owns one.
type Limiter struct {
	mu       sync.Mutex
	next     time.Time
	interval time.Duration
}

// NewLimiter returns a limiter for the given queries-per-second. A value <= 0
// falls back to one request per second.
func NewLimiter(qps float64) *Limiter {
	if qps <= 0 {
		qps = 1
	}
	return &Limiter{interval: time.Duration(float64(time.Second) / qps)}
}

// Wait blocks until the next request slot or the context is canceled.
func (l *Limiter) Wait(ctx context.Context) error {
	l.mu.Lock()
	now := time.Now()
	if l.next.Before(now) {
		l.next = now
	}
	wait := l.next.Sub(now)
	l.next = l.next.Add(l.interval)
	l.mu.Unlock()

	if wait <= 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
