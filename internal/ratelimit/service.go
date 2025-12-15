package ratelimit

import (
	"context"
	"errors"
	"time"

	"github.com/yourorg/llm-proxy-gateway/internal/store"
)

// Postgres-backed window counters. Good enough as a starter.
// For high throughput, move to Redis or in-memory sharded + periodic sync.

type Service struct {
	st *store.Store
}

func New(st *store.Store) *Service { return &Service{st: st} }

var ErrRateLimited = errors.New("rate limit exceeded")

func (s *Service) Allow(ctx context.Context, credentialID string) error {
	lim, err := s.st.Limits().Get(ctx, credentialID)
	if err != nil {
		return err
	}
	// no limits configured => allow
	if lim.RPM == nil && lim.RPD == nil && lim.RPMth == nil {
		return nil
	}

	now := time.Now().UTC()
	if lim.RPM != nil {
		if ok, err := s.st.Counters().IncAndCheck(ctx, credentialID, "minute", trunc(now, time.Minute), *lim.RPM); err != nil {
			return err
		} else if !ok {
			return ErrRateLimited
		}
	}
	if lim.RPD != nil {
		if ok, err := s.st.Counters().IncAndCheck(ctx, credentialID, "day", truncDay(now), *lim.RPD); err != nil {
			return err
		} else if !ok {
			return ErrRateLimited
		}
	}
	if lim.RPMth != nil {
		if ok, err := s.st.Counters().IncAndCheck(ctx, credentialID, "month", truncMonth(now), *lim.RPMth); err != nil {
			return err
		} else if !ok {
			return ErrRateLimited
		}
	}
	return nil
}

func trunc(t time.Time, d time.Duration) time.Time {
	return t.Truncate(d)
}
func truncDay(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}
func truncMonth(t time.Time) time.Time {
	y, m, _ := t.Date()
	return time.Date(y, m, 1, 0, 0, 0, 0, time.UTC)
}
