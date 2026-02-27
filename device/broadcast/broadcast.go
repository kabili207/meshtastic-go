// Package broadcast provides a periodic broadcast scheduler that fires
// caller-provided callbacks at configurable intervals. It is transport-
// and protocol-agnostic — the caller builds and sends the actual packets.
package broadcast

import (
	"context"
	"log/slog"
	"time"
)

// BroadcastFunc is called when the scheduler fires a periodic broadcast.
type BroadcastFunc func(ctx context.Context) error

// Config configures a broadcast Scheduler.
type Config struct {
	// NodeInfoInterval is the interval between NodeInfo broadcasts.
	// Zero disables NodeInfo broadcasting.
	NodeInfoInterval time.Duration
	// NodeInfoFunc is called to broadcast NodeInfo. Required if NodeInfoInterval > 0.
	NodeInfoFunc BroadcastFunc

	// PositionInterval is the interval between Position broadcasts.
	// Zero disables Position broadcasting.
	PositionInterval time.Duration
	// PositionFunc is called to broadcast Position. Required if PositionInterval > 0.
	PositionFunc BroadcastFunc

	// Logger for broadcast events. Falls back to slog.Default() if nil.
	Logger *slog.Logger
}

// Scheduler periodically fires broadcast callbacks.
type Scheduler struct {
	cfg Config
	log *slog.Logger
}

// New creates a broadcast Scheduler.
func New(cfg Config) *Scheduler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Scheduler{
		cfg: cfg,
		log: cfg.Logger.WithGroup("broadcast"),
	}
}

// Start begins periodic broadcasts. It blocks until the context is cancelled.
// An initial broadcast of each enabled type fires immediately, then repeats
// on interval.
func (s *Scheduler) Start(ctx context.Context) {
	type broadcastJob struct {
		name     string
		interval time.Duration
		fn       BroadcastFunc
	}

	var jobs []broadcastJob
	if s.cfg.NodeInfoInterval > 0 && s.cfg.NodeInfoFunc != nil {
		jobs = append(jobs, broadcastJob{
			name:     "NodeInfo",
			interval: s.cfg.NodeInfoInterval,
			fn:       s.cfg.NodeInfoFunc,
		})
	}
	if s.cfg.PositionInterval > 0 && s.cfg.PositionFunc != nil {
		jobs = append(jobs, broadcastJob{
			name:     "Position",
			interval: s.cfg.PositionInterval,
			fn:       s.cfg.PositionFunc,
		})
	}

	if len(jobs) == 0 {
		<-ctx.Done()
		return
	}

	// Start each job in its own goroutine
	done := make(chan struct{})
	for _, job := range jobs {
		go func(j broadcastJob) {
			// Initial broadcast
			if err := j.fn(ctx); err != nil {
				s.log.Error("failed to broadcast", "type", j.name, "error", err)
			}

			ticker := time.NewTicker(j.interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if err := j.fn(ctx); err != nil {
						s.log.Error("failed to broadcast", "type", j.name, "error", err)
					}
				}
			}
		}(job)
	}

	select {
	case <-ctx.Done():
	case <-done:
	}
}
