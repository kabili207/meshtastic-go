// Package broadcast provides a periodic broadcast scheduler for Meshtastic
// NodeInfo and Position packets. It sends packets at configurable intervals
// via a transport-agnostic callback.
package broadcast

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/kabili207/meshtastic-go/core"
	pb "github.com/kabili207/meshtastic-go/core/proto"
	"google.golang.org/protobuf/proto"
)

// SendFunc is called to transmit a built MeshPacket onto the mesh.
// The scheduler does not know about transports — it just calls this.
type SendFunc func(ctx context.Context, packet *pb.MeshPacket) error

// Config configures a broadcast Scheduler.
type Config struct {
	// NodeID is this node's identity.
	NodeID core.NodeID
	// LongName for NodeInfo broadcasts.
	LongName string
	// ShortName for NodeInfo broadcasts.
	ShortName string
	// HwModel for NodeInfo broadcasts.
	HwModel pb.HardwareModel
	// PublicKey is the X25519 public key included in NodeInfo broadcasts.
	PublicKey []byte

	// NodeInfoInterval is the interval between NodeInfo broadcasts.
	// Zero disables NodeInfo broadcasting.
	NodeInfoInterval time.Duration

	// PositionInterval is the interval between Position broadcasts.
	// Zero disables Position broadcasting.
	PositionInterval time.Duration

	// Position coordinates for Position broadcasts.
	PositionLatitudeI  int32
	PositionLongitudeI int32
	PositionAltitude   int32

	// Send is the function used to transmit packets.
	Send SendFunc

	// Logger for broadcast events. Falls back to slog.Default() if nil.
	Logger *slog.Logger
}

// Scheduler periodically broadcasts NodeInfo and Position packets.
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
		fn       func(context.Context) error
	}

	jobs := []broadcastJob{}
	if s.cfg.NodeInfoInterval > 0 {
		jobs = append(jobs, broadcastJob{
			name:     "NodeInfo",
			interval: s.cfg.NodeInfoInterval,
			fn:       s.BroadcastNodeInfo,
		})
	}
	if s.cfg.PositionInterval > 0 {
		jobs = append(jobs, broadcastJob{
			name:     "Position",
			interval: s.cfg.PositionInterval,
			fn:       s.BroadcastPosition,
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

// BroadcastNodeInfo sends an immediate NodeInfo broadcast.
func (s *Scheduler) BroadcastNodeInfo(ctx context.Context) error {
	s.log.Debug("broadcasting NodeInfo")
	user := &pb.User{
		Id:        s.cfg.NodeID.String(),
		LongName:  s.cfg.LongName,
		ShortName: s.cfg.ShortName,
		HwModel:   s.cfg.HwModel,
		PublicKey: s.cfg.PublicKey,
	}
	userBytes, err := proto.Marshal(user)
	if err != nil {
		return fmt.Errorf("marshalling user: %w", err)
	}
	return s.cfg.Send(ctx, &pb.MeshPacket{
		From: s.cfg.NodeID.Uint32(),
		To:   core.BroadcastNodeID.Uint32(),
		PayloadVariant: &pb.MeshPacket_Decoded{
			Decoded: &pb.Data{
				Portnum: pb.PortNum_NODEINFO_APP,
				Payload: userBytes,
			},
		},
	})
}

// BroadcastPosition sends an immediate Position broadcast.
func (s *Scheduler) BroadcastPosition(ctx context.Context) error {
	s.log.Debug("broadcasting Position")
	position := &pb.Position{
		LatitudeI:  &s.cfg.PositionLatitudeI,
		LongitudeI: &s.cfg.PositionLongitudeI,
		Altitude:   &s.cfg.PositionAltitude,
		Time:       uint32(time.Now().Unix()),
	}
	positionBytes, err := proto.Marshal(position)
	if err != nil {
		return fmt.Errorf("marshalling position: %w", err)
	}
	return s.cfg.Send(ctx, &pb.MeshPacket{
		From: s.cfg.NodeID.Uint32(),
		To:   core.BroadcastNodeID.Uint32(),
		PayloadVariant: &pb.MeshPacket_Decoded{
			Decoded: &pb.Data{
				Portnum: pb.PortNum_POSITION_APP,
				Payload: positionBytes,
			},
		},
	})
}
