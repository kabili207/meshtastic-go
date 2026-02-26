// Package nodedb provides a thread-safe database for tracking known Meshtastic
// nodes in the mesh network. It processes incoming mesh packets to extract and
// store node information, position data, and device telemetry.
package nodedb

import (
	"log/slog"
	"sync"
	"time"

	"github.com/kabili207/meshtastic-go/core"
	"github.com/kabili207/meshtastic-go/core/crypto"
	pb "github.com/kabili207/meshtastic-go/core/proto"
	"google.golang.org/protobuf/proto"
)

// Config configures a NodeDB.
type Config struct {
	// SelfNode is this node's identity.
	SelfNode core.NodeID
	// LongName is the self node's long display name.
	LongName string
	// ShortName is the self node's short display name.
	ShortName string
	// Logger for node DB events. Falls back to slog.Default() if nil.
	Logger *slog.Logger
}

// NodeDB tracks known nodes in the mesh network.
// All methods are safe for concurrent use.
type NodeDB struct {
	cfg   Config
	log   *slog.Logger
	mu    sync.RWMutex
	nodes map[uint32]*pb.NodeInfo
}

// New creates a NodeDB with the given configuration.
func New(cfg Config) *NodeDB {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.LongName == "" {
		cfg.LongName = cfg.SelfNode.DefaultLongName()
	}
	if cfg.ShortName == "" {
		cfg.ShortName = cfg.SelfNode.DefaultShortName()
	}
	return &NodeDB{
		cfg:   cfg,
		log:   cfg.Logger.WithGroup("nodedb"),
		nodes: make(map[uint32]*pb.NodeInfo),
	}
}

// Update applies an update function to the node entry for the given nodeID.
// If the node does not exist, a new entry is created. LastHeard is always
// updated to the current time.
func (db *NodeDB) Update(nodeID uint32, fn func(*pb.NodeInfo)) {
	db.mu.Lock()
	defer db.mu.Unlock()
	info, ok := db.nodes[nodeID]
	if !ok {
		info = &pb.NodeInfo{Num: nodeID}
	}
	fn(info)
	info.LastHeard = uint32(time.Now().Unix())
	db.nodes[nodeID] = info
}

// Get returns a clone of the NodeInfo for the given nodeID, or nil if not found.
func (db *NodeDB) Get(nodeID uint32) *pb.NodeInfo {
	db.mu.RLock()
	defer db.mu.RUnlock()
	info, ok := db.nodes[nodeID]
	if !ok {
		return nil
	}
	return proto.Clone(info).(*pb.NodeInfo)
}

// All returns cloned copies of all tracked nodes (excluding self).
func (db *NodeDB) All() []*pb.NodeInfo {
	db.mu.RLock()
	defer db.mu.RUnlock()
	nodes := make([]*pb.NodeInfo, 0, len(db.nodes))
	for _, info := range db.nodes {
		nodes = append(nodes, proto.Clone(info).(*pb.NodeInfo))
	}
	return nodes
}

// SelfInfo returns a NodeInfo for this node, built from the config.
func (db *NodeDB) SelfInfo() *pb.NodeInfo {
	return &pb.NodeInfo{
		Num: db.cfg.SelfNode.Uint32(),
		User: &pb.User{
			Id:        db.cfg.SelfNode.String(),
			LongName:  db.cfg.LongName,
			ShortName: db.cfg.ShortName,
		},
	}
}

// ProcessPacket extracts NODEINFO_APP, POSITION_APP, and TELEMETRY_APP data
// from a mesh packet and updates the node DB accordingly. If the packet is
// encrypted, it is decrypted using the provided PSK.
// Returns true if the node DB was updated.
func (db *NodeDB) ProcessPacket(pkt *pb.MeshPacket, channelPSK []byte) bool {
	var data *pb.Data
	switch payload := pkt.PayloadVariant.(type) {
	case *pb.MeshPacket_Decoded:
		data = payload.Decoded
	case *pb.MeshPacket_Encrypted:
		plaintext, err := crypto.XOR(payload.Encrypted, channelPSK, pkt.Id, pkt.From)
		if err != nil {
			db.log.Debug("decryption failed", "error", err)
			return false
		}
		data = &pb.Data{}
		if err := proto.Unmarshal(plaintext, data); err != nil {
			db.log.Debug("unmarshal failed", "error", err)
			return false
		}
	default:
		return false
	}

	switch data.Portnum {
	case pb.PortNum_NODEINFO_APP:
		user := &pb.User{}
		if err := proto.Unmarshal(data.Payload, user); err != nil {
			return false
		}
		db.Update(pkt.From, func(info *pb.NodeInfo) {
			info.User = user
		})
		return true
	case pb.PortNum_POSITION_APP:
		position := &pb.Position{}
		if err := proto.Unmarshal(data.Payload, position); err != nil {
			return false
		}
		db.Update(pkt.From, func(info *pb.NodeInfo) {
			info.Position = position
		})
		return true
	case pb.PortNum_TELEMETRY_APP:
		telemetry := &pb.Telemetry{}
		if err := proto.Unmarshal(data.Payload, telemetry); err != nil {
			return false
		}
		if metrics := telemetry.GetDeviceMetrics(); metrics != nil {
			db.Update(pkt.From, func(info *pb.NodeInfo) {
				info.DeviceMetrics = metrics
			})
			return true
		}
	}
	return false
}
