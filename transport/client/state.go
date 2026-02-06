package client

import (
	"sync"

	pb "github.com/kabili207/meshtastic-go/core/proto"
	"google.golang.org/protobuf/proto"
)

// DeviceState holds the state received from a Meshtastic device during handshake.
// All methods are thread-safe.
type DeviceState struct {
	sync.RWMutex
	complete       bool
	configID       uint32
	nodeInfo       *pb.MyNodeInfo
	deviceMetadata *pb.DeviceMetadata
	nodes          []*pb.NodeInfo
	channels       []*pb.Channel
	configs        []*pb.Config
	modules        []*pb.ModuleConfig
}

// Complete returns true if the initial configuration exchange is complete.
func (s *DeviceState) Complete() bool {
	s.RLock()
	defer s.RUnlock()
	return s.complete
}

// ConfigID returns the configuration request ID.
func (s *DeviceState) ConfigID() uint32 {
	s.RLock()
	defer s.RUnlock()
	return s.configID
}

// NodeInfo returns the device's node info.
func (s *DeviceState) NodeInfo() *pb.MyNodeInfo {
	s.RLock()
	defer s.RUnlock()
	if s.nodeInfo == nil {
		return nil
	}
	return proto.Clone(s.nodeInfo).(*pb.MyNodeInfo)
}

// DeviceMetadata returns the device's metadata.
func (s *DeviceState) DeviceMetadata() *pb.DeviceMetadata {
	s.RLock()
	defer s.RUnlock()
	if s.deviceMetadata == nil {
		return nil
	}
	return proto.Clone(s.deviceMetadata).(*pb.DeviceMetadata)
}

// Nodes returns a copy of all known nodes.
func (s *DeviceState) Nodes() []*pb.NodeInfo {
	s.RLock()
	defer s.RUnlock()
	nodes := make([]*pb.NodeInfo, len(s.nodes))
	for i, n := range s.nodes {
		nodes[i] = proto.Clone(n).(*pb.NodeInfo)
	}
	return nodes
}

// Channels returns a copy of all configured channels.
func (s *DeviceState) Channels() []*pb.Channel {
	s.RLock()
	defer s.RUnlock()
	channels := make([]*pb.Channel, len(s.channels))
	for i, c := range s.channels {
		channels[i] = proto.Clone(c).(*pb.Channel)
	}
	return channels
}

// Configs returns a copy of all device configs.
func (s *DeviceState) Configs() []*pb.Config {
	s.RLock()
	defer s.RUnlock()
	configs := make([]*pb.Config, len(s.configs))
	for i, c := range s.configs {
		configs[i] = proto.Clone(c).(*pb.Config)
	}
	return configs
}

// Modules returns a copy of all module configs.
func (s *DeviceState) Modules() []*pb.ModuleConfig {
	s.RLock()
	defer s.RUnlock()
	modules := make([]*pb.ModuleConfig, len(s.modules))
	for i, m := range s.modules {
		modules[i] = proto.Clone(m).(*pb.ModuleConfig)
	}
	return modules
}

// SetComplete sets the completion status.
func (s *DeviceState) SetComplete(complete bool) {
	s.Lock()
	defer s.Unlock()
	s.complete = complete
}

// SetConfigID sets the configuration ID.
func (s *DeviceState) SetConfigID(configID uint32) {
	s.Lock()
	defer s.Unlock()
	s.configID = configID
}

// SetNodeInfo sets the device's node info.
func (s *DeviceState) SetNodeInfo(nodeInfo *pb.MyNodeInfo) {
	s.Lock()
	defer s.Unlock()
	s.nodeInfo = nodeInfo
}

// SetDeviceMetadata sets the device's metadata.
func (s *DeviceState) SetDeviceMetadata(metadata *pb.DeviceMetadata) {
	s.Lock()
	defer s.Unlock()
	s.deviceMetadata = metadata
}

// AddNode adds a node to the known nodes list.
func (s *DeviceState) AddNode(node *pb.NodeInfo) {
	s.Lock()
	defer s.Unlock()
	s.nodes = append(s.nodes, node)
}

// AddChannel adds a channel to the channels list.
func (s *DeviceState) AddChannel(channel *pb.Channel) {
	s.Lock()
	defer s.Unlock()
	s.channels = append(s.channels, channel)
}

// AddConfig adds a config to the configs list.
func (s *DeviceState) AddConfig(config *pb.Config) {
	s.Lock()
	defer s.Unlock()
	s.configs = append(s.configs, config)
}

// AddModule adds a module config to the modules list.
func (s *DeviceState) AddModule(module *pb.ModuleConfig) {
	s.Lock()
	defer s.Unlock()
	s.modules = append(s.modules, module)
}

// Reset clears all state.
func (s *DeviceState) Reset() {
	s.Lock()
	defer s.Unlock()
	s.complete = false
	s.configID = 0
	s.nodeInfo = nil
	s.deviceMetadata = nil
	s.nodes = nil
	s.channels = nil
	s.configs = nil
	s.modules = nil
}
