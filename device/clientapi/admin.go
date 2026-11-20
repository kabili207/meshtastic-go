package clientapi

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/kabili207/meshtastic-go/core"
	pb "github.com/kabili207/meshtastic-go/core/proto"
	"github.com/kabili207/meshtastic-go/transport/stream"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// sessionPasskeyLifetime is how long a session passkey lasts before firmware's
// AdminModule::setPassKey replaces it.
const sessionPasskeyLifetime = 150 * time.Second

// ConfigChangeHandler decides whether to accept a settings change a client sent:
// an AdminMessage carrying set_owner, set_config, set_module_config, or
// set_channel. Returning nil accepts it, and the server reports the new value to
// clients from then on. Persisting the change, or applying it to the running
// node, is up to the handler. Returning an error refuses it, and the client is
// told the save failed.
type ConfigChangeHandler func(change *pb.AdminMessage) error

// handleAdmin answers an admin message a client sent. One addressed to another
// node is forwarded to the mesh, as firmware does; the rest are ours to answer,
// like AdminModule does for a local request.
func (s *Server) handleAdmin(ctx context.Context, conn *stream.Conn, pkt *pb.MeshPacket, data *pb.Data) error {
	if to := core.NodeID(pkt.To); to != 0 && to != s.cfg.NodeID {
		return s.sendToMesh(ctx, conn, pkt)
	}

	req := &pb.AdminMessage{}
	if err := proto.Unmarshal(data.Payload, req); err != nil {
		s.log.Warn("ignoring malformed admin message", "error", err)
		return nil
	}

	reply, reason := s.answerAdmin(req)
	switch {
	case reply != nil && data.WantResponse:
		reply.SessionPasskey = s.sessionPasskey()
		payload, err := proto.Marshal(reply)
		if err != nil {
			return fmt.Errorf("marshalling admin response: %w", err)
		}
		return conn.Write(s.adminToClient(pkt.Id, payload))
	case reply == nil && (data.WantResponse || reason != pb.Routing_NONE):
		// AdminModule acks a request it has no reply for, when asked to respond.
		return conn.Write(s.routingToClient(pkt.Id, reason))
	}
	return nil
}

// answerAdmin returns the reply to a local admin request, or the Routing result
// when there is no reply message.
func (s *Server) answerAdmin(req *pb.AdminMessage) (*pb.AdminMessage, pb.Routing_Error) {
	switch v := req.PayloadVariant.(type) {
	case *pb.AdminMessage_GetOwnerRequest:
		return &pb.AdminMessage{PayloadVariant: &pb.AdminMessage_GetOwnerResponse{GetOwnerResponse: s.ownNodeInfo().GetUser()}}, pb.Routing_NONE

	case *pb.AdminMessage_GetDeviceMetadataRequest:
		return &pb.AdminMessage{PayloadVariant: &pb.AdminMessage_GetDeviceMetadataResponse{GetDeviceMetadataResponse: s.metadata()}}, pb.Routing_NONE

	case *pb.AdminMessage_GetChannelRequest:
		// The request carries the channel index plus one.
		ch := s.channel(int(v.GetChannelRequest) - 1)
		if ch == nil {
			return nil, pb.Routing_BAD_REQUEST
		}
		return &pb.AdminMessage{PayloadVariant: &pb.AdminMessage_GetChannelResponse{GetChannelResponse: ch}}, pb.Routing_NONE

	case *pb.AdminMessage_GetConfigRequest:
		c := s.configSection(&pb.Config{}, s.localConfig, int32(v.GetConfigRequest)+1)
		if c == nil {
			return nil, pb.Routing_BAD_REQUEST
		}
		return &pb.AdminMessage{PayloadVariant: &pb.AdminMessage_GetConfigResponse{GetConfigResponse: c.(*pb.Config)}}, pb.Routing_NONE

	case *pb.AdminMessage_GetModuleConfigRequest:
		m := s.configSection(&pb.ModuleConfig{}, s.moduleConfig, int32(v.GetModuleConfigRequest)+1)
		if m == nil {
			return nil, pb.Routing_BAD_REQUEST
		}
		return &pb.AdminMessage{PayloadVariant: &pb.AdminMessage_GetModuleConfigResponse{GetModuleConfigResponse: m.(*pb.ModuleConfig)}}, pb.Routing_NONE

	case *pb.AdminMessage_BeginEditSettings, *pb.AdminMessage_CommitEditSettings:
		// Each change is applied as it arrives, so a transaction has nothing to add.
		return nil, pb.Routing_NONE

	case *pb.AdminMessage_SetOwner, *pb.AdminMessage_SetConfig, *pb.AdminMessage_SetModuleConfig, *pb.AdminMessage_SetChannel:
		return nil, s.applyChange(req)
	}

	if isWrite(req) {
		// Reboots, resets, and the like: nothing a Go node can do for an app.
		return nil, pb.Routing_NOT_AUTHORIZED
	}
	return nil, pb.Routing_NONE
}

// isWrite reports whether an admin request asks for something to change, as
// opposed to reading state. Every read request is named get_*_request.
func isWrite(req *pb.AdminMessage) bool {
	m := req.ProtoReflect()
	fd := m.WhichOneof(m.Descriptor().Oneofs().ByName("payload_variant"))
	if fd == nil {
		return false
	}
	name := string(fd.Name())
	return !(len(name) > len("get__request") && name[:4] == "get_" && name[len(name)-8:] == "_request")
}

// applyChange offers a settings change to OnConfigChange, and on acceptance
// records it so clients see it from then on.
func (s *Server) applyChange(req *pb.AdminMessage) pb.Routing_Error {
	if s.cfg.OnConfigChange == nil {
		return pb.Routing_NOT_AUTHORIZED
	}
	if err := s.cfg.OnConfigChange(proto.Clone(req).(*pb.AdminMessage)); err != nil {
		s.log.Info("settings change refused", "error", err)
		return pb.Routing_BAD_REQUEST
	}

	s.settingsMu.Lock()
	defer s.settingsMu.Unlock()
	switch v := req.PayloadVariant.(type) {
	case *pb.AdminMessage_SetOwner:
		s.owner = proto.Clone(v.SetOwner).(*pb.User)
	case *pb.AdminMessage_SetConfig:
		storeSection(v.SetConfig, s.localConfig)
	case *pb.AdminMessage_SetModuleConfig:
		storeSection(v.SetModuleConfig, s.moduleConfig)
	case *pb.AdminMessage_SetChannel:
		if i := int(v.SetChannel.GetIndex()); i >= 0 && i < len(s.channels) {
			s.channels[i] = proto.Clone(v.SetChannel).(*pb.Channel)
		}
	}
	return pb.Routing_NONE
}

// storeSection copies the section a Config or ModuleConfig carries into the
// LocalConfig or LocalModuleConfig field of the same name.
func storeSection(wrapper proto.Message, local proto.Message) {
	wm := wrapper.ProtoReflect()
	fd := wm.WhichOneof(wm.Descriptor().Oneofs().ByName("payload_variant"))
	if fd == nil {
		return
	}
	lm := local.ProtoReflect()
	if lfd := lm.Descriptor().Fields().ByName(fd.Name()); lfd != nil {
		lm.Set(lfd, protoreflect.ValueOfMessage(proto.Clone(wm.Get(fd).Message().Interface()).ProtoReflect()))
	}
}

// configSection returns the Config or ModuleConfig holding the section with
// field number num, or nil when there is no such section.
func (s *Server) configSection(wrapper proto.Message, local proto.Message, num int32) proto.Message {
	s.settingsMu.RLock()
	defer s.settingsMu.RUnlock()
	fd := wrapper.ProtoReflect().Descriptor().Oneofs().ByName("payload_variant").Fields().ByNumber(protoreflect.FieldNumber(num))
	if fd == nil {
		return nil
	}
	return sectionMessage(wrapper, local, fd)
}

// sessionPasskey returns the current session passkey, replacing it once it is
// older than firmware's lifetime.
func (s *Server) sessionPasskey() []byte {
	s.passkeyMu.Lock()
	defer s.passkeyMu.Unlock()
	if s.passkey == nil || time.Since(s.passkeyTime) > sessionPasskeyLifetime {
		s.passkey = make([]byte, 8)
		_, _ = rand.Read(s.passkey)
		s.passkeyTime = time.Now()
	}
	return append([]byte(nil), s.passkey...)
}

// adminToClient wraps an admin reply as firmware delivers one to the phone.
func (s *Server) adminToClient(requestID uint32, payload []byte) *pb.FromRadio {
	return &pb.FromRadio{PayloadVariant: &pb.FromRadio_Packet{Packet: &pb.MeshPacket{
		Id:   s.cfg.NextPacketID(),
		From: s.cfg.NodeID.Uint32(),
		To:   s.cfg.NodeID.Uint32(),
		PayloadVariant: &pb.MeshPacket_Decoded{Decoded: &pb.Data{
			Portnum:   pb.PortNum_ADMIN_APP,
			Payload:   payload,
			RequestId: requestID,
		}},
	}}}
}
