package client

import (
	"fmt"
	"sync"
	"sync/atomic"

	"google.golang.org/protobuf/proto"
)

// MessageHandler is a function that processes a protobuf message and returns an error if handling fails.
type MessageHandler func(msg proto.Message) error

// Subscription represents a registered handler that can be unsubscribed.
type Subscription struct {
	id       uint64
	registry *HandlerRegistry
	msgName  string
}

// Unsubscribe removes this handler from the registry.
func (s *Subscription) Unsubscribe() {
	if s.registry != nil {
		s.registry.unsubscribe(s.msgName, s.id)
	}
}

type handlerEntry struct {
	id      uint64
	handler MessageHandler
}

// HandlerRegistry holds registered handlers for protobuf messages.
type HandlerRegistry struct {
	errorOnNoHandlers bool
	mu                sync.RWMutex
	handlers          map[string][]handlerEntry
	nextID            atomic.Uint64
}

// NewHandlerRegistry creates a new instance of HandlerRegistry.
// Set errorOnNoHandler to true if you want HandleMessage to return
// an error if there are no handlers registered for a given msg.
func NewHandlerRegistry(errorOnNoHandler bool) *HandlerRegistry {
	return &HandlerRegistry{
		errorOnNoHandlers: errorOnNoHandler,
		handlers:          make(map[string][]handlerEntry),
	}
}

// Register registers a handler for a specific protobuf message type.
// Returns a Subscription that can be used to unsubscribe the handler.
func (r *HandlerRegistry) Register(msg proto.Message, handler MessageHandler) *Subscription {
	r.mu.Lock()
	defer r.mu.Unlock()

	msgName := proto.MessageName(msg)
	if msgName == "" {
		return nil
	}
	name := string(msgName)

	id := r.nextID.Add(1)
	entry := handlerEntry{
		id:      id,
		handler: handler,
	}
	r.handlers[name] = append(r.handlers[name], entry)

	return &Subscription{
		id:       id,
		registry: r,
		msgName:  name,
	}
}

// unsubscribe removes a handler by its ID.
func (r *HandlerRegistry) unsubscribe(msgName string, id uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	entries := r.handlers[msgName]
	for i, entry := range entries {
		if entry.id == id {
			// Remove the entry by replacing it with the last element
			r.handlers[msgName] = append(entries[:i], entries[i+1:]...)
			return
		}
	}
}

// HandleMessage invokes all registered handlers for the provided protobuf message.
// Handlers are called synchronously in the order they were registered.
// Returns the first error encountered, if any.
func (r *HandlerRegistry) HandleMessage(msg proto.Message) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	msgName := proto.MessageName(msg)
	if msgName == "" {
		return fmt.Errorf("failed to get message name for type: %T", msg)
	}
	name := string(msgName)

	entries, exists := r.handlers[name]
	if !exists || len(entries) == 0 {
		if r.errorOnNoHandlers {
			return fmt.Errorf("no handlers registered for message: %s", msgName)
		}
		return nil
	}

	// Call handlers synchronously - callers can spawn goroutines if they need async
	for _, entry := range entries {
		if err := entry.handler(msg); err != nil {
			return err
		}
	}

	return nil
}

// HandlerCount returns the number of handlers registered for a message type.
func (r *HandlerRegistry) HandlerCount(msg proto.Message) int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	msgName := proto.MessageName(msg)
	if msgName == "" {
		return 0
	}
	return len(r.handlers[string(msgName)])
}
