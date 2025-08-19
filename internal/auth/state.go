// Package auth provides authentication state management functionality.
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/vector233/go-singpass/internal/constants"
)

// StateData represents OAuth state information
type StateData struct {
	CodeVerifier string `json:"code_verifier"`
	Nonce        string `json:"nonce"`
}

// StateStore defines the interface for state storage
type StateStore interface {
	Store(ctx context.Context, state string, stateData *StateData) error
	Get(ctx context.Context, state string) (*StateData, error)
	Delete(ctx context.Context, state string)
}

// MemoryStateStore implements StateStore using in-memory storage
type MemoryStateStore struct {
	mu         sync.RWMutex
	data       map[string]*stateEntry
	expiration time.Duration
}

type stateEntry struct {
	data      *StateData
	expiredAt time.Time
}

// NewMemoryStateStore creates a new memory-based state store
func NewMemoryStateStore(expiration time.Duration) *MemoryStateStore {
	if expiration == 0 {
		expiration = constants.DefaultStateExpiration
	}
	return &MemoryStateStore{
		data:       make(map[string]*stateEntry),
		expiration: expiration,
	}
}

// Store stores state data in memory
func (ms *MemoryStateStore) Store(ctx context.Context, state string, stateData *StateData) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	ms.data[state] = &stateEntry{
		data:      stateData,
		expiredAt: time.Now().Add(ms.expiration),
	}
	return nil
}

// Get retrieves state data from memory
func (ms *MemoryStateStore) Get(ctx context.Context, state string) (*StateData, error) {
	ms.mu.RLock()
	entry, exists := ms.data[state]
	ms.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("invalid state: state not found or expired")
	}

	if time.Now().After(entry.expiredAt) {
		ms.mu.Lock()
		delete(ms.data, state)
		ms.mu.Unlock()
		return nil, fmt.Errorf("invalid state: state not found or expired")
	}

	return entry.data, nil
}

// Delete removes state data from memory
func (ms *MemoryStateStore) Delete(ctx context.Context, state string) {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	delete(ms.data, state)
}

// RedisStateStore implements StateStore using Redis
type RedisStateStore struct {
	redisClient *redis.Client
	expiration  time.Duration
}

// NewRedisStateStore creates a new Redis-based state store
func NewRedisStateStore(redisClient *redis.Client, expiration time.Duration) *RedisStateStore {
	if expiration == 0 {
		expiration = constants.DefaultStateExpiration
	}
	return &RedisStateStore{
		redisClient: redisClient,
		expiration:  expiration,
	}
}

// Store stores state data in Redis
func (rs *RedisStateStore) Store(ctx context.Context, state string, stateData *StateData) error {
	data, err := json.Marshal(stateData)
	if err != nil {
		return fmt.Errorf("failed to marshal state data: %w", err)
	}

	key := fmt.Sprintf("%s%s", constants.StateKeyPrefix, state)
	err = rs.redisClient.Set(ctx, key, data, rs.expiration).Err()
	if err != nil {
		return fmt.Errorf("redis set operation failed: %w", err)
	}
	return nil
}

// Get retrieves state data from Redis
func (rs *RedisStateStore) Get(ctx context.Context, state string) (*StateData, error) {
	key := fmt.Sprintf("%s%s", constants.StateKeyPrefix, state)
	data, err := rs.redisClient.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("invalid state: state not found or expired")
		}
		return nil, fmt.Errorf("redis get operation failed: %w", err)
	}

	var stateData StateData
	if err := json.Unmarshal([]byte(data), &stateData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal state data: %w", err)
	}

	return &stateData, nil
}

// Delete removes state data from Redis
func (rs *RedisStateStore) Delete(ctx context.Context, state string) {
	key := fmt.Sprintf("%s%s", constants.StateKeyPrefix, state)
	rs.redisClient.Del(ctx, key)
}

// StateManager handles OAuth state management (deprecated, use StateStore interface)
type StateManager struct {
	store StateStore
}

// NewStateManager creates a new state manager with the given store
func NewStateManager(store StateStore) *StateManager {
	return &StateManager{
		store: store,
	}
}

// NewStateManagerWithRedis creates a new state manager with Redis store
func NewStateManagerWithRedis(redisClient *redis.Client, expiration time.Duration) *StateManager {
	return NewStateManager(NewRedisStateStore(redisClient, expiration))
}

// NewStateManagerWithMemory creates a new state manager with memory store
func NewStateManagerWithMemory(expiration time.Duration) *StateManager {
	return NewStateManager(NewMemoryStateStore(expiration))
}

// Store stores state data using the configured store
func (sm *StateManager) Store(ctx context.Context, state string, stateData *StateData) error {
	return sm.store.Store(ctx, state, stateData)
}

// Get retrieves state data using the configured store
func (sm *StateManager) Get(ctx context.Context, state string) (*StateData, error) {
	return sm.store.Get(ctx, state)
}

// Delete removes state data using the configured store
func (sm *StateManager) Delete(ctx context.Context, state string) {
	sm.store.Delete(ctx, state)
}
