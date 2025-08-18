// Package auth provides authentication state management functionality.
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/vector233/go-singpass/internal/constants"
	"github.com/vector233/go-singpass/internal/errors"
)

// StateData represents OAuth state information
type StateData struct {
	CodeVerifier string `json:"code_verifier"`
	Nonce        string `json:"nonce"`
}

// StateManager handles OAuth state management with Redis
type StateManager struct {
	redisClient *redis.Client
	expiration  time.Duration
}

// NewStateManager creates a new state manager
func NewStateManager(redisClient *redis.Client, expiration time.Duration) *StateManager {
	if expiration == 0 {
		expiration = constants.DefaultStateExpiration
	}
	return &StateManager{
		redisClient: redisClient,
		expiration:  expiration,
	}
}

// Store stores state data in Redis
func (sm *StateManager) Store(ctx context.Context, state string, stateData *StateData) error {
	data, err := json.Marshal(stateData)
	if err != nil {
		return fmt.Errorf("failed to marshal state data: %w", err)
	}

	key := fmt.Sprintf("%s%s", constants.StateKeyPrefix, state)
	err = sm.redisClient.Set(ctx, key, data, sm.expiration).Err()
	if err != nil {
		return errors.ErrRedisOperation{Operation: "set", Message: err.Error()}
	}

	return nil
}

// Get retrieves state data from Redis
func (sm *StateManager) Get(ctx context.Context, state string) (*StateData, error) {
	key := fmt.Sprintf("%s%s", constants.StateKeyPrefix, state)
	data, err := sm.redisClient.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, errors.ErrInvalidState{Message: "state not found"}
		}
		return nil, errors.ErrRedisOperation{Operation: "get", Message: err.Error()}
	}

	var stateData StateData
	if err := json.Unmarshal([]byte(data), &stateData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal state data: %w", err)
	}

	return &stateData, nil
}

// Delete removes state data from Redis
func (sm *StateManager) Delete(ctx context.Context, state string) {
	key := fmt.Sprintf("%s%s", constants.StateKeyPrefix, state)
	sm.redisClient.Del(ctx, key)
}