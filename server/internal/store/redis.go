// Package store — Redis decorator for presence and pub/sub.
//
// RedisStore wraps any base Store and overrides presence methods with Redis
// commands, adds sliding-window rate limiting, and publishes session.updated
// events so multiple server instances can relay WebSocket notifications.
package store

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	presencePrefix     = "device:online:"
	sessionUpdatedChan = "session.updated"
	rateLimitPrefix    = "ratelimit:"
)

// RedisStore decorates a base Store with Redis-backed presence and pub/sub.
type RedisStore struct {
	Store          // embedded base (all non-presence methods delegate here)
	rdb   *redis.Client
}

// NewRedisStore creates a RedisStore that delegates non-presence operations to
// base and uses rdb for presence and pub/sub.
func NewRedisStore(base Store, opts *redis.Options) (*RedisStore, error) {
	rdb := redis.NewClient(opts)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		_ = rdb.Close()
		return nil, fmt.Errorf("store/redis: ping: %w", err)
	}
	return &RedisStore{Store: base, rdb: rdb}, nil
}

// Close shuts down the Redis client and the underlying base store.
func (r *RedisStore) Close() error {
	rErr := r.rdb.Close()
	bErr := r.Store.Close()
	if rErr != nil {
		return rErr
	}
	return bErr
}

// ─── Presence ────────────────────────────────────────────────────────────────

// SetOnline marks a device as online in Redis with the given TTL.
func (r *RedisStore) SetOnline(ctx context.Context, deviceID string, ttl time.Duration) error {
	key := presencePrefix + deviceID
	return r.rdb.Set(ctx, key, "1", ttl).Err()
}

// IsOnline checks whether a device is currently marked online in Redis.
func (r *RedisStore) IsOnline(ctx context.Context, deviceID string) (bool, error) {
	key := presencePrefix + deviceID
	n, err := r.rdb.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("store/redis: is_online: %w", err)
	}
	return n > 0, nil
}

// ─── Rate limiting ────────────────────────────────────────────────────────────

// RateLimitResult is returned by CheckRateLimit.
type RateLimitResult struct {
	Allowed   bool
	Remaining int
	ResetAt   time.Time
}

// CheckSlidingRateLimit implements a sliding-window rate limiter using a Redis
// sorted set.  windowSec is the window duration in seconds; limit is the max
// number of requests allowed per window.
func (r *RedisStore) CheckSlidingRateLimit(ctx context.Context, key string, limit int, windowSec int64) (RateLimitResult, error) {
	now := time.Now()
	nowMS := now.UnixMilli()
	windowStart := nowMS - windowSec*1000

	rkey := rateLimitPrefix + key
	pipe := r.rdb.Pipeline()

	// Remove old entries outside the window.
	pipe.ZRemRangeByScore(ctx, rkey, "-inf", strconv.FormatInt(windowStart, 10))
	// Count current entries.
	countCmd := pipe.ZCount(ctx, rkey, strconv.FormatInt(windowStart, 10), "+inf")
	// Add this request.
	pipe.ZAdd(ctx, rkey, redis.Z{Score: float64(nowMS), Member: strconv.FormatInt(nowMS, 10)})
	// Set expiry.
	pipe.Expire(ctx, rkey, time.Duration(windowSec)*time.Second*2)

	if _, err := pipe.Exec(ctx); err != nil {
		return RateLimitResult{}, fmt.Errorf("store/redis: rate limit pipeline: %w", err)
	}

	count := int(countCmd.Val())
	resetAt := now.Add(time.Duration(windowSec) * time.Second)
	if count >= limit {
		return RateLimitResult{Allowed: false, Remaining: 0, ResetAt: resetAt}, nil
	}
	return RateLimitResult{Allowed: true, Remaining: limit - count - 1, ResetAt: resetAt}, nil
}

// ─── Pub/Sub ─────────────────────────────────────────────────────────────────

// PublishSessionUpdated publishes a session-updated payload to all server
// instances via the Redis pub/sub channel.
func (r *RedisStore) PublishSessionUpdated(ctx context.Context, payload []byte) error {
	return r.rdb.Publish(ctx, sessionUpdatedChan, payload).Err()
}

// SubscribeSessionUpdated subscribes to the session.updated channel and calls
// handler for each message until ctx is cancelled.  This should be started as
// a dedicated goroutine.
func (r *RedisStore) SubscribeSessionUpdated(ctx context.Context, handler func(payload []byte)) {
	sub := r.rdb.Subscribe(ctx, sessionUpdatedChan)
	defer func() { _ = sub.Close() }()

	ch := sub.Channel()
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			func() {
				defer func() {
					if rv := recover(); rv != nil {
						slog.Error("session.updated handler panic", "recover", rv)
					}
				}()
				handler([]byte(msg.Payload))
			}()
		}
	}
}
