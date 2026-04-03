package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"wiremind/config"
)

const (
	QueueName = "wiremind:jobs"
)

type Job struct {
	ID         string    `json:"id"`
	InputPath  string    `json:"input_path"`
	OutputPath string    `json:"output_path"`
	CreatedAt  time.Time `json:"created_at"`
}

type RedisQueue struct {
	client *redis.Client
}

func NewRedisQueue(cfg config.RedisConfig) (*RedisQueue, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("redis is disabled")
	}

	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Password: cfg.Password,
		DB:       cfg.DB,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis ping: %w", err)
	}

	return &RedisQueue{client: client}, nil
}

func (q *RedisQueue) PublishJob(ctx context.Context, job Job) error {
	data, err := json.Marshal(job)
	if err != nil {
		return fmt.Errorf("marshal job: %w", err)
	}

	if err := q.client.LPush(ctx, QueueName, data).Err(); err != nil {
		return fmt.Errorf("lpush: %w", err)
	}

	return nil
}

func (q *RedisQueue) ConsumeJob(ctx context.Context) (*Job, error) {
	// BRPop blocks until a job is available or context is cancelled
	res, err := q.client.BRPop(ctx, 0, QueueName).Result()
	if err != nil {
		return nil, err
	}

	if len(res) < 2 {
		return nil, fmt.Errorf("unexpected brpop result length")
	}

	var job Job
	if err := json.Unmarshal([]byte(res[1]), &job); err != nil {
		return nil, fmt.Errorf("unmarshal job: %w", err)
	}

	return &job, nil
}

func (q *RedisQueue) Close() error {
	return q.client.Close()
}
