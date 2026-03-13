package repo

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type OTPRepository interface {
	Save(ctx context.Context, username, code string, ttl time.Duration) error
	Get(ctx context.Context, username string) (string, bool, error)
	Delete(ctx context.Context, username string) error
}

type OTPRepo struct {
	rd *redis.Client
}

func NewOTPRepo(rd *redis.Client) *OTPRepo {
	return &OTPRepo{rd: rd}
}

func (r *OTPRepo) Save(ctx context.Context, username, code string, ttl time.Duration) error {
	return r.rd.Set(ctx, username, code, ttl).Err()
}

func (r *OTPRepo) Get(ctx context.Context, username string) (string, bool, error) {
	val, err := r.rd.Get(ctx, username).Result()
	if err == redis.Nil {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return val, true, nil
}
func (r *OTPRepo) Delete(ctx context.Context, username string) error {
	return r.rd.Del(ctx, username).Err()
}
